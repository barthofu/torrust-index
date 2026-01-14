//! API handlers for the the [`user`](crate::web::api::server::v1::contexts::user) API
//! context.
use std::sync::Arc;

use axum::extract::{self, Host, Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;

// serde_json::Value and time imports already declared above

// Helper to capture arbitrary additional claims from UserInfo
#[allow(dead_code)]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
struct AnyClaims(serde_json::Value);
impl openidconnect::AdditionalClaims for AnyClaims {}
use super::forms::{ChangePasswordForm, JsonWebToken, LoginForm, RegistrationForm};
use super::responses::{self};
use crate::common::AppData;
use crate::services::user::ListingRequest;
use crate::web::api::server::v1::extractors::optional_user_id::ExtractOptionalLoggedInUser;
use crate::web::api::server::v1::extractors::user_id::ExtractLoggedInUser;
use crate::web::api::server::v1::responses::OkResponseData;

// OIDC
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreIdToken, CoreIdTokenClaims, CoreProviderMetadata,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{AuthorizationCode, CsrfToken, IssuerUrl, Nonce, RedirectUrl, Scope};
use openidconnect::{ClientId, ClientSecret};
use openidconnect::{EmptyAdditionalClaims, OAuth2TokenResponse};
use rand::RngCore;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

// Registration

/// It handles the registration of a new user.
///
/// # Errors
///
/// It returns an error if the user could not be registered.
#[allow(clippy::unused_async)]
pub async fn registration_handler(
    State(app_data): State<Arc<AppData>>,
    Host(host_from_header): Host,
    extract::Json(registration_form): extract::Json<RegistrationForm>,
) -> Response {
    let api_base_url = app_data
        .cfg
        .get_api_base_url()
        .await
        .unwrap_or(api_base_url(&host_from_header));

    match app_data
        .registration_service
        .register_user(&registration_form, &api_base_url)
        .await
    {
        Ok(user_id) => responses::added_user(user_id).into_response(),
        Err(error) => error.into_response(),
    }
}

#[derive(Deserialize)]
pub struct TokenParam(String);

/// It handles the verification of the email verification token.
#[allow(clippy::unused_async)]
pub async fn email_verification_handler(State(app_data): State<Arc<AppData>>, Path(token): Path<TokenParam>) -> String {
    match app_data.registration_service.verify_email(&token.0).await {
        Ok(_) => String::from("Email verified, you can close this page."),
        Err(error) => error.to_string(),
    }
}

// Authentication

/// It handles the user login.
///
/// # Errors
///
/// It returns an error if:
///
/// - Unable to verify the supplied payload as a valid JWT.
/// - The JWT is not invalid or expired.
#[allow(clippy::unused_async)]
pub async fn login_handler(
    State(app_data): State<Arc<AppData>>,
    extract::Json(login_form): extract::Json<LoginForm>,
) -> Response {
    match app_data
        .authentication_service
        .login(&login_form.login, &login_form.password)
        .await
    {
        Ok((token, user_compact)) => responses::logged_in_user(token, user_compact).into_response(),
        Err(error) => error.into_response(),
    }
}

// ===============
// OIDC Handlers
// ===============

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct OidcStateClaims {
    iss: String,
    nonce: String,
    exp: u64,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random_string64() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

#[allow(clippy::unused_async)]
pub async fn oidc_login_handler(State(app_data): State<Arc<AppData>>, Host(host_from_header): Host) -> Response {
    let settings = app_data.cfg.settings.read().await;

    let Some(oidc) = &settings.auth.oidc else {
        return crate::web::api::server::v1::responses::json_error_response(
            hyper::StatusCode::NOT_FOUND,
            &crate::web::api::server::v1::responses::ErrorResponseData {
                error: "OIDC not configured".to_string(),
            },
        );
    };
    if !oidc.enabled {
        return crate::web::api::server::v1::responses::json_error_response(
            hyper::StatusCode::NOT_FOUND,
            &crate::web::api::server::v1::responses::ErrorResponseData {
                error: "OIDC disabled".to_string(),
            },
        );
    }

    let issuer_url = match IssuerUrl::new(oidc.issuer_url.clone()) {
        Ok(v) => v,
        Err(_) => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "Bad OIDC issuer URL".to_string(),
                },
            )
        }
    };

    let api_base = app_data
        .cfg
        .get_api_base_url()
        .await
        .unwrap_or_else(|| format!("http://{}", host_from_header));
    let redirect_uri = format!("{}{}", api_base, oidc.redirect_path);
    let redirect_url = match RedirectUrl::new(redirect_uri) {
        Ok(v) => v,
        Err(_) => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "Bad OIDC redirect URI".to_string(),
                },
            )
        }
    };

    // Discover provider and build client
    let provider_metadata = match CoreProviderMetadata::discover_async(issuer_url, async_http_client).await {
        Ok(m) => m,
        Err(_) => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::BAD_GATEWAY,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "OIDC discovery failed".to_string(),
                },
            )
        }
    };

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(oidc.client_id.clone()),
        Some(ClientSecret::new(oidc.client_secret.clone())),
    )
    .set_redirect_uri(redirect_url);

    // Create signed state containing a nonce
    let nonce = random_string64();
    let claims = OidcStateClaims {
        iss: "oidc-state".to_string(),
        nonce: nonce.clone(),
        exp: now_secs() + 600, // 10 minutes
    };
    let key = settings.auth.user_claim_token_pepper.as_bytes();
    let state_jwt = match encode(&Header::default(), &claims, &EncodingKey::from_secret(key)) {
        Ok(v) => v,
        Err(_) => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "Failed to sign OIDC state".to_string(),
                },
            )
        }
    };

    let mut auth_req = client.authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        || CsrfToken::new(state_jwt),
        || Nonce::new(nonce),
    );

    for s in &oidc.scopes {
        auth_req = auth_req.add_scope(Scope::new(s.clone()));
    }

    let (auth_url, _, _) = auth_req.url();
    Redirect::to(auth_url.as_ref()).into_response()
}

#[allow(clippy::unused_async)]
pub async fn oidc_callback_handler(
    State(app_data): State<Arc<AppData>>,
    Host(host_from_header): Host,
    Query(params): Query<OidcCallbackQuery>,
) -> Response {
    let settings = app_data.cfg.settings.read().await;
    let oidc_opt = settings.auth.oidc.clone();
    let pepper = settings.auth.user_claim_token_pepper.clone();
    drop(settings);
    let Some(oidc) = oidc_opt else {
        return crate::web::api::server::v1::responses::json_error_response(
            hyper::StatusCode::NOT_FOUND,
            &crate::web::api::server::v1::responses::ErrorResponseData {
                error: "OIDC not configured".to_string(),
            },
        );
    };
    if !oidc.enabled {
        return crate::web::api::server::v1::responses::json_error_response(
            hyper::StatusCode::NOT_FOUND,
            &crate::web::api::server::v1::responses::ErrorResponseData {
                error: "OIDC disabled".to_string(),
            },
        );
    }

    // If the provider returned an error (e.g., access_denied), handle gracefully
    if let Some(err) = &params.error {
        let desc = params.error_description.clone().unwrap_or_default();
        if let Some(ref redirect_url) = oidc.post_login_redirect_url {
            let sep = if redirect_url.contains('?') { '&' } else { '?' };
            let final_url = format!(
                "{}{}error={}&error_description={}",
                redirect_url,
                sep,
                urlencoding::encode(err),
                urlencoding::encode(&desc)
            );
            return Redirect::to(&final_url).into_response();
        }
        return crate::web::api::server::v1::responses::json_error_response(
            hyper::StatusCode::UNAUTHORIZED,
            &crate::web::api::server::v1::responses::ErrorResponseData {
                error: format!(
                    "OIDC authorization failed: {}{}{}",
                    err,
                    if desc.is_empty() { "" } else { ": " },
                    desc
                ),
            },
        );
    }

    // Verify state JWT and get nonce
    let state_param = match &params.state {
        Some(s) => s,
        None => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::BAD_REQUEST,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "Missing OIDC state".to_string(),
                },
            )
        }
    };
    let key = pepper.as_bytes();
    let token_data = match decode::<OidcStateClaims>(
        state_param,
        &DecodingKey::from_secret(key),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(d) => d.claims,
        Err(_) => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::UNAUTHORIZED,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "Invalid OIDC state".to_string(),
                },
            )
        }
    };
    if token_data.iss != "oidc-state" || token_data.exp < now_secs() {
        return crate::web::api::server::v1::responses::json_error_response(
            hyper::StatusCode::UNAUTHORIZED,
            &crate::web::api::server::v1::responses::ErrorResponseData {
                error: "Expired OIDC state".to_string(),
            },
        );
    }

    let issuer_url = match IssuerUrl::new(oidc.issuer_url.clone()) {
        Ok(v) => v,
        Err(_) => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "Bad OIDC issuer URL".to_string(),
                },
            )
        }
    };

    let api_base = app_data
        .cfg
        .get_api_base_url()
        .await
        .unwrap_or_else(|| format!("http://{}", host_from_header));
    let redirect_uri = format!("{}{}", api_base, oidc.redirect_path);
    let redirect_url = match RedirectUrl::new(redirect_uri) {
        Ok(v) => v,
        Err(_) => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "Bad OIDC redirect URI".to_string(),
                },
            )
        }
    };

    let provider_metadata = match CoreProviderMetadata::discover_async(issuer_url, async_http_client).await {
        Ok(m) => m,
        Err(_) => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::BAD_GATEWAY,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "OIDC discovery failed".to_string(),
                },
            )
        }
    };

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(oidc.client_id.clone()),
        Some(ClientSecret::new(oidc.client_secret.clone())),
    )
    .set_redirect_uri(redirect_url);

    // Exchange code
    let code = match &params.code {
        Some(c) => c.clone(),
        None => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::BAD_REQUEST,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "Missing authorization code".to_string(),
                },
            )
        }
    };
    let token_res = match client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await
    {
        Ok(t) => t,
        Err(_) => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::UNAUTHORIZED,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "OIDC token exchange failed".to_string(),
                },
            )
        }
    };

    // Validate ID token & nonce
    let id_token: CoreIdToken = match token_res.extra_fields().id_token().cloned() {
        Some(t) => t,
        None => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::UNAUTHORIZED,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "Missing ID token".to_string(),
                },
            )
        }
    };
    let nonce = Nonce::new(token_data.nonce);
    let claims: CoreIdTokenClaims = match id_token.claims(&client.id_token_verifier(), &nonce) {
        Ok(c) => c.clone(),
        Err(_) => {
            return crate::web::api::server::v1::responses::json_error_response(
                hyper::StatusCode::UNAUTHORIZED,
                &crate::web::api::server::v1::responses::ErrorResponseData {
                    error: "Invalid ID token".to_string(),
                },
            )
        }
    };

    // Extract identity
    let email = claims.email().map(|e| e.as_str().to_string());
    let mut username_opt = claims.preferred_username().map(|u| u.as_str().to_string());
    if username_opt.is_none() {
        if let Some(e) = &email {
            if let Some((u, _)) = e.split_once('@') {
                username_opt = Some(u.to_string());
            }
        }
    }
    let mut username = username_opt.unwrap_or_else(|| claims.subject().as_str().to_string());
    // Sanitize username to match local constraints (A-Za-z0-9-_ up to 20 chars)
    username = username
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(20)
        .collect::<String>();
    if username.is_empty() {
        username = "user".to_string();
    }

    // settings lock already released

    // Ensure local user exists
    let user_id_res = app_data
        .user_profile_repository
        .get_user_profile_from_username(&username)
        .await;

    let user_id = match user_id_res {
        Ok(profile) => profile.user_id,
        Err(_) => {
            // Create user with random password
            let random_password = random_string64();
            let salt = SaltString::generate(&mut rand_core::OsRng);
            let argon2 = Argon2::default();
            let password_hash = argon2
                .hash_password(random_password.as_bytes(), &salt)
                .map(|ph| ph.to_string())
                .map_err(|_| ())
                .unwrap_or_else(|_| "$argon2id$v=19$m=4096,t=3,p=1$NXVybHVzLWZhbGwtdmFsdWU$2n3cV3JXQ8Kz".to_string());

            let email_str = email.clone().unwrap_or_default();
            match app_data.user_repository.add(&username, &email_str, &password_hash).await {
                Ok(uid) => {
                    // If we received an email, mark it verified to avoid blocking OIDC users
                    if email.is_some() {
                        drop(app_data.user_profile_repository.verify_email(&uid).await);
                    }
                    uid
                }
                Err(e) => return e.into_response(),
            }
        }
    };

    // If configured, grant admin rights based on group membership
    if let Some(admin_group) = &oidc.admin_group {
        // Try to detect groups from ID token first
        let mut has_admin = false;
        let id_token_json: Value = match serde_json::to_value(&claims) {
            Ok(v) => v,
            Err(_) => Value::Null,
        };

        fn extract_group_match(root: &Value, claim_path: &str, target: &str) -> bool {
            // Support dot paths like "realm_access.roles"
            let mut current = root;
            for key in claim_path.split('.') {
                match current {
                    Value::Object(map) => {
                        if let Some(next) = map.get(key) {
                            current = next;
                        } else {
                            return false;
                        }
                    }
                    _ => return false,
                }
            }
            match current {
                Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(target)),
                Value::String(s) => s == target,
                _ => false,
            }
        }

        if extract_group_match(&id_token_json, &oidc.groups_claim, admin_group) {
            has_admin = true;
        } else {
            // Fallback: try userinfo endpoint if available
            if let Ok(userinfo_req) = client.user_info(token_res.access_token().clone(), Some(claims.subject().clone())) {
                if let Ok(userinfo_claims) = userinfo_req
                    .request_async::<EmptyAdditionalClaims, _, _, CoreGenderClaim, _>(async_http_client)
                    .await
                {
                    let userinfo_json: Value = serde_json::to_value(&userinfo_claims).unwrap_or(Value::Null);
                    if extract_group_match(&userinfo_json, &oidc.groups_claim, admin_group) {
                        has_admin = true;
                    }
                }
            }
            // Second fallback: parse raw ID token payload for groups claim
            if !has_admin {
                let id_token_raw = id_token.to_string();
                let parts: Vec<&str> = id_token_raw.split('.').collect();
                if parts.len() >= 2 {
                    if let Ok(bytes) = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1]) {
                        if let Ok(json) = serde_json::from_slice::<Value>(&bytes) {
                            if extract_group_match(&json, &oidc.groups_claim, admin_group) {
                                has_admin = true;
                            }
                        }
                    }
                }
            }
        }

        if has_admin {
            drop(app_data.user_repository.grant_admin_role(&user_id).await);
        }
    }

    // Build token response using local JWT
    let user_compact = match app_data.user_repository.get_compact(&user_id).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let token = app_data.json_web_token.sign(user_compact.clone()).await;
    // If GUI redirect is configured, redirect with token on query string; otherwise return JSON
    if let Some(ref redirect_url) = oidc.post_login_redirect_url {
        let sep = if redirect_url.contains('?') { '&' } else { '?' };
        let safe_token = urlencoding::encode(&token);
        let final_url = format!("{}{}token={}", redirect_url, sep, safe_token);
        return Redirect::to(&final_url).into_response();
    }

    super::responses::logged_in_user(token, user_compact).into_response()
}

// ===============
// Tracker Key / Announce URL
// ===============

#[derive(serde::Serialize)]
pub struct TrackerAnnounceResponse {
    announce_url: String,
    key: Option<String>,
}

#[allow(clippy::unused_async)]
pub async fn tracker_announce_handler(
    State(app_data): State<Arc<AppData>>,
    ExtractLoggedInUser(user_id): ExtractLoggedInUser,
) -> Response {
    match app_data.tracker_service.get_personal_announce_url(user_id).await {
        Ok(url) => {
            // Try to also provide the raw key
            let key_opt = app_data.database.get_user_tracker_key(user_id).await.map(|k| k.key);
            let res = TrackerAnnounceResponse {
                announce_url: url.to_string(),
                key: key_opt,
            };
            axum::Json(OkResponseData { data: res }).into_response()
        }
        Err(err) => {
            use crate::tracker::service::TrackerAPIError;
            let (status, msg) = match err {
                TrackerAPIError::InvalidToken => (hyper::StatusCode::UNAUTHORIZED, "Invalid tracker API token".to_string()),
                TrackerAPIError::InternalServerError => {
                    (hyper::StatusCode::INTERNAL_SERVER_ERROR, "Tracker internal error".to_string())
                }
                TrackerAPIError::NotFound => (hyper::StatusCode::NOT_FOUND, "Tracker resource not found".to_string()),
                TrackerAPIError::UnexpectedResponseStatus => {
                    (hyper::StatusCode::BAD_GATEWAY, "Unexpected tracker response".to_string())
                }
                TrackerAPIError::CannotSaveUserKey => (
                    hyper::StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to save tracker key".to_string(),
                ),
                TrackerAPIError::TorrentNotFound => (hyper::StatusCode::NOT_FOUND, "Torrent not found".to_string()),
                TrackerAPIError::MissingResponseBody => {
                    (hyper::StatusCode::BAD_GATEWAY, "Missing tracker response body".to_string())
                }
                TrackerAPIError::FailedToParseTrackerResponse { body: _ } => {
                    (hyper::StatusCode::BAD_GATEWAY, "Failed to parse tracker response".to_string())
                }
                TrackerAPIError::TrackerOffline { error } => {
                    (hyper::StatusCode::BAD_GATEWAY, format!("Tracker offline: {}", error))
                }
            };
            crate::web::api::server::v1::responses::json_error_response(
                status,
                &crate::web::api::server::v1::responses::ErrorResponseData { error: msg },
            )
        }
    }
}

/// It verifies a supplied JWT.
///
/// # Errors
///
/// It returns an error if:
///
/// - Unable to verify the supplied payload as a valid JWT.
/// - The JWT is not invalid or expired.
#[allow(clippy::unused_async)]
pub async fn verify_token_handler(
    State(app_data): State<Arc<AppData>>,
    extract::Json(token): extract::Json<JsonWebToken>,
) -> Response {
    match app_data.json_web_token.verify(&token.token).await {
        Ok(_) => axum::Json(OkResponseData {
            data: "Token is valid.".to_string(),
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
}

#[derive(Deserialize)]
pub struct UsernameParam(pub String);

/// It renews the JWT.
///
/// # Errors
///
/// It returns an error if:
///
/// - Unable to parse the supplied payload as a valid JWT.
/// - The JWT is not invalid or expired.
#[allow(clippy::unused_async)]
pub async fn renew_token_handler(
    State(app_data): State<Arc<AppData>>,
    extract::Json(token): extract::Json<JsonWebToken>,
) -> Response {
    match app_data.authentication_service.renew_token(&token.token).await {
        Ok((token, user_compact)) => responses::renewed_token(token, user_compact).into_response(),
        Err(error) => error.into_response(),
    }
}

/// It changes the user's password.
///
/// # Errors
///
/// It returns an error if:
///
/// - The user account is not found.
#[allow(clippy::unused_async)]
#[allow(clippy::missing_panics_doc)]
pub async fn change_password_handler(
    State(app_data): State<Arc<AppData>>,
    ExtractOptionalLoggedInUser(maybe_user_id): ExtractOptionalLoggedInUser,
    extract::Json(change_password_form): extract::Json<ChangePasswordForm>,
) -> Response {
    match app_data
        .profile_service
        .change_password(maybe_user_id, &change_password_form)
        .await
    {
        Ok(()) => Json(OkResponseData {
            data: format!("Password changed for user with ID: {}", maybe_user_id.unwrap()),
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
}

/// It bans a user from the index.
///
/// # Errors
///
/// This function will return if:
///
/// - The JWT provided by the banning authority was not valid.
/// - The user could not be banned: it does not exist, etcetera.
#[allow(clippy::unused_async)]
pub async fn ban_handler(
    State(app_data): State<Arc<AppData>>,
    Path(to_be_banned_username): Path<UsernameParam>,
    ExtractOptionalLoggedInUser(maybe_user_id): ExtractOptionalLoggedInUser,
) -> Response {
    // todo: add reason and `date_expiry` parameters to request

    match app_data.ban_service.ban_user(&to_be_banned_username.0, maybe_user_id).await {
        Ok(()) => Json(OkResponseData {
            data: format!("Banned user: {}", to_be_banned_username.0),
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
}

/// It returns the base API URL without the port. For example: `http://localhost`.
fn api_base_url(host: &str) -> String {
    // HTTPS is not supported yet.
    // See https://github.com/torrust/torrust-index/issues/131
    format!("http://{host}")
}

/// It handles the request to get all the user profiles.
///
///It returns a list of user profiles matching the search criteria.
///
/// # Errors
///
/// It returns an error if:
/// There is a database error
/// There is a problem authorizing the action.
/// The user is not authorized to perform the action
#[allow(clippy::unused_async)]
pub async fn get_user_profiles_handler(
    State(app_data): State<Arc<AppData>>,
    Query(criteria): Query<ListingRequest>,
    ExtractOptionalLoggedInUser(maybe_user_id): ExtractOptionalLoggedInUser,
) -> Response {
    let listing = match app_data
        .listing_service
        .listing_specification_from_user_request(maybe_user_id, &criteria)
        .await
    {
        Ok(listing_value) => listing_value,
        Err(err) => return err.into_response(),
    };

    match app_data.listing_service.generate_user_profile_listing(&listing).await {
        Ok(users) => Json(crate::web::api::server::v1::responses::OkResponseData { data: users }).into_response(),
        Err(error) => error.into_response(),
    }
}
