use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::response::Response;

use crate::common::AppData;
use crate::models::user::UserId;
use crate::services::hasher;
use crate::utils::clock;
use crate::web::api::server::v1::extractors::{api_key, bearer_token};

pub struct ExtractOptionalLoggedInUser(pub Option<UserId>);

#[async_trait]
impl<S> FromRequestParts<S> for ExtractOptionalLoggedInUser
where
    Arc<AppData>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // 1) Bearer auth (preferred when present)
        let bearer_token = match bearer_token::Extract::from_request_parts(parts, state).await {
            Ok(bearer_token) => bearer_token.0,
            Err(_) => None,
        };

        //Extracts the app state
        let app_data = Arc::from_ref(state);

        match app_data.auth.get_user_id_from_bearer_token(bearer_token).await {
            Ok(user_id) => return Ok(ExtractOptionalLoggedInUser(Some(user_id))),
            Err(_) => {
                // fall-through: no/invalid bearer token
            }
        }

        // 2) API key auth (optional)
        let maybe_api_key = match api_key::Extract::from_request_parts(parts, state).await {
            Ok(maybe_api_key) => maybe_api_key.0,
            Err(_) => None,
        };

        let Some(api_key) = maybe_api_key else {
            return Ok(ExtractOptionalLoggedInUser(None));
        };

        let settings = app_data.cfg.settings.read().await;
        let pepper = settings.auth.user_claim_token_pepper.to_string();
        let key_hash = hasher::sha1(&format!("{pepper}:{}", api_key.value()));

        match app_data.database.get_user_id_from_api_key_hash(&key_hash).await {
            Ok(Some(user_id)) => {
                // Best-effort update. If this fails, still allow the request.
                let _touch_result = app_data
                    .database
                    .touch_user_api_key_last_used(&key_hash, clock::now() as i64)
                    .await;

                Ok(ExtractOptionalLoggedInUser(Some(user_id)))
            }
            Ok(None) => Ok(ExtractOptionalLoggedInUser(None)),
            Err(_) => Ok(ExtractOptionalLoggedInUser(None)),
        }
    }
}
