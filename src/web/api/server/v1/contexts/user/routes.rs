//! API routes for the [`user`](crate::web::api::server::v1::contexts::user) API context.
//!
//! Refer to the [API endpoint documentation](crate::web::api::server::v1::contexts::user).
use std::sync::Arc;

use axum::routing::{delete, get, post};
use axum::Router;

use super::handlers::{
    ban_handler, email_verification_handler, get_user_profiles_handler, oidc_callback_handler, oidc_login_handler,
    renew_token_handler, revoke_api_key_handler, tracker_announce_handler, user_api_keys_create_handler,
    user_api_keys_list_handler, verify_token_handler,
};
use crate::common::AppData;

/// Routes for the [`user`](crate::web::api::server::v1::contexts::user) API context.
pub fn router(app_data: Arc<AppData>) -> Router {
    Router::new()
        // Email verification (kept)
        .route(
            "/email/verify/:token",
            get(email_verification_handler).with_state(app_data.clone()),
        )
        // OIDC authentication
        .route("/oidc/login", get(oidc_login_handler).with_state(app_data.clone()))
        .route("/oidc/callback", get(oidc_callback_handler).with_state(app_data.clone()))
        .route("/token/verify", post(verify_token_handler).with_state(app_data.clone()))
        .route("/token/renew", post(renew_token_handler).with_state(app_data.clone()))
        .route(
            "/tracker/announce",
            get(tracker_announce_handler).with_state(app_data.clone()),
        )
        // API keys (for app integrations)
        .route(
            "/api-keys",
            get(user_api_keys_list_handler)
                .post(user_api_keys_create_handler)
                .with_state(app_data.clone()),
        )
        .route(
            "/api-keys/:api_key_id",
            delete(revoke_api_key_handler).with_state(app_data.clone()),
        )
        // Profile
        // Change password disabled when using OIDC-only auth
        // User ban
        // code-review: should not this be a POST method? We add the user to the blacklist. We do not delete the user.
        .route("/ban/:user", delete(ban_handler).with_state(app_data))
}

/// Routes for the [`user`](crate::web::api::server::v1::contexts::user) API context.
pub fn router_for_multiple_resources(app_data: Arc<AppData>) -> Router {
    Router::new().route("/", get(get_user_profiles_handler).with_state(app_data))
}
