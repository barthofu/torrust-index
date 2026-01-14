//! Route initialization for the v1 API.
use std::env;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::extract::FromRequestParts;
use axum::extract::State;
use axum::http::HeaderName;
use axum::http::Request as AxumRequest;
use axum::middleware;
use axum::middleware::Next;
use axum::response::{Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use hyper::Request;
use serde_json::{json, Value};
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::propagate_header::PropagateHeaderLayer;
use tower_http::request_id::{MakeRequestUuid, SetRequestIdLayer};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::{Level, Span};

use super::contexts::{about, category, proxy, settings, tag, torrent, user};
use crate::bootstrap::config::ENV_VAR_CORS_PERMISSIVE;
use crate::common::AppData;
use crate::web::api::server::v1::extractors::user_id::ExtractLoggedInUser;

pub const API_VERSION_URL_PREFIX: &str = "v1";

/// Add all API routes to the router.
#[allow(clippy::needless_pass_by_value)]
pub fn router(app_data: Arc<AppData>) -> Router {
    // code-review: should we use plural for the resource prefix: `users`, `categories`, `tags`?
    // Some endpoint are using plural (for instance, `get_categories`) and some singular.
    // See: https://stackoverflow.com/questions/6845772/should-i-use-singular-or-plural-name-convention-for-rest-resources

    let auth_required_layer = middleware::from_fn_with_state(app_data.clone(), require_auth_middleware);

    // Public v1 endpoints (minimal): user auth/oidc/email verification/token verify+renew.
    let public_v1_routes = Router::new().nest("/user", user::routes::router(app_data.clone()));

    // Protected v1 endpoints: everything else.
    let protected_v1_routes = Router::new()
        .nest("/users", user::routes::router_for_multiple_resources(app_data.clone()))
        .nest("/about", about::routes::router(app_data.clone()))
        .nest("/category", category::routes::router(app_data.clone()))
        .nest("/tag", tag::routes::router_for_single_resources(app_data.clone()))
        .nest("/tags", tag::routes::router_for_multiple_resources(app_data.clone()))
        .nest("/settings", settings::routes::router(app_data.clone()))
        .nest("/torrent", torrent::routes::router_for_single_resources(app_data.clone()))
        .nest("/torrents", torrent::routes::router_for_multiple_resources(app_data.clone()))
        .nest("/proxy", proxy::routes::router(app_data.clone()))
        .route_layer(auth_required_layer);

    let v1_api_routes = Router::new()
        .route("/", get(redirect_to_about))
        .merge(public_v1_routes)
        .merge(protected_v1_routes);

    let router = Router::new()
        .route("/", get(redirect_to_about))
        .route("/health_check", get(health_check_handler).with_state(app_data.clone()))
        .nest(&format!("/{API_VERSION_URL_PREFIX}"), v1_api_routes);

    let router = if env::var(ENV_VAR_CORS_PERMISSIVE).is_ok() {
        router.layer(CorsLayer::permissive())
    } else {
        router
    };

    router
        .layer(DefaultBodyLimit::max(10_485_760))
        .layer(CompressionLayer::new())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateHeaderLayer::new(HeaderName::from_static("x-request-id")))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(|request: &Request<axum::body::Body>, _span: &Span| {
                    let method = request.method().to_string();
                    let uri = request.uri().to_string();
                    let request_id = request
                        .headers()
                        .get("x-request-id")
                        .map(|v| v.to_str().unwrap_or_default())
                        .unwrap_or_default();

                    tracing::span!(
                        target: "API",
                        tracing::Level::INFO, "request", method = %method, uri = %uri, request_id = %request_id);
                })
                .on_response(|response: &Response, latency: Duration, _span: &Span| {
                    let status_code = response.status();
                    let request_id = response
                        .headers()
                        .get("x-request-id")
                        .map(|v| v.to_str().unwrap_or_default())
                        .unwrap_or_default();
                    let latency_ms = latency.as_millis();

                    tracing::span!(
                        target: "API",
                        tracing::Level::INFO, "response", latency = %latency_ms, status = %status_code, request_id = %request_id);
                }),
        )
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

/// Endpoint for container health check.
async fn health_check_handler() -> Json<Value> {
    Json(json!({ "status": "Ok" }))
}

async fn redirect_to_about() -> Redirect {
    Redirect::permanent(&format!("/{API_VERSION_URL_PREFIX}/about"))
}

pub(crate) async fn require_auth_middleware(
    State(app_data): State<Arc<AppData>>,
    request: AxumRequest<Body>,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();

    match ExtractLoggedInUser::from_request_parts(&mut parts, &app_data).await {
        Ok(_) => next.run(AxumRequest::from_parts(parts, body)).await,
        Err(rejection) => rejection,
    }
}
