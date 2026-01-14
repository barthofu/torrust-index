use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::Response;

pub struct Extract(pub Option<ApiKey>);

#[derive(Debug, Clone)]
pub struct ApiKey(String);

impl ApiKey {
    #[must_use]
    pub fn value(&self) -> String {
        self.0.clone()
    }
}

fn parse_api_key_from_authorization_header(authorization: &str) -> Option<String> {
    // Expected: "ApiKey <key>" (case-sensitive, kept simple).
    let authorization = authorization.trim();
    if let Some(rest) = authorization.strip_prefix("ApiKey ") {
        let key = rest.trim();
        if !key.is_empty() {
            return Some(key.to_string());
        }
    }
    None
}

#[async_trait]
impl<S> FromRequestParts<S> for Extract
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Prefer explicit header.
        if let Some(value) = parts.headers.get("X-API-Key") {
            let key = value.to_str().unwrap_or("").trim();
            if !key.is_empty() {
                return Ok(Extract(Some(ApiKey(key.to_string()))));
            }
        }

        // Fallback: Authorization scheme.
        if let Some(value) = parts.headers.get("Authorization") {
            let auth = value.to_str().unwrap_or("");
            if let Some(key) = parse_api_key_from_authorization_header(auth) {
                return Ok(Extract(Some(ApiKey(key))));
            }
        }

        Ok(Extract(None))
    }
}
