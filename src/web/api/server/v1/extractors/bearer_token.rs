use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::Response;
use serde::Deserialize;

use crate::web::api::server::v1::auth::parse_token;

pub struct Extract(pub Option<BearerToken>);

#[derive(Deserialize, Debug)]
pub struct BearerToken(String);

impl BearerToken {
    #[must_use]
    pub fn value(&self) -> String {
        self.0.clone()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Extract
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let header = parts.headers.get("Authorization");

        match header {
            Some(header_value) => {
                // Only attempt to parse when it is a Bearer token.
                // This avoids panics when using other auth schemes.
                let auth_header = header_value.to_str().unwrap_or("");
                if auth_header.trim_start().starts_with("Bearer ") {
                    Ok(Extract(Some(BearerToken(parse_token(header_value)))))
                } else {
                    Ok(Extract(None))
                }
            }
            None => Ok(Extract(None)),
        }
    }
}
