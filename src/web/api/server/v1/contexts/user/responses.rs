use axum::Json;
use serde::{Deserialize, Serialize};

use crate::models::user::{UserCompact, UserId};
use crate::models::user_api_key::{ApiKeyId, UserApiKey};
use crate::web::api::server::v1::responses::OkResponseData;

// Registration

#[derive(Serialize, Deserialize, Debug)]
pub struct NewUser {
    pub user_id: UserId,
}

/// Response after successfully creating a new user.
pub fn added_user(user_id: i64) -> Json<OkResponseData<NewUser>> {
    Json(OkResponseData {
        data: NewUser { user_id },
    })
}

// Authentication

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenResponse {
    pub token: String,
    pub username: String,
    pub admin: bool,
}

/// Response after successfully logging in a user.
pub fn logged_in_user(token: String, user_compact: UserCompact) -> Json<OkResponseData<TokenResponse>> {
    Json(OkResponseData {
        data: TokenResponse {
            token,
            username: user_compact.username,
            admin: user_compact.administrator,
        },
    })
}

/// Response after successfully renewing a JWT.
pub fn renewed_token(token: String, user_compact: UserCompact) -> Json<OkResponseData<TokenResponse>> {
    Json(OkResponseData {
        data: TokenResponse {
            token,
            username: user_compact.username,
            admin: user_compact.administrator,
        },
    })
}

// API Keys

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiKeyPublic {
    pub api_key_id: ApiKeyId,
    pub name: String,
    pub key_prefix: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

impl From<UserApiKey> for ApiKeyPublic {
    fn from(value: UserApiKey) -> Self {
        Self {
            api_key_id: value.api_key_id,
            name: value.name,
            key_prefix: value.key_prefix,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
            revoked_at: value.revoked_at,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreatedApiKey {
    pub api_key_id: ApiKeyId,
    pub name: String,
    pub key_prefix: String,
    /// The full API key secret. This is returned only once.
    pub api_key: String,
    pub created_at: i64,
}

pub fn api_keys_list(api_keys: Vec<UserApiKey>) -> Json<OkResponseData<Vec<ApiKeyPublic>>> {
    Json(OkResponseData {
        data: api_keys.into_iter().map(Into::into).collect(),
    })
}

pub fn created_api_key(api_key_id: ApiKeyId, name: String, key_prefix: String, api_key: String, created_at: i64) -> Json<OkResponseData<CreatedApiKey>> {
    Json(OkResponseData {
        data: CreatedApiKey {
            api_key_id,
            name,
            key_prefix,
            api_key,
            created_at,
        },
    })
}

pub fn revoked_api_key(api_key_id: ApiKeyId) -> Json<OkResponseData<ApiKeyId>> {
    Json(OkResponseData { data: api_key_id })
}
