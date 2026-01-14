use serde::{Deserialize, Serialize};
use sqlx::FromRow;

pub type ApiKeyId = i64;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct UserApiKey {
    pub api_key_id: ApiKeyId,
    pub user_id: i64,
    pub name: String,
    pub key_prefix: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}
