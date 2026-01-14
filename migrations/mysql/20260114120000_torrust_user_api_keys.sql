CREATE TABLE IF NOT EXISTS torrust_user_api_keys (
    api_key_id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT,
    user_id INTEGER NOT NULL,
    name VARCHAR(64) NOT NULL,
    key_prefix CHAR(8) NOT NULL,
    key_hash CHAR(64) NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT NULL,
    revoked_at BIGINT NULL,
    FOREIGN KEY(user_id) REFERENCES torrust_users(user_id) ON DELETE CASCADE,
    UNIQUE KEY idx_torrust_user_api_keys_key_hash (key_hash),
    KEY idx_torrust_user_api_keys_user_id (user_id)
);
