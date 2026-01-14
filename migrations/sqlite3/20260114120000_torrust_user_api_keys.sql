CREATE TABLE IF NOT EXISTS torrust_user_api_keys (
    api_key_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER,
    FOREIGN KEY(user_id) REFERENCES torrust_users(user_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_torrust_user_api_keys_key_hash
    ON torrust_user_api_keys(key_hash);

CREATE INDEX IF NOT EXISTS idx_torrust_user_api_keys_user_id
    ON torrust_user_api_keys(user_id);
