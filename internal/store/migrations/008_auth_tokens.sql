CREATE TABLE IF NOT EXISTS auth_tokens (
  token_hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  client_id  TEXT NOT NULL,
  expires_at TEXT NOT NULL DEFAULT ''
);
