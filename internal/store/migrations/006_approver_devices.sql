CREATE TABLE IF NOT EXISTS approver_devices (
  device_id   TEXT PRIMARY KEY,
  public_key  BLOB NOT NULL,
  created_at  TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,
  disabled_at TEXT
);
