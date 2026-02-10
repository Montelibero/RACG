PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS requests (
  request_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  status TEXT NOT NULL,
  op_json TEXT NOT NULL,
  risk_flags_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_requests_session_created ON requests(session_id, created_at);

CREATE TABLE IF NOT EXISTS decisions (
  request_id TEXT PRIMARY KEY,
  decision TEXT NOT NULL,
  decision_source TEXT NOT NULL,
  decided_at TEXT NOT NULL,
  rule_id TEXT,
  FOREIGN KEY(request_id) REFERENCES requests(request_id)
);

CREATE TABLE IF NOT EXISTS executions (
  request_id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  exit_code INTEGER NOT NULL,
  status TEXT NOT NULL,
  stdout TEXT NOT NULL,
  stderr TEXT NOT NULL,
  stdout_truncated INTEGER NOT NULL,
  stderr_truncated INTEGER NOT NULL,
  stdout_sha256 TEXT NOT NULL,
  stderr_sha256 TEXT NOT NULL,
  FOREIGN KEY(request_id) REFERENCES requests(request_id)
);

