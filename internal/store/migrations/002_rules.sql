PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS rules (
  rule_id TEXT PRIMARY KEY,
  source TEXT NOT NULL, -- "always" (MVP)
  op_type TEXT NOT NULL,

  cmd_argv_prefix_json TEXT,
  path_exact TEXT,
  path_prefix TEXT,
  path_glob TEXT,

  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  disabled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_rules_source_enabled ON rules(source, enabled);

