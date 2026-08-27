UPDATE rules
SET enabled = 0,
    disabled_at = COALESCE(disabled_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    cmd_stdin_sha256 = NULL
WHERE cmd_stdin_sha256 IS NOT NULL;
