# RACG CLI Reference

## Auth

Log in with a pairing code shown by `racg serve`:

```bash
racg login --host server --pairing-code ABC123
export RACG_CLIENT_NAME=server
```

Check saved auth:

```bash
racg session status
```

Client auth defaults to named profiles in `~/.config/racg/clients/`. `racg login` does not change global client state. If `--name` is omitted, RACG derives a profile name from the hostname only: `--host server:8777` saves profile `server`. Select it for the current shell:

```bash
export RACG_CLIENT_NAME=server
```

Use one explicit config path when needed:

```bash
RACG_CLIENT_CONFIG=/tmp/racg-client.json racg login --host server --pairing-code ABC123
```

Auth precedence is explicit `--host/--token`, then `--name` or `RACG_CLIENT_NAME`, then explicit `RACG_CLIENT_CONFIG`. Without one of those, client commands fail instead of reading global mutable state:

```bash
racg run --host http://127.0.0.1:8777 --token "$RACG_TOKEN" -- date
racg run --name prod -- date
RACG_CLIENT_NAME=prod racg session status
RACG_HOST=http://127.0.0.1:8777 RACG_TOKEN=... racg request logs <id> --live
```

## Run

Submit and wait:

```bash
racg run -- bash -lc 'date && uname -a'
```

Submit without waiting:

```bash
racg run --no-wait -- /bin/sh -c 'while true; do date; sleep 3; done'
```

Useful flags:

```text
--cwd <dir>              command working directory
--execution-timeout <d>  maximum remote process execution time
--timeout <seconds>      legacy execution-timeout alias
--no-wait                print request id and return immediately
--poll-interval <dur>    wait/tail polling interval
--wait-timeout <dur>     maximum local wait; does not cancel remote work
--status-interval <dur>  status heartbeat; 0 disables
--reconnect-timeout <d>  maximum time to restore observation
--script <file>          execute a local script through interpreter stdin
--script-stdin           read a script from local stdin
--interpreter <path>     interpreter for script modes; default /bin/bash
--stdin-file <file>      pass a local file as exact command stdin
--stdin                  pass local stdin as exact command stdin
```

Multiline scripts and exact stdin:

```bash
racg run --script ./maintenance.sh --interpreter /bin/bash
racg run --script-stdin <<'SCRIPT'
set -Eeuo pipefail
printf '%s\n' "$VARIABLE"
SCRIPT
racg run --stdin-file ./query.sql -- isql -database main.fdb
cat ./query.sql | racg run --stdin -- isql -database main.fdb
```

Input bytes are staged outside request JSON and no persistent remote file is created. The approval view includes size, SHA-256, and exact content. Saved session/always rules include the stdin SHA-256 in addition to argv; existing argv-only rules do not approve requests carrying stdin.

Status transitions are written to stderr. Live output and the final report are written to stdout:

```text
status: <PENDING_APPROVAL|APPROVED|QUEUED|RUNNING|...>
waiting_for: <server approval|execution slot|remote process>

Request: <uuid>
Status: <terminal status>
Exit code: <n>
Output truncated: <yes|no>
```

## Wait And Resume

Attach to an existing request without creating a new request or repeating the operation:

```bash
racg request wait <id> --wait-timeout 30m
```

The command follows status changes and live output, retries temporary observation failures for `--reconnect-timeout`, and returns the remote process exit code. `--wait-timeout` is local only. If it expires, run the same command again; the remote request is not cancelled.

## Config Edits

Use `racg config set` for simple key updates in `env`, `json`, and `yaml` files. This creates a `conf.set` approval request; after human approval RACG parses the file, changes the key, validates the result, writes a backup by default, and atomically replaces the file.

```bash
racg config set /app/.env PORT 8080 --format env
racg config set /app/config.json server.debug true --format json --type bool
racg config set /app/values.yaml image.tag v1.2.3 --format yaml
racg config set /etc/netplan/60-static.yaml network '{"version":2}' --format yaml --type json --create
```

Supported `--type` values for `json`/`yaml` are:

```text
string
bool
int
float
null
json
```

Backups are enabled by default and are written next to the edited file:

```text
<file>.racg-backup-YYYYMMDDTHHMMSSZ
```

Useful flags:

```text
--format <env|json|yaml>  required format
--type <type>             value type, default string
--create                  create a missing file with mode 0600; parent directory must exist
--no-backup               disable backup only when explicitly requested
--backup-dir <dir>        write backup somewhere else
--no-wait                 print request id and return immediately
```

Prefer `racg config set` over generating Python, sed, jq, yq, or shell scripts for a single structured config key update. For arbitrary text edits, use `racg file read` and `racg file patch`.

Without `--create`, a missing config file is an error. With `--create`, RACG validates the complete content and atomically creates the file; no backup is written because there was no original. Do not create an intermediate empty file through `racg run`.

## Plain Text File Reads And Patches

Use `racg file read` and `racg file patch` for non-structured text files such as HAProxy configs, nginx configs, systemd unit files, and application-specific `.cfg` files.

Read a file:

```bash
racg file read /apps/haproxy/haproxy.cfg
racg file read /apps/haproxy/haproxy.cfg --max-bytes 65536
```

Patch a file with a unified diff:

```bash
racg file patch /apps/haproxy/haproxy.cfg --diff-file /tmp/haproxy.patch
racg file patch /apps/haproxy/haproxy.cfg --diff '@@ -1,2 +1,2 @@
 global
-    maxconn 2000
+    maxconn 4000
'
```

Underlying operations:

```text
racg file read   -> fs.read
racg file patch  -> fs.patch_unified
```

## Binary And Large File Transfers

Upload a local file to the server through approval:

```bash
racg file upload ./bundle.tar.gz /srv/releases/bundle.tar.gz
racg file upload ./private.key /etc/app/private.key --mode 0600
```

Download a server file through approval:

```bash
racg file download /var/log/app/archive.gz ./archive.gz
racg file download /var/log/app/archive.gz ./archive.gz --force
```

`upload` stages the bytes, then submits `fs.upload` with the destination path, size, SHA-256, and optional mode. It preserves an existing target's permissions or uses `0644` for a new file. `download` submits `fs.download`, waits for approval, streams the snapshot, verifies SHA-256, and atomically writes the local file. It refuses an existing local destination unless `--force` is passed. Transfer contents do not enter request JSON. The default server limit is 100 MiB; `racg serve --max-transfer-bytes N` changes it. Resume is not supported.

Underlying operations:

```text
racg file upload   -> fs.upload
racg file download -> fs.download
```

Do not use `racg config set --format yaml` for native configs like `haproxy.cfg`; they are plain text, not YAML. Always read the current file before generating a patch.

## Logs

Current live combined output while a request is running:

```bash
racg request logs <id> --live
```

Follow live combined output until terminal status:

```bash
racg request tail <id>
```

Final raw streams after request completion:

```bash
racg request logs <id> --stdout
racg request logs <id> --stderr
```

`--stdout` and `--stderr` require a finished request. If the server returns `REQUEST_NOT_FINISHED`, use `--live` or `tail`.

## Cancel

Cancel pending approval or stop a running command:

```bash
racg request cancel <id>
```

After cancel, verify status:

```bash
racg request logs <id> --live
```

For direct HTTP status checks, use:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" "$HOST/v1/requests/<id>"
```
