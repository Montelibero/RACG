# RACG CLI Reference

## Auth

Log in with a pairing code shown by `racg serve`:

```bash
racg login --host server --pairing-code ABC123
racg use server
```

Check saved auth:

```bash
racg session status
```

Client auth defaults to named profiles in `~/.config/racg/clients/`; `racg login` makes the saved profile active. If `--name` is omitted, RACG derives a profile name from the hostname only: `--host server:8777` saves profile `server`. Override it for isolated sessions:

```bash
RACG_CLIENT_CONFIG=/tmp/racg-client.json racg login --host server --pairing-code ABC123
```

Auth precedence is explicit `--host/--token`, then `--name` or `RACG_CLIENT_NAME`, then the active saved profile, then the legacy single config:

```bash
racg run --host http://127.0.0.1:8777 --token "$RACG_TOKEN" -- date
racg run --name prod -- date
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
--timeout <seconds>      command timeout
--no-wait                print request id and return immediately
--poll-interval <dur>    wait/tail polling interval
--wait-timeout <dur>     maximum wait duration for racg run
```

Expected compact output includes:

```text
request_id: <uuid>
status: <PENDING_APPROVAL|RUNNING|SUCCEEDED|FAILED|KILLED|...>
exit_code: <n>
stdout:
...
stderr:
...
```

## Config Edits

Use `racg config set` for simple key updates in `env`, `json`, and `yaml` files. This creates a `conf.set` approval request; after human approval RACG parses the file, changes the key, validates the result, writes a backup by default, and atomically replaces the file.

```bash
racg config set /app/.env PORT 8080 --format env
racg config set /app/config.json server.debug true --format json --type bool
racg config set /app/values.yaml image.tag v1.2.3 --format yaml
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
--no-backup               disable backup only when explicitly requested
--backup-dir <dir>        write backup somewhere else
--no-wait                 print request id and return immediately
```

Prefer `racg config set` over generating Python, sed, jq, yq, or shell scripts for a single structured config key update. For arbitrary text edits, use `racg file read` and `racg file patch`.

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
