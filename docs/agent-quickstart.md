# RACG Agent Quickstart

This file is for an automation agent that works with a running `racg serve`.

Prefer the `racg` client commands over raw HTTP. They handle saved auth, request creation, waiting, live output, final logs, and cancel/kill with compact human-readable output.

## Agent Skill

This repository includes an agentskills.io-style skill for agents:

```text
skills/racg-client-ops/
```

Install it by copying the directory into the agent's skills directory. For Codex:

```bash
mkdir -p ~/.codex/skills
cp -R skills/racg-client-ops ~/.codex/skills/
```

Use the skill when an agent should operate through RACG instead of direct shell execution. It covers login, command submission, live output, final logs, cancel/kill, safe diagnostics, and auto-approve rule boundaries.

## 1. Connect

Inputs needed from the human:

- `HOST`, usually `http://127.0.0.1:8777`
- `PAIRING_CODE`, shown in the RACG TUI

Log in once:

```bash
racg login --host server --pairing-code ABC123
export RACG_CLIENT_NAME=server
racg session status
```

Client login state is saved as named profiles in `~/.config/racg/clients/`. RACG does not keep a global active profile, because that lets one agent shell change another agent's target. If `--name` is omitted, `racg login` derives a profile name from the hostname only: `--host server:8777` saves profile `server`. Select the profile in the current shell with `RACG_CLIENT_NAME`, or pass `--name` on each command. For an explicit single config path, set `RACG_CLIENT_CONFIG`:

```bash
export RACG_CLIENT_CONFIG=/tmp/racg-client.json
racg login --host server --pairing-code ABC123
```

Auth resolution order is explicit `--host/--token`, then `--name` or `RACG_CLIENT_NAME`, then explicit `RACG_CLIENT_CONFIG`. Without one of those, client commands fail:

```bash
racg run --host "$HOST" --token "$TOKEN" -- date
racg run --name prod -- date
RACG_CLIENT_NAME=prod racg session status
RACG_HOST="$HOST" RACG_TOKEN="$TOKEN" racg request logs <id> --live
```

Do not print saved tokens in chat or logs.

## Update RACG

For an already installed binary, prefer the built-in updater over piping the installer again:

```bash
racg update --check
racg update
```

If RACG is installed under `/usr/local/bin` and the current user cannot write there, use:

```bash
sudo racg update --target /usr/local/bin/racg
```

The updater verifies release checksums. If `racg serve` is running, restart it after update so the server process uses the new binary.

## 2. Run Commands

Submit a command and wait for terminal status:

```bash
racg run -- date
racg run -- bash -lc 'date && uname -a'
```

Run multiline shell without nested quoting:

```bash
racg run --script ./maintenance.sh --interpreter /bin/bash

racg run --script-stdin <<'SCRIPT'
set -Eeuo pipefail
printf '%s\n' "$VARIABLE"
docker inspect --format '{{json .Mounts}}' app
SCRIPT
```

Pass a local SQL file or local stdin directly to a command without a remote file:

```bash
racg run --stdin-file ./query.sql -- isql -database main.fdb
printf 'select 1;\n' | racg run --stdin -- isql -database main.fdb
```

The input is staged outside request JSON, verified with SHA-256, displayed in the approval TUI, and supplied directly to process stdin. It is removed after denial, cancellation, or execution. Rules saved for stdin requests include the exact stdin SHA-256, so changing the script or SQL requires a new approval.
Script/stdin modes are not secret transport because their content is intentionally visible during approval.

Expected output is compact, not a full JSON document:

```text
status: PENDING_APPROVAL
waiting_for: server approval
elapsed: 1m42s

Request: <uuid>
Status: SUCCEEDED
Approval wait: 2m13s
Queue wait: 1s
Execution: 14s
Exit code: 0
Output truncated: no
```

Submit a long-running command without waiting:

```bash
racg run --no-wait -- /bin/sh -c 'while true; do date +"tick %H:%M:%S"; sleep 3; done'
```

Useful flags:

```text
--cwd <dir>              command working directory
--execution-timeout <d>  maximum remote process execution time
--timeout <seconds>      legacy execution-timeout alias
--no-wait                print request id and return immediately
--poll-interval <dur>    wait/tail polling interval
--wait-timeout <dur>     maximum local wait; does not cancel the request
--status-interval <dur>  unchanged-status heartbeat; 0 disables
--reconnect-timeout <d>  maximum time to restore observation
--script <file>          execute a local script through interpreter stdin
--script-stdin           read a script from local stdin
--interpreter <path>     interpreter for script modes; default /bin/bash
--stdin-file <file>      pass a local file as exact command stdin
--stdin                  pass local stdin as exact command stdin
```

Resume an existing request after `--no-wait`, a local timeout, terminal closure, or a temporary connection loss:

```bash
racg request wait <request_id> --wait-timeout 30m
```

`request wait` never creates or repeats the remote operation. If local waiting ends, the remote request remains active until it reaches a terminal state or is explicitly cancelled.

## 3. Edit Config Values

Prefer `racg config set` over generating ad-hoc scripts for simple config edits:

```bash
racg config set /app/.env PORT 8080 --format env
racg config set values.yaml image.tag v1.2.3 --format yaml
racg config set config.json server.debug true --format json --type bool
racg config set /etc/netplan/60-static.yaml network '{"version":2}' --format yaml --type json --create
```

Supported formats are `env`, `json`, and `yaml`. For `json` and `yaml`, keys are dotted paths. Supported value types are `string` (default), `bool`, `int`, `float`, `null`, and `json`.

Backups are enabled by default and are written next to the edited file:

```text
config.yaml.racg-backup-YYYYMMDDTHHMMSSZ
```

Use `--no-backup` only when the human explicitly does not want one. YAML/JSON may be reformatted, but RACG parses and validates the result before replacing the file.

If the config file does not exist, pass `--create`. RACG builds and validates the complete config before atomically creating it with mode `0600`; it does not create parent directories and does not write a backup for a newly created file. Without `--create`, a missing file remains an error. Do not create an intermediate empty file with a shell command.

## 4. Read And Patch Plain Text Files

Use `racg file read` and `racg file patch` for non-structured text configs such as HAProxy, nginx, systemd unit files, or application-specific `.cfg` files:

```bash
racg file read /apps/haproxy/haproxy.cfg
racg file read /apps/haproxy/haproxy.cfg --max-bytes 65536
racg file patch /apps/haproxy/haproxy.cfg --diff-file /tmp/haproxy.patch
```

`racg file patch` sends `fs.patch_unified`, so the patch must be a unified diff against the current file content:

```diff
@@ -1,3 +1,3 @@
 global
-    maxconn 2000
+    maxconn 4000
```

Do not use `racg config set --format yaml` for native configs like `haproxy.cfg`; they are plain text, not YAML.

## 5. Upload And Download Files

Use the transfer helpers for binary files, archives, or files too large for `fs.read` output:

```bash
racg file upload ./bundle.tar.gz /srv/releases/bundle.tar.gz
racg file upload ./private.key /etc/app/private.key --mode 0600
racg file download /var/log/app/archive.gz ./archive.gz
racg file download /var/log/app/archive.gz ./archive.gz --force
```

Upload stages bytes without changing the target, then creates an `fs.upload` approval request containing the remote path, size, SHA-256, and requested mode. Approval atomically replaces the target. If `--mode` is omitted, RACG preserves an existing file's permissions or uses `0644` for a new file.

Download creates an `fs.download` approval request first. After approval, RACG snapshots and streams the server file; the client verifies SHA-256 before atomically replacing the local destination. Existing local files require `--force`. File contents are not stored in request JSON or displayed in the TUI.

The default server transfer limit is 100 MiB. Start the server with `--max-transfer-bytes N` to change it. Transfers do not support resume in this version.

## 6. Approval And Status

After request creation, status is usually `PENDING_APPROVAL`. The human decides in the TUI:

- allow once
- allow session
- allow always
- deny

For long-running or pending work, do not submit duplicate requests. Wait for approval, inspect live output after it starts, or cancel if the user asks.

Non-terminal server statuses:

- `PENDING_APPROVAL` — waiting for a human decision
- `APPROVED` — approval has been recorded
- `QUEUED` — waiting for an execution slot
- `RUNNING` — the remote process is running

`SUBMITTED`, `CONNECTION_LOST`, and `CONNECTION_RESTORED` are local client notifications, not persisted server states.

Terminal statuses:

- `SUCCEEDED`
- `FAILED`
- `TIMED_OUT`
- `KILLED`
- `DENIED`
- `CANCELED`

## 7. Live And Final Output

Wait for an existing request, follow its live output, and receive its final exit code:

```bash
racg request wait <request_id>
```

This is the preferred command when the caller must survive a local interruption and later continue waiting for the same request.

Current live combined output while a request is running:

```bash
racg request logs <request_id> --live
```

Follow live output until terminal status:

```bash
racg request tail <request_id>
```

Final raw streams after completion:

```bash
racg request logs <request_id> --stdout
racg request logs <request_id> --stderr
```

`--stdout` and `--stderr` require a finished request. If the server returns `REQUEST_NOT_FINISHED`, use `--live` or `tail`.

## 8. Cancel Or Stop

Cancel a pending request or stop a running command:

```bash
racg request cancel <request_id>
```

For running commands this maps to the server kill path. Verify with live output or final request status.

## 9. Reduce Repeated Approvals

Install narrow read-only presets when the human wants repeated diagnostics to avoid approval friction:

```bash
racg rules presets list
racg rules presets install readonly-diagnostics
```

The preset auto-approves:

- `git status`
- `git log`
- `kubectl get`
- `kubectl describe`
- `kubectl logs`
- `curl *health*`

Do not auto-approve destructive or mutating operations such as `kubectl apply/delete/patch`, `git push`, `sudo`, firewall commands, or filesystem deletion.

The human can view and manually create both persisted `ALLOW_ALWAYS` rules and in-memory `ALLOW_SESSION` rules in the TUI via `3 Rules`. `Add Session` (`s`) requires selecting a session; `Add Always` (`a`) persists the rule. The form supports command scopes and exact, prefix, or glob path scopes. Manual persisted rules obey `allow_always_for_dangerous`. Session rules expire when the server/session ends. Rule enable, disable, and delete actions affect the live engine immediately.

By default `racg serve` stores persisted history and `ALLOW_ALWAYS` rules in `~/.local/state/racg/racg.db`. Humans can start separate server rule/history sets with `racg serve --profile docker` or `racg serve --profile network`; the profile selects a separate DB under the RACG state directory.

When the human chooses `Allow session` or `Allow always` for a command request, RACG opens a scope editor. For shell requests with multiple command segments, the editor shows one scope per segment. Scopes are command patterns, such as `docker stop nginx` or `docker stop n*`. Shell separators (`&&`, `||`, `|`, `;`, `&`) are not part of a scope.

For shell commands, RACG analyzes each command segment independently. A request like `bash -lc 'docker stop nginx && echo ok'` can auto-approve only if both `docker stop nginx` and `echo ok` match rules. If any segment is not allowed, the whole request stays pending.

## 10. Safety Checklist

Before submitting a command, identify:

- cwd
- argv
- timeout
- whether it reads, writes, restarts, deletes, patches, applies, or exposes secrets
- expected output size

Prefer explicit argv over opaque shell strings:

```bash
racg run -- kubectl get pods -A
```

Use shell only when shell features are necessary:

```bash
racg run -- bash -lc 'set -euo pipefail; date; uname -a'
```

Treat these words as extra-risk indicators:

```text
delete
patch
apply
secret
sudo
ufw
iptables
systemctl restart
```

## 11. Raw HTTP Fallback

Use raw HTTP only when the CLI is unavailable.

Open a session:

```bash
curl -sS -X POST "$HOST/v1/session/open" \
  -H 'Content-Type: application/json' \
  -d "{\"pairing_code\":\"$PAIRING_CODE\",\"client_id\":\"codex-cli\"}"
```

Create a command request:

```bash
curl -sS -X POST "$HOST/v1/requests" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"op":{"type":"cmd.run","payload":{"argv":["/bin/uname","-a"],"timeout_sec":120}}}'
```

Read current live output:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  "$HOST/v1/requests/$REQ_ID/logs/live"
```

Useful endpoints:

- `GET /v1/info`
- `GET /openapi.json`
- `POST /v1/session/open`
- `GET /v1/session/me`
- `POST /v1/uploads`
- `POST /v1/requests`
- `GET /v1/requests`
- `GET /v1/requests/{id}`
- `POST /v1/requests/{id}/decision`
- `POST /v1/requests/{id}/kill`
- `GET /v1/requests/{id}/logs/live`
- `GET /v1/requests/{id}/logs/stdout`
- `GET /v1/requests/{id}/logs/stderr`
- `GET /v1/requests/{id}/file`
- `GET /v1/events` (WebSocket)

## 12. Troubleshooting

- `PAIRING_CODE_USED`: reuse the existing saved client config if available, otherwise ask for a new pairing code.
- `REQUEST_NOT_PENDING`: request was already decided or finished.
- `REQUEST_NOT_FINISHED`: use `logs --live` or `tail`; final stdout/stderr are not available yet.
- `ALLOW_ALWAYS_NOT_PERMITTED`: request is dangerous by policy.
- `401/403`: token expired or invalid; log in again with a fresh pairing code.
