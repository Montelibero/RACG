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
racg login --host http://127.0.0.1:8777 --pairing-code ABC123
racg session status
```

Client login state is saved in `~/.config/racg/client.json`. For isolated agent sessions, set `RACG_CLIENT_CONFIG`:

```bash
export RACG_CLIENT_CONFIG=/tmp/racg-client.json
racg login --host http://127.0.0.1:8777 --pairing-code ABC123
```

Auth resolution order is explicit flags, then environment variables, then saved config:

```bash
racg run --host "$HOST" --token "$TOKEN" -- date
RACG_HOST="$HOST" RACG_TOKEN="$TOKEN" racg request logs <id> --live
```

Do not print saved tokens in chat or logs.

## 2. Run Commands

Submit a command and wait for terminal status:

```bash
racg run -- date
racg run -- bash -lc 'date && uname -a'
```

Expected output is compact, not a full JSON document:

```text
request_id: <uuid>
status: SUCCEEDED
exit_code: 0
stdout:
...
stderr:
...
```

Submit a long-running command without waiting:

```bash
racg run --no-wait -- /bin/sh -c 'while true; do date +"tick %H:%M:%S"; sleep 3; done'
```

Useful flags:

```text
--cwd <dir>              command working directory
--timeout <seconds>      command timeout
--no-wait                print request id and return immediately
--poll-interval <dur>    wait/tail polling interval
--wait-timeout <dur>     maximum wait duration for racg run
```

## 3. Approval And Status

After request creation, status is usually `PENDING_APPROVAL`. The human decides in the TUI:

- allow once
- allow session
- allow always
- deny

For long-running or pending work, do not submit duplicate requests. Wait for approval, inspect live output after it starts, or cancel if the user asks.

Terminal statuses:

- `SUCCEEDED`
- `FAILED`
- `TIMED_OUT`
- `KILLED`
- `DENIED`
- `CANCELED`

## 4. Live And Final Output

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

## 5. Cancel Or Stop

Cancel a pending request or stop a running command:

```bash
racg request cancel <request_id>
```

For running commands this maps to the server kill path. Verify with live output or final request status.

## 6. Reduce Repeated Approvals

Install narrow read-only presets when the human wants repeated diagnostics to avoid approval friction:

```bash
racg rules presets list
racg rules presets install readonly-diagnostics --db racg.db
```

The preset auto-approves:

- `git status`
- `git log`
- `kubectl get`
- `kubectl describe`
- `kubectl logs`
- `curl *health*`

Do not auto-approve destructive or mutating operations such as `kubectl apply/delete/patch`, `git push`, `sudo`, firewall commands, or filesystem deletion.

## 7. Safety Checklist

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

## 8. Raw HTTP Fallback

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
- `POST /v1/requests`
- `GET /v1/requests`
- `GET /v1/requests/{id}`
- `POST /v1/requests/{id}/decision`
- `POST /v1/requests/{id}/kill`
- `GET /v1/requests/{id}/logs/live`
- `GET /v1/requests/{id}/logs/stdout`
- `GET /v1/requests/{id}/logs/stderr`
- `GET /v1/events` (WebSocket)

## 9. Troubleshooting

- `PAIRING_CODE_USED`: reuse the existing saved client config if available, otherwise ask for a new pairing code.
- `REQUEST_NOT_PENDING`: request was already decided or finished.
- `REQUEST_NOT_FINISHED`: use `logs --live` or `tail`; final stdout/stderr are not available yet.
- `ALLOW_ALWAYS_NOT_PERMITTED`: request is dangerous by policy.
- `401/403`: token expired or invalid; log in again with a fresh pairing code.
