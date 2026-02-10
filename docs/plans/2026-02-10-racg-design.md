# RACG (Remote Approval Command Gateway) Design

Date: 2026-02-10
Version: 0.1 (MVP design)
Status: Draft

## 0. Scope And Non-Goals

**In scope (MVP):** a single `racg` Go binary that runs on a server during an interactive SSH session and exposes a local HTTP API + WebSocket event stream; a built-in TUI for human approvals; short-lived pairing codes that mint session tokens; an execution engine that runs approved operations (including root operations); a rules store (once/session/always) backed by SQLite; audit logging and export.

**Explicit non-goals (MVP):**
- No automatic rollback.
- No always-on daemon after reboot; no systemd unit required.
- No attempt to “solve” prompt injection beyond human approval + access control + auditing.

**Assumptions:**
- You (a human) are the only person with interactive access to the server during use.
- Agents may issue multiple requests concurrently; approvals are per-request.
- Execution may be concurrent up to a configurable limit (default `max_concurrency=3`).

## 1. Overview

RACG is a **human-in-the-loop remote command gateway**. Agents do not get direct shell access; they can only request high-level operations or `cmd.run(argv[])`. A human reviews each request in a TUI and chooses:
- `Allow once` (this request only)
- `Allow for session` (this request pattern for the current session)
- `Allow always` (persist rule in SQLite)
- `Deny`
- `Kill` (if already running)

RACG prioritizes **presence + approval + audit** over aggressive sandboxing. It still avoids the most foot-gunny interface by default: `cmd.run` accepts **argv only** (no shell string).

## 2. Execution And Concurrency Model

Key decisions (MVP):
- **Approvals are per request.** A human can approve multiple queued requests quickly; approved requests start executing without waiting for prior ones.
- **Execution is concurrent** for all operations including `cmd.run`, limited by `max_concurrency` (config). Default `3`.
- Each execution runs in its own **process group** so `Kill` can terminate reliably.
- Timeouts are enforced per execution (default from config), producing terminal status `TIMED_OUT`.

State machine (request lifecycle):
- `PENDING_APPROVAL` -> `DENIED`
- `PENDING_APPROVAL` -> `APPROVED` -> `RUNNING` -> `SUCCEEDED` | `FAILED` | `KILLED` | `TIMED_OUT`

Agent-facing semantics:
- If the human clicks `Deny`, the agent receives a terminal response: `DENIED_BY_HUMAN`.
- If the human clicks `Allow`, the request proceeds; the agent can either:
  - wait for completion by polling / subscribing to WS, or
  - request an immediate “accepted” response and later fetch results.

Kill semantics (MVP):
- If a request is `RUNNING`, `Kill` sends `SIGTERM` to the process group, waits `kill_grace_sec`, then sends `SIGKILL`.
- If a request is not running yet (queued after approval), `Kill` marks it as `KILLED` and it will not be executed.

## 3. Privilege Modes

RACG supports both modes; default is Mode A.

### 3.1 Mode A (default): `serve` runs as root
- Human starts: `sudo racg serve ...`
- Approved operations execute as root by default.
- Per-operation `run_as` may drop privileges for a specific execution.

### 3.2 Mode B (optional): user + sudo timestamp
- Human starts: `racg serve ...`
- Privileged operations use `sudo -n ...`.
- Human refreshes sudo timestamp manually via `sudo -v` in their own terminal.
- If timestamp expired, execution fails with `NEEDS_SUDO_REFRESH`.

## 4. Network Model

Defaults:
- `listen_addr = 127.0.0.1`
- `port = 8777`

Optional:
- bind to `tailscale0` or an explicit address.
- recommended remote access: Tailscale or SSH tunnel.
- optional **client address lock** when binding beyond localhost (see below).

Threat model notes:
- if binding beyond localhost, tokens become the primary access control.
- optional `allowed_clients` can restrict which `client_id` values are allowed to open sessions.

### 4.1 Client Address Lock (optional)

When exposing RACG beyond localhost (e.g. no VPN), an additional safeguard is to **lock** the server to the
first client IP that successfully pairs.

Behavior (MVP):
- On the first successful `POST /v1/session/open` (valid `pairing_code`), record `locked_client_ip = <remote ip>`.
- For all subsequent HTTP and WebSocket requests, if the remote IP differs from `locked_client_ip`, return `403 CLIENT_ADDR_LOCKED`.
- Reset happens on `racg serve` restart (which also invalidates tokens).

Notes:
- By default RACG uses the TCP peer IP (`RemoteAddr`). If running behind a reverse proxy, do not enable this unless
  you have a trusted way to derive the real client IP.

## 5. Authentication: Pairing And Sessions

On `racg serve` start:
- Generate a **one-time pairing code** (6-8 chars), TTL configurable (default 3 minutes).
- Client calls `POST /v1/session/open` with `client_id` + `pairing_code`.
- If valid, server mints a **session token** (Bearer), TTL configurable (default 8 hours), returns `session_id`.

Token invalidation:
- Stopping the `serve` process invalidates all tokens (because in-memory key material is lost).
- Optionally, explicit revoke endpoint can be added (MVP optional).

### 5.1 HTTP Authorization
- All endpoints except pairing are protected via:
  - `Authorization: Bearer <session_token>`
- The server records `client_id` in audits.

## 6. API Surface (MVP)

All payloads are JSON.

### 6.0 Discovery / Self-Description

There is no single universal “agent API discovery” standard, so RACG provides two pragmatic mechanisms:
- **OpenAPI** for machine-readable HTTP API description.
- A small **capabilities** endpoint tailored for agents (limits, supported ops, auth modes).

Endpoints:
- `GET /openapi.json`: OpenAPI 3.x document (HTTP endpoints, schemas, error codes).
- `GET /v1/info`: server info and capabilities (see below).
- `GET /healthz` (optional): returns `200 OK` if the process is healthy (no auth; minimal output).

`GET /v1/info` response (example):
`{ "server_version": "0.1.0", "api_versions": ["v1"], "ws_url": "/v1/events", "openapi_url": "/openapi.json", "privilege_mode": "root", "limits": { "default_timeout_sec": 120, "max_output_bytes": 1048576, "max_concurrency": 3 }, "features": { "lock_first_client_addr": true }, "supported_ops": ["cmd.run", "fs.read", "fs.patch_unified", "conf.set_kv", "svc.status", "svc.restart", "svc.logs"] }`

### 6.0.1 Error Model

All non-2xx responses return:

```json
{
  "error": {
    "code": "DENIED_BY_HUMAN",
    "message": "Human denied the request",
    "request_id": "optional",
    "details": { "optional": "object" }
  }
}
```

MVP error codes (non-exhaustive):
- `UNAUTHORIZED` (missing/invalid bearer token)
- `FORBIDDEN` (token valid but not allowed)
- `CLIENT_ADDR_LOCKED`
- `PAIRING_CODE_INVALID`
- `PAIRING_CODE_EXPIRED`
- `SESSION_EXPIRED`
- `REQUEST_NOT_FOUND`
- `REQUEST_NOT_PENDING` (e.g. decision attempted after already decided)
- `DENIED_BY_HUMAN`
- `NEEDS_SUDO_REFRESH`
- `OP_NOT_SUPPORTED`
- `PATCH_APPLY_FAILED`
- `TIMEOUT`

### 6.1 Session

`POST /v1/session/open`
- Request: `{ "client_id": "codex-home", "pairing_code": "AB12CD" }`
- Response: `{ "session_id": "...", "session_token": "...", "expires_at": "..." }`

`GET /v1/session/me`
- Response: `{ "session_id": "...", "client_id": "...", "expires_at": "...", "privilege_mode": "root" }`

### 6.2 Requests

`POST /v1/requests`
- Creates a new request in `PENDING_APPROVAL`.
- Request: `{ "op": { ... }, "client_req_id": "optional" }`
- Response: `{ "request_id": "...", "status": "PENDING_APPROVAL" }`

Synchronous convenience (MVP optional):
- `POST /v1/requests?wait=true&timeout_sec=...` blocks until terminal state or timeout.
- If the human denies during the wait, return `403` with `DENIED_BY_HUMAN`.

`GET /v1/requests/{request_id}`
- Returns current status + result (if any).

`GET /v1/requests?status=PENDING_APPROVAL&limit=100`
- For clients that prefer polling.

Request record shape (example):

```json
{
  "request_id": "...",
  "client_req_id": "...",
  "session_id": "...",
  "client_id": "...",
  "created_at": "...",
  "status": "PENDING_APPROVAL",
  "op": { "type": "cmd.run", "payload": { "argv": ["ls", "-la"] } },
  "risk_flags": ["ROOT", "WRITE_ETC"],
  "decision": {
    "decision": "ALLOW_ONCE",
    "decision_source": "tui",
    "decided_at": "..."
  },
  "result": {
    "started_at": "...",
    "finished_at": "...",
    "duration_ms": 12,
    "exit_code": 0,
    "stdout": "...",
    "stderr": "...",
    "stdout_truncated": false,
    "stderr_truncated": false,
    "stdout_sha256": "...",
    "stderr_sha256": "...",
    "status": "SUCCEEDED"
  }
}
```

### 6.3 Approvals (TUI drives this, but keep API for future)

`POST /v1/requests/{request_id}/decision`
- Request: `{ "decision": "ALLOW_ONCE" | "ALLOW_SESSION" | "ALLOW_ALWAYS" | "DENY" }`
- Response: `{ "ok": true }`

`POST /v1/requests/{request_id}/kill`
- Attempts SIGTERM -> wait -> SIGKILL.
- Response: `{ "ok": true }` (execution status changes are delivered via WS / polling)

### 6.4 WebSocket Events

`GET /v1/events` (WebSocket)
- Server emits events like:
  - `request.created`
  - `request.decision`
  - `request.started`
  - `request.output` (optional chunked)
  - `request.finished`

Clients may subscribe to avoid polling.

Event envelope:

```json
{
  "type": "request.finished",
  "ts": "2026-02-10T00:00:00Z",
  "request_id": "...",
  "session_id": "...",
  "client_id": "...",
  "data": { }
}
```

Output streaming (MVP optional):
- `request.output` may be emitted in chunks (e.g. `{ "stream": "stdout", "chunk": "..." }`).
- If output is large, streaming may be omitted; clients should rely on `GET /v1/requests/{id}` for the final stored output.

## 7. Operation Types (MVP)

All operations share a common envelope:

```json
{ "type": "cmd.run", "payload": { ... } }
```

### 7.1 `cmd.run`
Payload:
- `argv`: string[] (required)
- `cwd`: string (optional)
- `timeout_sec`: int (optional; default from config)
- `run_as`: `{ "uid": 0, "gid": 0 }` or `{ "user": "www-data" }` (optional)
- `pty`: bool (optional; default false)

Rules:
- No shell string by default.
- Output is captured up to `max_output_bytes` per stream; exceeding data is truncated and hashed.

### 7.2 `fs.read`
Payload: `path`, optional `start_line`, `end_line`.

### 7.3 `fs.patch_unified`
Payload: `path`, `unified_diff`.
- Server applies patch atomically via write-to-temp + rename.
- Server also shows context lines in TUI (pre-apply) when possible.

### 7.4 `conf.set_kv`
Payload: `path`, `format` (ini|env|toml|yaml), `key`, `value`, optional `section`.
- MVP: implement `env` and `ini` first; keep others behind “not implemented” until needed.

### 7.5 `svc.status` / `svc.restart` / `svc.logs`
- Uses `systemctl` and `journalctl` under the hood.
- `svc.logs` supports `since` and `lines`.

## 8. Approval UX (TUI)

TUI shows:
- who/when: `client_id`, `session_id`, timestamps
- operation summary: type + key fields
- detailed payload:
  - `cmd.run`: argv, cwd, run_as, timeout
  - `fs.patch_unified`: diff
  - `conf.set_kv`: key change summary if old value known
- context preview for file edits (20-50 lines around target)
- **risk flags** (highlighted): root execution, writes under `/etc`, apt installs/removals, firewall/iptables, destructive args (`rm`, `chmod`, `chown`), `systemctl stop/disable ssh*`, etc.

Actions:
- `Allow once`, `Allow for session`, `Allow always`, `Deny`, `Kill` (when running)

Constraint:
- `Allow always` uses *simple patterns only* (exact + prefix/glob). See Rules.

### 8.1 Risk Flags (MVP)

Risk flags are computed server-side and recorded in audit. They drive highlighting in TUI and can gate whether
`ALLOW_ALWAYS` is permitted by default.

Two sources:
- Operation type + payload (e.g. `fs.patch_unified` targeting `/etc/...`).
- Heuristics for `cmd.run(argv[])` (executable + dangerous argv patterns).

Initial flag set (MVP):
- `ROOT` (effective user is root, or requested run_as root)
- `WRITE_ETC` (write/edit under `/etc`)
- `APT_INSTALL`, `APT_REMOVE`
- `FIREWALL` (ufw/iptables/nft)
- `DESTRUCTIVE_FS` (`rm`, `dd`, `mkfs`, `chmod`, `chown`, `mv` into sensitive paths)
- `SERVICE_SSH_RISK` (`systemctl stop/disable ssh/sshd`)

`dangerous = true` if any of: `WRITE_ETC`, `APT_REMOVE`, `FIREWALL`, `DESTRUCTIVE_FS`, `SERVICE_SSH_RISK`.

## 9. Rules Model

Decision types:
- Once: applies only to `request_id`.
- Session: creates an in-memory rule scoped to `session_id`.
- Always: persists rule in SQLite and is loaded on start.

MVP rule matching (simple, predictable):
- For non-cmd ops: match on `op.type` + path constraints (exact or prefix) + selected fields.
- For `cmd.run`: match on:
  - executable (`argv[0]`) exact
  - argv prefix exact for first N args (configurable per rule)
  - optional glob match for path-like args (simple `*`)

Auto-approval behavior:
- If a request matches a session or always rule, the server may skip the TUI prompt and immediately transition the
  request to `APPROVED` and enqueue it for execution.
- The audit record must still include the final effective decision, with `decision_source = rule` (vs `tui`).

Examples:
- allow always: `fs.read` for `path_prefix=/home/itolstov/`
- allow always: `cmd.run` for `argv_prefix=["ls", "-la"]` with `any_cwd=true`
- allow always: `cmd.run` for `argv_prefix=["journalctl", "-u", "nginx"]`

Safety note:
- Some “dangerous” patterns default to **disallow saving as always** unless a policy flag enables it:
  `allow_always_for_dangerous = true`.

## 10. Auditing And Storage (SQLite)

SQLite DB stores:
- sessions
- requests
- decisions
- executions
- rules

Audit requirements:
- Store full requested payload.
- Store human decision, who decided (local user), and when.
- Store execution result: status, exit_code, duration.
- Store stdout/stderr up to limits + hashes + truncated flags.

Log hygiene:
- Do not log env values (store keys only).
- Apply secret-masking regexes to stdout/stderr before storing.
- Retention: configurable (default 90 days).

Secret masking (MVP):
- Apply a small set of default regex masks (bearer tokens, long hex strings, PEM blocks) to stdout/stderr.
- Allow user-supplied masks in config (regex + replacement label).
- Store both masked output and the original SHA256 for integrity checks; do not store raw secrets.

Output capture and hashing (MVP):
- Capture up to `max_output_bytes` per stream (stdout/stderr) for storage and display.
- Independently compute SHA256 over the full byte stream observed (even if truncated for storage) by streaming data
  into a hasher while discarding excess bytes from persistence.
- Record `*_truncated` flags to signal partial storage.

## 11. Configuration

`config.toml`:
- `listen_addr`
- `port`
- `privilege_mode` (`root`|`sudo_timestamp`)
- `default_timeout_sec`
- `max_output_bytes`
- `db_path`
- `log_dir` (optional)
- `max_concurrency`
- `session_token_ttl`
- `pairing_code_ttl`
- `allowed_clients` (optional)
- `lock_first_client_addr` (optional; IP-lock after first successful pairing)
- `allow_always_for_dangerous` (optional; default false)
- `kill_grace_sec` (optional; default 3-10s)
- `retention_days`

## 12. Implementation Outline (Go)

Packages (proposed):
- `internal/httpapi`: REST + WS
- `internal/auth`: pairing + token mint/verify
- `internal/queue`: request queue, decision routing
- `internal/exec`: execution engine, process groups, kill/timeout
- `internal/rules`: matcher + persistence
- `internal/audit`: sqlite writes + export
- `internal/tui`: Bubble Tea UI

## 13. Open Questions (for next iteration)

- Should `cmd.run` ever allow PTY in MVP, or keep it behind a config flag?
- Which config formats for `conf.set_kv` are required immediately beyond env/ini?
- Do we want request “preview” endpoints for config edits to show diff before creating request?
