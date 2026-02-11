# RACG Agent Quickstart

This file is for an automation agent that works with a running `racg serve`.

## 1) Connect to RACG

Inputs needed from human:
- `BASE_URL` (example: `http://127.0.0.1:8777`)
- `PAIRING_CODE` (shown in TUI)
- `CLIENT_ID` (your agent name, example: `codex-cli`)

Open session:

```bash
BASE_URL="http://127.0.0.1:8777"
PAIRING_CODE="ABC123"
CLIENT_ID="codex-cli"

curl -sS -X POST "$BASE_URL/v1/session/open" \
  -H 'Content-Type: application/json' \
  -d "{\"pairing_code\":\"$PAIRING_CODE\",\"client_id\":\"$CLIENT_ID\"}"
```

Save `session_token` from response and use it as bearer token:

```bash
TOKEN="<session_token>"
AUTH_HEADER="Authorization: Bearer $TOKEN"
```

## 2) Submit operations

Create request (`cmd.run`, argv only):

```bash
curl -sS -X POST "$BASE_URL/v1/requests" \
  -H 'Content-Type: application/json' \
  -H "$AUTH_HEADER" \
  -d '{"op":{"type":"cmd.run","payload":{"argv":["/bin/uname","-a"],"timeout_ms":5000}}}'
```

Create request (`fs.read`):

```bash
curl -sS -X POST "$BASE_URL/v1/requests" \
  -H 'Content-Type: application/json' \
  -H "$AUTH_HEADER" \
  -d '{"op":{"type":"fs.read","payload":{"path":"/etc/hosts","max_bytes":4096}}}'
```

Notes:
- Do not use shell string mode for commands.
- Send absolute paths (not `~`).

## 3) Wait for human approval

After request creation, status is usually `PENDING_APPROVAL`.
Human decides in TUI:
- `ALLOW_ONCE`
- `ALLOW_SESSION`
- `ALLOW_ALWAYS`
- `DENY`

Poll request:

```bash
REQ_ID="<request_id>"
curl -sS "$BASE_URL/v1/requests/$REQ_ID" -H "$AUTH_HEADER"
```

Terminal statuses:
- `SUCCEEDED`
- `FAILED`
- `TIMED_OUT`
- `KILLED`
- `DENIED`

## 4) How to reduce repeated approvals

Important:
- No operation is auto-approved from scratch.
- Auto-approval appears only after human creates a rule (`ALLOW_ALWAYS`).

Practical flow:
1. Send safe read/diagnostic request.
2. Human chooses `ALLOW_ALWAYS`.
3. Similar future requests are auto-approved by rules.

## 5) What is considered dangerous

`ALLOW_ALWAYS` is blocked by default for dangerous requests.
Danger flags:
- `WRITE_ETC`
- `APT_REMOVE`
- `FIREWALL`
- `DESTRUCTIVE_FS`
- `SERVICE_SSH_RISK`

Config override:
- `allow_always_for_dangerous=true` (not recommended by default)

## 6) Useful endpoints

- `GET /v1/info`
- `GET /openapi.json`
- `POST /v1/session/open`
- `GET /v1/session/me`
- `POST /v1/requests`
- `GET /v1/requests`
- `GET /v1/requests/{id}`
- `POST /v1/requests/{id}/decision`
- `POST /v1/requests/{id}/kill`
- `GET /v1/events` (websocket)

## 7) Minimal troubleshooting

- `PAIRING_CODE_USED`: ask human for a new pairing code.
- `REQUEST_NOT_PENDING`: request already decided/finished.
- `ALLOW_ALWAYS_NOT_PERMITTED`: request is dangerous by policy.
- `401/403`: token expired or invalid; reopen session with new pairing code.
