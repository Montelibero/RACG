# RACG MVP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a single `racg` Go binary that exposes a local REST+WS API to request privileged operations, queues them for human approval in a TUI, executes approved operations concurrently, and records rules/audit in SQLite.

**Architecture:** One process `racg serve` hosts HTTP+WS, manages sessions/tokens, maintains an approval queue, runs an executor with bounded concurrency, and persists state to SQLite. The built-in TUI is the only place a human approves/denies.

**Tech Stack:** Go, `net/http`, WebSocket, SQLite (driver), Bubble Tea (TUI), OpenAPI JSON.

---

## Prerequisites / Environment

- Go toolchain installed on the server (MVP assumes `go` is available).
- If Go is missing, install it before starting implementation.

## Conventions

- No production code without a failing test first (TDD).
- Small steps, each 2-5 minutes, frequent commits.
- Keep packages under `internal/`.

## Task 1: Bootstrap Go Module + Minimal CLI Skeleton

**Files:**
- Create: `go.mod`
- Create: `cmd/racg/main.go`
- Create: `internal/cli/root.go`
- Create: `internal/version/version.go`
- Test: `internal/version/version_test.go`

**Step 1: Write the failing test**

Create `internal/version/version_test.go`:
```go
package version

import "testing"

func TestVersionNonEmpty(t *testing.T) {
	if Version == "" {
		t.Fatalf("Version must be non-empty")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./...`
Expected: FAIL with "undefined: Version" or similar.

**Step 3: Write minimal implementation**

Create `internal/version/version.go`:
```go
package version

const Version = "0.1.0"
```

**Step 4: Run test to verify it passes**

Run: `go test ./...`
Expected: PASS.

**Step 5: Implement minimal CLI**

Create `cmd/racg/main.go` to call CLI root and support `racg --version`.

**Step 6: Run**

Run: `go run ./cmd/racg --version`
Expected: prints version.

**Step 7: Commit**

Run:
```bash
git add go.mod cmd/racg/main.go internal/cli/root.go internal/version/version.go internal/version/version_test.go
git commit -m "feat: bootstrap racg CLI"
```

## Task 2: Config + Server Startup (`racg serve`)

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/server/server.go`
- Modify: `internal/cli/root.go`
- Test: `internal/config/config_test.go`

**Step 1: Write failing test**

Test default config values (listen addr, port, limits).

**Step 2: Run failing test**

Run: `go test ./...`

**Step 3: Implement config parsing**

Support `config.toml` path flag + defaults.

**Step 4: Implement `racg serve`**

Start HTTP server, print pairing code to stdout, start TUI.

**Step 5: Run**

Run: `go run ./cmd/racg serve --listen-addr 127.0.0.1 --port 8777`
Expected: server starts; prints pairing code.

**Step 6: Commit**

Commit config + serve skeleton.

## Task 3: SQLite Storage Layer (Migrations)

**Files:**
- Create: `internal/store/store.go`
- Create: `internal/store/migrations/*.sql`
- Test: `internal/store/store_test.go`

Steps: write a test that opens an in-memory DB, runs migrations, inserts one session row.

## Task 4: Auth (Pairing + Session Tokens)

**Files:**
- Create: `internal/auth/pairing.go`
- Create: `internal/auth/tokens.go`
- Modify: `internal/server/server.go`
- Test: `internal/auth/auth_test.go`

Steps: test pairing code TTL, token verification, token expiry.

## Task 5: HTTP API (Info, Session, Requests)

**Files:**
- Create: `internal/httpapi/router.go`
- Create: `internal/httpapi/handlers_info.go`
- Create: `internal/httpapi/handlers_session.go`
- Create: `internal/httpapi/handlers_requests.go`
- Test: `internal/httpapi/httpapi_test.go`

Steps: test `GET /v1/info`, `POST /v1/session/open`, `POST /v1/requests` creates PENDING.

## Task 6: WebSocket Events

**Files:**
- Create: `internal/events/hub.go`
- Modify: `internal/httpapi/router.go`
- Test: `internal/events/hub_test.go`

Steps: test that publishing `request.created` reaches subscribers.

## Task 7: Queue + Decisions + Rules

**Files:**
- Create: `internal/queue/queue.go`
- Create: `internal/rules/matcher.go`
- Modify: `internal/httpapi/handlers_requests.go`
- Test: `internal/rules/matcher_test.go`

Steps: test exact/prefix/glob matching; test auto-approve with `decision_source=rule`.

## Task 8: Executor (cmd.run) + Kill/Timeout + Output Limits

**Files:**
- Create: `internal/executor/executor.go`
- Create: `internal/executor/process.go`
- Test: `internal/executor/executor_test.go`

Steps: test `cmd.run` with `argv=["sh","-c","echo hi"]` is NOT allowed (because shell string not supported). Use `argv=["/bin/echo","hi"]` for tests. Test timeout with `sleep` (if available). Test kill sends SIGTERM/SIGKILL.

## Task 9: FS ops (read, patch_unified) + conf.set_kv (env/ini)

**Files:**
- Create: `internal/ops/fs_read.go`
- Create: `internal/ops/fs_patch.go`
- Create: `internal/ops/conf_set_kv.go`
- Test: `internal/ops/fs_test.go`, `internal/ops/conf_test.go`

Steps: test patch apply on temp files; test env/ini set.

## Task 10: Services ops (status/restart/logs)

**Files:**
- Create: `internal/ops/svc.go`
- Test: `internal/ops/svc_test.go`

Note: for MVP tests, stub systemctl/journalctl via interface to avoid requiring systemd in CI.

## Task 11: TUI Approvals (Bubble Tea)

**Files:**
- Create: `internal/tui/model.go`
- Create: `internal/tui/view.go`
- Create: `internal/tui/update.go`
- Test: `internal/tui/model_test.go`

Steps: test model transitions on keypress; integrate queue feed.

## Task 12: OpenAPI JSON

**Files:**
- Create: `openapi.json`
- Modify: `internal/httpapi/handlers_openapi.go`
- Test: `internal/httpapi/openapi_test.go`

Steps: serve `/openapi.json` and ensure valid JSON returned.

