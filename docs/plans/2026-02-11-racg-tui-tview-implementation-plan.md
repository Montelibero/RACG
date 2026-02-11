# RACG TUI (tview/tcell) Implementation Plan

**Goal:** Replace the minimal Bubble Tea approvals UI with a fully mouse+keyboard-driven tview/tcell TUI per the 0.1 UX spec (pairing page, dashboard, rules, history, job live output).

**Architecture:** `racg serve` starts HTTP API + in-process TUI. TUI is event-driven: subscribe to the in-process event hub and use `Application.QueueUpdateDraw` for all view updates. A periodic refresh is allowed as a safety net for dropped events.

**Tech Stack:** Go 1.22.2, `github.com/rivo/tview`, `github.com/gdamore/tcell/v2`.

## Current State (as of 2026-02-11)

Implemented skeleton:
- Pairing page with regen + expiry countdown.
- Dashboard layout: pending list + details + running list + status bar.
- Rules and History pages (minimal lists).
- Job page skeleton + follow toggle + kill confirmation.
- Live output support via executor callbacks + `request.output` events.

Gaps vs spec:
- Proper focus highlighting + explicit Tab cycle order.
- Pending list selection stability and mouse interactions validation.
- Running jobs should show finished jobs (toggle all/only-running).
- Job view tabs for multiple jobs + keyboard switching (`Alt+1/2/3`, `[` `]`).
- Toast actions (View/Approve once/Deny) and optional bell.
- Better request details rendering (argv list + quoting, diff highlighting).
- Rules page: test rule, create rule from last decision, enable/disable/delete UX.
- History: session view + operations drilldown (later).

## Tasks (TDD)

### Task 1: Stabilize selection + focus cycle
- Add unit-testable state helpers for selection mapping (pending/job lists).
- Ensure Tab cycles: Pending -> Details -> Jobs -> Status (or closest primitives).
- Verify mouse click selects items; wheel scroll works on lists/textviews.

### Task 2: Jobs list + job view tabs
- Track running + recently finished jobs in UI state.
- Add toggle `Show all / Only running`.
- Add job tabs on job view; support `[` `]` and `Alt+N`.

### Task 3: Toast notifications
- Show non-focus-stealing toast on `request.created`.
- Add actions: View / Approve once / Deny (modal or inline).

### Task 4: Request details formatting
- `cmd.run`: show argv list + display-only quoted command string.
- `fs.patch_unified`: simple diff coloring for +/- lines.
- Add Copy modal with plain text block.

### Task 5: Rules UX
- Add enable/disable/delete to Rules page (already partially done).
- Add "test rule" input (argv/path) -> match result.
- Add "new rule from last decision" (pick last approved request).

### Task 6: Help overlay + keymap legend
- Add `F1`/`?` overlay with keymap + risk badge legend.

### Task 7: OpenAPI sync
- Update `/openapi.json` to include `fs.read`, `fs.patch_unified`, decision/kill semantics, and event types including `request.output`.

## Verification
- `GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOMODCACHE=/tmp/gomodcache go test ./...`
- Manual: `go run ./cmd/racg serve` over SSH, verify mouse selection/scroll, approve/deny, live output, kill, pages navigation.

