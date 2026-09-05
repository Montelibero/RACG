# RACG service mode and Linux approver

Status: file execution extracted; shared UI contracts and signed protocol primitives added. Service mode and desktop approver are not implemented. User authorized closing the legacy HTTP decision endpoint; it now rejects agent decisions while local TUI decisions remain available. Baseline inspected: `a1fda41`.

## Agreed scope

- Develop in this repository, with separately built and deployed components.
- Primary new workflow: persistent server services and a Linux desktop approver.
- Direct connectivity through existing Tailscale; no relay or Telegram dependency in the first release.
- Preserve standalone `racg serve`: manual SSH launch, existing TUI, pairing, rules, profiles, transfers, results and shutdown behavior. No service installation, device enrollment or Tailscale requirement for this mode.
- Keep the agent CLI and operation semantics shared across both modes.
- Service agents are registered once through trusted SSH administration with a permanent key until explicit revocation/rotation. Service restart requires no new pairing. This credential authorizes request submission, never approval. The user confirmed this onboarding model; interactive pairing remains unchanged.
- Desktop: multiple servers, background connection, sound, notifications, request details, decisions and results. Tray support must be optional.
- Telegram notifications are a later stage. They do not grant execution authority.
- No arbitrary new request, server or device caps. Protocol safety requirements must be explained and distinguished from product policy.

## Desktop UX follow-ups agreed on 2026-09-05

These requirements inform the protocol now; the richer UI can ship after the first vertical slice. The desktop need not reproduce the TUI's session-oriented interaction model.

- Add time-limited reusable grants, with convenient examples such as “Allow for 1 hour” and “Allow for 4 hours”. These are presets, not the only permitted durations. Clearly distinguish one execution from repeated matching operations until expiry.
- Separate rule scope (what may execute, on which server and for which authenticated agent/client) from duration (how long the grant lasts). Do not silently turn a session grant into permission for every agent. Preserve existing session semantics in interactive mode and protocol compatibility where needed.
- Provide an editable scope builder using the actual requested command and its parsed segments/arguments or file paths. Show the exact proposed rule, what is fixed and what is generalized, before signing. Reuse existing matching semantics rather than introducing a second desktop matcher with different behavior. Include temporary and permanent grants, inspection and revocation.
- Protect the desktop signing key with a password and allow unlocking for a user-chosen period, with explicit Lock now. Do not silently unlock signing authority merely because the OS account is logged in. Select vetted encrypted-storage/KDF facilities during implementation, not a custom cryptographic construction.
- Keep the signing-key unlock timer independent from grant expiry. Locking prevents new signatures but does not implicitly revoke previously issued grants or stop running jobs. Show this distinction in the UI.
- Decide auto-lock behavior on inactivity, screen lock, suspend and application restart before shipping key protection. The locked app may receive notifications and display permitted information, but must not sign decisions or silently approve queued requests after unlocking.
- Password protection addresses access to a locked approver or copied encrypted key material. It does not guarantee protection against malware controlling the user's account while the key is unlocked, or capturing a later unlock. Make this boundary clear without adding a mandatory password prompt to every decision.
- Freeze these protocol concepts early: grant scope and expiry must be signed and enforced by the privileged authority independently of the desktop connection or broker's clock. Reconnect/restart must not refresh a grant's lifetime. Specify expiry checks at execution dispatch, clock rollback handling and running-job behavior; expiry alone is not an instruction to kill a job.
- Test expiry boundaries, reconnect without extension, altered expiry/scope, locked-key signing attempts, auto-lock and delayed requests after unlock.

## Current boundaries found through codespaces and source inspection

The existing graph was queried without regeneration. Its symbol locations lag the current source; source is authoritative.

| Current source | Finding | Planned treatment |
|---|---|---|
| `internal/cli/serve.go` | Starts the server, passes concrete API/store to TUI, stops server when UI exits | Preserve this composition as the interactive entry point |
| `internal/server/server.go` | Creates SQLite store, loads rules, rehydrates API and serves HTTP | Separate composition from reusable request lifecycle |
| `internal/httpapi/httpapi.go` | Owns request state, decisions, execution dispatch and TUI-facing methods; decision source is currently recorded as TUI | Extract application operations, explicit decision authority and neutral views |
| `internal/httpapi/transfers.go` | Both stages transfers and performs privileged file operations | Separate transport staging from authorized file execution |
| `internal/executor/executor.go` | Runs processes with argv/cwd/stdin, output capture and process-group handling | Reuse process execution; do not mistake this package for the complete privilege boundary |
| `internal/tui/tview_ui.go` | Depends on concrete API and store | Introduce a local application adapter while preserving UI behavior |
| `internal/rules/`, `internal/store/`, `internal/events/` | Existing matching, persistence and event infrastructure | Reuse after defining authoritative ownership in each mode |

## Target composition

Interactive: existing CLI/TUI -> local application core -> local execution backend.

Service: agent CLI / desktop -> network broker -> local privileged authority/executor.

Proposed new package names are provisional: `internal/application`, `internal/approval`, `internal/privileged`, `internal/broker`, and a separately built approver under `cmd/` or `apps/`.

The broker runs under a dedicated unprivileged account. The executor validates authorization itself through a local IPC protocol. A broker assertion such as `approved=true` or `matched_rule=true` is never authority. Root-owned state includes trusted device keys, authoritative rules, consumed decisions and execution state. Broker-writable queue/cache data cannot authorize execution.

The interactive local adapter is not exposed as an unsigned shortcut in service mode. Agent credentials submit requests and access their results; approver credentials have separately defined authority. Session identity must be authenticated rather than accepted as a broker-supplied label when matching session rules.

Network-free executor means no broker-facing network listener or external approval-service dependency. It must not accidentally prohibit approved child commands from using networking.

## Implementation stages and acceptance criteria

### 1. Establish compatibility baseline

- Inventory current CLI/API behaviors and existing tests, including command input staging, upload/download, manual rules, cancellation, history and rehydration.
- Extend meaningful missing tests around `racg serve` startup/shutdown and TUI decisions before refactoring.
- Capture agent CLI contract tests against the existing in-process composition.
- Acceptance: existing manual workflow works without installed services or registered approver keys; current rules and profiles remain readable.

### 2. Extract shared application operations

- Move request lifecycle and operation dispatch from HTTP handlers behind application interfaces in small steps.
- Separate query views, decision submission, event subscriptions and execution backend.
- Adapt TUI locally; retain existing public commands and semantics.
- Move privileged file operations alongside process execution behind the execution boundary, including configuration editing and transfer output handling.
- Acceptance: shared core does not require TUI, and existing tests plus compatibility tests pass after each extraction.

### 3. Specify and test the approval protocol

- Define a versioned canonical operation envelope covering all behavior-affecting fields, client/session identity, server identity, request ID, immutable payload digests and execution context.
- Bind signed decisions to the exact envelope, action, permission scope, device identity and a fresh single-use challenge. Define validity/expiry behavior explicitly; the earlier 60-second example is not a requirement.
- Bind reusable grants to the full rule content and scope. Authority-side matching, revocation and session lifetimes must survive broker replacement without widening access.
- Executor creates/freezes authoritative request content; the approver verifies server authenticity and displays the content it actually signs. An untrusted broker must not substitute display text while requesting a signature for another operation.
- Freeze staged bytes in authority-owned storage or another reviewed immutable mechanism; independently verify digests. Never hash broker-owned bytes and later execute a mutable pathname to those bytes.
- Specify device enrollment through trusted SSH, server identity verification, key storage, revocation, rotation and recovery through SSH. Device private keys stay on the desktop.
- Test changed argv/cwd/payload/rule, wrong server/session, unknown or revoked key, replay across restarts, conflicting decisions and forged events.
- Acceptance: protocol fixtures and adversarial tests are reviewable before service execution is exposed.

### 4. Implement service composition and persistence

- Add separate broker and privileged binaries/entry points, IPC permissions and explicit service configuration; final CLI names are chosen with their help text.
- Preserve the agent API where possible; make additional connection/enrollment requirements discoverable without rewriting agent workflows.
- Store authorization consumption durably before starting execution. Following a crash, uncertain executions are reported as uncertain/interrupted and are not automatically rerun. Do not promise exactly-once external side effects.
- Reconnect by fetching authoritative snapshots plus events; duplicate decisions/events must not cause duplicate execution.
- An offline approver does not approve pending requests. Existing authorized rules may still match; running jobs do not depend on desktop connectivity.
- Keep service state separate from existing interactive profiles. Importing old unsigned persistent rules requires an explicit trusted administrative step, never automatic broker-side import.
- Test with a malicious broker: fabricated approvals, forged session labels, mutable transfer data, altered rules, replay and restart races.
- Acceptance: a real unprivileged broker can submit work but cannot authorize it; a signed decision executes one corresponding request and returns results to its originating agent.

### 5. Deliver Linux desktop approver

- Select toolkit and packaging after a short Linux/Wayland feasibility check for notifications, sound, secure key storage and background lifecycle. Toolkit is not yet selected.
- Implement SSH-assisted enrollment, multiple server connections, reconnect, server identity display, pending requests and job results.
- Use system notifications to open the full request. Provide a usable window independently of tray availability.
- Initial vertical slice: Allow once and Deny. Plan password-protected signing with timed unlock as part of desktop key management; richer temporary/permanent scope selection may follow. Preserve the TUI's session/always behavior throughout; the desktop can emphasize time-limited grants instead of exposing transport sessions as the primary UX.
- Verify on the user's Linux desktop, including loss of Tailscale connectivity, suspend/resume, notification clicks and simultaneous requests from different servers.
- Acceptance: agent submits a request, desktop sounds/notifies, user reviews and signs, server executes, agent gets the result. The same release still passes standalone `racg serve` tests.

### 6. Packaging, documentation and release gate

- Provide deliberate service installation and lifecycle management, separate desktop packaging, upgrade/recovery instructions and protocol compatibility handling.
- Keep the interactive distribution usable without service setup or desktop dependencies.
- For every shipped public change update applicable root/subcommand help, README, `docs/agent-quickstart.md`, OpenAPI and `skills/racg-client-ops/`; add help-contract tests.
- Run repository tests, vet, race checks for concurrent lifecycle changes and release builds according to the repository workflow. Exercise both modes end to end.
- Review changes since the previous release and execute help for every changed command before versioning. Publication requires an explicit user request.

## Decisions to resolve during the corresponding stage

- Precise canonical encoding, signing/authentication mechanisms, IPC schema and protocol version negotiation.
- Linux toolkit, key-store integration and package format.
- Service-mode agent onboarding and session lifetime, including signed reusable grants and restart behavior.
- Default decision validity and key-recovery UX; no new mandatory confirmation on every click beyond the agreed interaction without discussing the tradeoff.

These are engineering/design follow-ups, not reasons to delay the compatibility inventory and application-boundary extraction plan. This document does not authorize deployment to servers or publication.

## Implementation progress: compatibility and first extraction

- `internal/cli/serve_test.go`: exercise a real ephemeral HTTP listener with an injected UI entry point, startup metadata, profile selection, UI return/ExitFunc/context shutdown, listener release and invalid configuration. The default constructor still launches the existing TUI.
- A real agent CLI login/run/logs round trip now passes through this interactive composition: local Allow once executes, the next identical request remains pending, Deny does not execute, and both decisions are audited as TUI decisions.
- Existing regression suites cover staged stdin, transfers, patch/config operations, session and persistent rules, cancellation, rehydration and CLI wait/reconnect behavior. These remain part of the compatibility gate.
- `internal/httpapi/fs_read_compat_test.go`: pin empty/exact/truncated output, request/server/default limits, full-content hashes, open/read errors and result timestamps before extraction.
- `internal/executor/read_file.go`: reusable already-authorized file read, independent of HTTP and TUI. HTTP retains authorization, effective limit selection, request lifecycle and result serialization. This is an incremental extraction, not the completed application core or privilege separation.
- Checked with local Go 1.22.2: full tests, race tests, vet and static Linux amd64/arm64 builds passed. No CLI/API behavior was intentionally changed; user-facing help and wire schemas remain unchanged.
- The codespaces graph was queried before source inspection. A separate graph refresh was attempted under an ignored `.codespaces/stage1-map.*` directory but could not publish because tree-sitter Go dependencies are absent. Existing maps and caches were preserved; the old graph does not contain the new file.
- Manual terminal UI/Wayland interaction is not covered by these new lifecycle tests: they replace only the UI entry point. Existing TUI unit tests were also run.
- Next extraction: move remaining file execution and introduce application-level request/decision interfaces while retaining the same interactive composition and compatibility tests.

### Go parser setup follow-up

Installed the skill-pinned `tree-sitter==0.25.2` and `tree-sitter-go==0.25.0` through `ov-skill-run codespaces scripts/install-deps.sh go`, using an isolated seeded environment because the system Python has no pip.

Local environment: `.codespaces/go-parsers.TT2Gep/`. Put its absolute `bin` path first in `PATH` when invoking `ov-skill-run` for subsequent builds.

Fresh graph: `.codespaces/verified-map.UKga2P/belief_map.sexp` (79 Go files, 145 import edges, 600 entities). Run graph searches from that directory to select this snapshot rather than the older root map. Verified `quick internal/executor/read_file` resolves the new module and its HTTP dependents. The original root map remains in place; the builder also refreshed its incremental cache. Both new directories are ignored by Git.

### Unified patch and configuration execution extraction

- Added HTTP/TUI compatibility tests before extraction for patch success/failure, denied edits, unchanged files before approval, preserved permissions, config backup suppression, exact output and result hashes.
- Moved the unified patch implementation unchanged into `internal/executor/patch_file.go`; its existing empty-file and no-newline tests moved alongside it. The relocated algorithm was also compared directly against its original text.
- Added `executor.SetConfig` around the existing configuration editor and moved its report formatting into the execution layer. Default backup selection remains unchanged in the HTTP adapter; existing backup and file-creation integration tests pass.
- Read, patch and config operations now share HTTP result translation while preserving request-level timestamps, status, output and hashes. No public command, flag, protocol or rule semantics changed.
- Full tests, race tests, vet and Linux amd64/arm64 static builds passed with Go 1.22.2.
- Latest graph: `.codespaces/file-edit-map.a7es2j/belief_map.sexp` (83 Go files, 155 edges, 605 entities). Query this snapshot for subsequent work. Earlier maps remain; the prior incremental cache was copied to `cache-before.json` in this snapshot directory before rebuilding. Verified the new configuration executor and its dependents via codespaces.
- Remaining extraction includes upload/download staging versus privileged file access, application-level request/decision interfaces and eventual service-mode authorization. No new daemon or remote approver exists yet.

### Transfer, interface and signed-protocol progress

- Added `executor.UploadFile` and `executor.DownloadFile`; HTTP retains transfer ownership, staging and metadata publication. Tests verify binary snapshots, permissions, checksum/size failure without replacing the target, oversize/non-regular downloads and temporary-file cleanup. Existing HTTP transfer tests pass.
- Added `application` views and trusted local `InteractiveBackend`/`HistoryReader` interfaces. TUI no longer requires a concrete HTTP API or SQLite handle. Compatibility aliases preserve existing API caller types and JSON field names. Business request state still lives in HTTP API and needs further extraction.
- Added isolated `approval` protocol primitives using standard-library Ed25519: server-signed immutable request bytes with fresh challenges, and device-signed decisions bound to the full request digest. Grant scope and expiry are signed separately from decision delivery validity. Tests cover mutated request fields, server/device/key mismatch, scope widening, expiry and owned input buffers.
- Protocol verification is not complete execution authorization. Durable replay prevention, enrollment/revocation checks, semantic rule validation, dispatch and broker/service integration remain unimplemented. The new signing code is not exposed as a live endpoint.
- Full race tests (including all packages), vet and static Linux amd64/arm64 builds passed on Go 1.22.2.
- Latest graph: `.codespaces/core-approval-map.XwZ1iJ/belief_map.sexp` (90 Go files, 170 edges, 643 entities); prior maps and a pre-build incremental cache snapshot are retained.

### Resolved: legacy client token self-approval

The baseline public endpoint `POST /v1/requests/{id}/decision` calls `handleDecision` under the same bearer authentication used by the agent. There is no distinct approver role. This behavior exists at baseline HEAD `a1fda41` and is documented in OpenAPI; it was not introduced by this refactor.

A local diagnostic using the public handlers, no TUI decision and no preloaded rules confirmed: client login -> `/bin/echo self-approval-proof` request -> `PENDING_APPROVAL` -> `ALLOW_ONCE` with the same token -> `SUCCEEDED`. The diagnostic is preserved at `.codespaces/approval-self-confirm/main.go`; it does not contact a deployed server.

Recommended compatibility decision: preserve manual `racg serve` and its local TUI, but stop accepting approval decisions authenticated only by an agent token. Remove/disable the legacy HTTP decision path or replace its authorization with a distinct trusted approver mechanism. Update help, quickstart, OpenAPI and affected tests in the same task. Ordinary agent submission/wait/result workflows and local TUI approval should remain available.

The user explicitly authorized closing this endpoint. Authenticated POST requests now return `403 REMOTE_DECISION_DISABLED` without invoking decision logic, parsing approval bodies or creating rules. The old HTTP decision handler is removed. Regression tests cover all four actions with the requesting client's token and a different client's token, unchanged pending state, no decision/rule persistence, authentication and method errors, and retained local TUI denial. Existing execution, audit and automatic-rule tests now make manual decisions through the trusted local TUI interface.

Root/serve help, README, quickstart, OpenAPI and the repository client skill document the boundary. Earlier conversational assurances that a stolen client token could only enqueue work were incorrect. Previously deployed server binaries remain affected until replaced and restarted. No deployed server was changed.

Progress is committed locally by completed task; publication still requires an explicit user request.

Verification: full tests, race tests, vet, Linux amd64/arm64 static builds and root/serve help checks passed with Go 1.22.2. Latest preserved graph snapshot: `.codespaces/decision-fix-map.qZp0RR/belief_map.sexp` (90 Go files, 170 edges, 645 entities), with the prior incremental cache copied alongside it.

### Shared local decision policy

- Extracted the existing exact-rule construction, risk flags and dangerous-rule checks into `application/local_policy.go`, preserving their behavior. HTTP compatibility wrappers delegate to the shared implementation.
- Added `PlanLocalDecision`: prepares a trusted local decision and reusable rules without HTTP, SQLite, queue mutation, events or execution. Existing interactive decisions now use this policy. Caller-owned command/path overrides are copied so later UI input mutation cannot silently change a prepared rule.
- This is not service authorization: the plan must never be trusted when supplied by a broker. Signature/device verification, durable decision consumption and authoritative request storage remain separate, unfinished work.
- Tests cover all existing actions, invalid actions, dangerous operations and broad rules, the existing dangerous-always option, exact path rules, one-shot decisions ignoring reusable scopes, preserved no-rule fallback and owned input data. Existing integration tests retain local approval, execution, rule persistence and the HTTP decision prohibition.
- Full tests, race tests, vet and Linux amd64/arm64 static builds passed with Go 1.22.2. No public command or protocol behavior changed.
- Latest graph: `.codespaces/local-policy-map.4C2eHP/belief_map.sexp` (93 Go files, 180 edges, 654 entities). Earlier graphs and pre-build cache are retained. Graph inspection confirms the new policy has no HTTP dependency.
- Next extraction: authoritative request state and transactional decision persistence. Existing interactive persistence errors are still ignored in parts of the legacy lifecycle; this behavior must not be inherited by the new service authority.

### Atomic manual decision persistence

- Added `store.CommitPendingDecision`: conditional pending-state transition, decision audit and permanent rules commit together, using the existing schema. Duplicate/conflicting decisions cannot overwrite a consumed request, including after reopening the database.
- Local TUI decisions now return persistence failures before changing live request state, installing rules, publishing decision events or dispatching execution. The existing TUI error display presents the failure. No-store in-process test compositions remain supported.
- Tests inject decision-insert and second-rule-insert failures and cancelled contexts, verify full rollback, race allow against deny, reopen the database to check replay rejection, and ensure all four manual actions have no live effects with a closed store.
- Help, README, quickstart, OpenAPI and client skill describe the storage-failure behavior. Full tests/race checks, vet and Linux amd64/arm64 builds passed.
- Graph: `.codespaces/decision-tx-map.r3g4l0/belief_map.sexp` (96 files, 212 edges, 664 entities), with prior cache preserved.
- Automatic rule approval and other lifecycle persistence paths still need migration; the new transaction is not yet a service-mode authority.

### Atomic automatic approvals

- Rule approvals now use the same pending-decision transaction. The local adapter resolves operation, identity and matching rules from stored state and serializes with manual TUI decisions. It never overwrites a non-pending request or dispatches it again.
- Requests become visible in the live queue only after initial persistence succeeds.
- An automatic-approval storage failure returns HTTP 500 `DECISION_PERSISTENCE_FAILED` with the already-created request ID. It remains pending for operator recovery, without execution. Help and all applicable documentation explain that clients should not resubmit it.
- Tests inject a SQLite decision-write failure through the real HTTP submission path, verify persisted/live pending state and no execution, then recover storage and deny the same request. Concurrent manual/automatic decisions dispatch once, and a later matching pass is inert.
- Full race tests and vet passed. Latest preserved graph: `.codespaces/auto-decision-map.8TTXMP/belief_map.sexp` (98 files, 236 edges, 666 entities).

### Isolated service authority state

- Added `internal/authority`, independent of HTTP and the interactive SQLite schema. It pins database identity to the server public key, manages trusted device enrollment/rotation/revocation, and stores server-signed immutable request envelopes with authority-generated IDs and challenges.
- `Consume` reads the stored envelope, verifies the server signature and current enrolled device key, verifies decision binding/expiry and atomically records the first single-shot decision. It returns stored operation bytes only after commit; replay and conflicting decisions are rejected after reopening the file.
- This stage accepts only the agreed initial `ALLOW_ONCE`/`DENY` slice. Reusable grants remain protocol primitives, not executable permissions in the authority.
- Tests cover command/display mutation, unknown/revoked/rotated/wrong keys, cross-request decisions, expiry, conflicting decisions, database rollback, actual database reopen and server identity mismatch.
- No live service or execution entry point is connected. Composition must still enforce private root-owned database/key/socket storage and single-process ownership, authenticate agent identity before request admission, freeze all staged bytes, implement durable execution state and clock rollback handling, and never replay uncertain executions.
- Full race tests and vet passed. Latest graph: `.codespaces/authority-map.4Z5Vcu/belief_map.sexp` (100 files, 238 edges, 676 entities); prior snapshots retained.

### Persistent agent credentials and authenticated admission

- Added a separate authority-owned agent registry with trusted enrollment, rotation and revocation. No agent entry grants approver permissions, even when an agent tries an approver's device ID.
- Added domain-separated Ed25519 submission signatures binding server identity, agent identity, exact operation bytes, a fresh retry nonce and sender-chosen delivery expiry. The agent key has no automatic expiry; delivery expiry applies only to an individual message.
- Authority admission verifies the current registered key and revocation itself, rather than trusting a broker-provided identity. Service requests have no broker-supplied session label.
- A submission nonce and the resulting pending request are committed in one transaction. Identical retries return the same signed envelope, including after database reopen; changed content under the same nonce is rejected. Failed storage leaves no orphan request.
- Tests cover permanent enrollment across reopen, concurrent retries, nonce/content changes, all signed field tampering, expiry, revocation, rotation, separate agent/approver authority, signature domain separation and database rollback.
- Still internal only: trusted SSH CLI enrollment, key-file protection, operation/file admission, broker transport and execution composition remain to be wired. A delivery-expired message needs authenticated inspection/recovery rather than blind creation of another request.
- Full race tests and vet passed. Latest preserved graph: `.codespaces/agent-admission-map.g1OSA6/belief_map.sexp` (104 files, 244 edges, 690 entities).

### Authenticated submission recovery

- Added agent-signed read-only lookup by the original submission nonce, scoped to the currently enrolled agent. Recovery works after submission delivery expiry without creating another operation.
- Both found and not-found outcomes carry a server signature bound to a fresh lookup challenge and sender-chosen lookup expiry. The caller verifies the pinned server key, request owner, envelope signature and response binding; broker-supplied status is not trusted.
- A not-found response is a point-in-time snapshot, not permission to blindly create a new submission while the original delivery could still be in flight. Reuse the original signed submission when still valid, or resolve uncertainty explicitly.
- Tests cover expired-delivery recovery, authenticated absent results, other-agent isolation, revoked/expired lookup credentials, forged status and stale-response replay. Full race tests and vet passed.

### Durable service execution claim

- Added an injected trusted execution boundary: it receives only the stored signed request after a durable single-use execution claim. It does not accept broker-supplied command bytes.
- Before dispatch, the authority re-verifies the stored decision, current approver key/revocation and validity deadline. Pending, denied, expired, revoked and already-claimed requests do not invoke the backend.
- Request status and execution-start record commit before the callback; terminal status and result commit together afterward, even when the command context has been cancelled.
- Startup recovery under exclusive process ownership marks interrupted `EXECUTING` requests `UNCERTAIN`. They are not rerun: a crash may have occurred before or after external side effects. Completion-storage failures also leave the claim consumed.
- Tests cover concurrent/late duplicate dispatch, frozen backend input, pre-dispatch storage failure, revoked/expired approval, cancellation result persistence, completion rollback and uncertain startup recovery. Full race tests and vet passed.
- This remains an internal injected boundary, not a deployed root executor. Real operation admission, immutable file staging, private state/IPC ownership, service wiring, clock rollback handling and desktop UX remain unfinished.
