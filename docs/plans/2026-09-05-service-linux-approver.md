# RACG service mode and Linux approver

Status: file execution extracted; shared UI contracts, signed protocol primitives, internal authenticated delivery/recovery, peer-verified Unix transport, trusted key/admin boundaries, operation admission/staging, stored execution/result delivery, reusable service grants, desktop transport UI, two-process service commands, trusted admin/enrollment CLI, authenticated agent results/downloads, service stdin/upload staging delivery and pre-dispatch cancellation added. Production packaging/installer is not implemented. User authorized closing the legacy HTTP decision endpoint; it now rejects agent decisions while local TUI decisions remain available. Baseline inspected: `a1fda41`.

## Agreed scope

- Develop in this repository, with separately built and deployed components.
- Primary new workflow: persistent server services and a Linux desktop approver.
- Direct connectivity through existing Tailscale; no relay or Telegram dependency in the first release.
- Preserve standalone `racg serve`: manual SSH launch, existing TUI, pairing, rules, profiles, transfers, results and shutdown behavior. No service installation, device enrollment or Tailscale requirement for this mode.
- Keep the agent CLI and operation semantics shared across both modes.
- Service agents are registered once through trusted SSH administration with a permanent key until explicit revocation/rotation. Service restart requires no new pairing. This credential authorizes request submission, never approval. The user confirmed this onboarding model; interactive pairing remains unchanged.
- Desktop: multiple servers, background connection, sound, notifications, request details, decisions and results. Tray support must be optional.
- Desktop UI is native only. Browser-based UI, browser extensions, WebCrypto signing, Electron/Tauri/Wails-style browser shells and local web approval endpoints are explicitly rejected.
- Mobile is native Android Kotlin + Jetpack Compose. The Docker build produces an installable debug APK without Android Studio; protocol and approval integration are not added yet.
- The mobile shell includes the camera QR import flow. The next mobile stage is enrollment persistence, secure device-key creation, and connection of the signed approval protocol.
- The mobile QR import now validates the trusted setup schema, persists the server profile, and creates an Ed25519 device key encrypted with an Android Keystore wrapping key. It intentionally remains offline until biometric unlock and the signed broker client are added.
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

### Authenticated decision receipt

- Added an authority-signed `DecisionReceipt` that acknowledges durable consumption of an `ALLOW_ONCE` or `DENY` decision. The receipt binds the authority identity, request identity/digest, device identity, action, terminal decision status and a caller-fresh challenge.
- Added `Authority.SubmitDecision` as the local composition boundary for a future transport adapter. It is not a network listener. Receipt acceptance means the decision was durably stored; execution remains a separate durable claim and callback.
- `VerifyDecisionReceipt` independently verifies the original device decision and the authority response. Tests cover both actions, replay rejection, invalid challenges without consumption, request/device/action/status/digest/challenge/signature binding and authority signature failure.
- This remains an internal boundary. Broker transport, authenticated delivery recovery, service composition, trusted enrollment CLI and desktop UX remain unfinished.
- Codespaces snapshot: `.codespaces/decision-receipt-map.1789240177/belief_map.sexp` (118 files, 288 edges, 748 entities), earlier maps/cache retained.

### Authenticated decision recovery

- Added a device-signed `DecisionLookup` bound to the authority, current device, request ID, exact request digest, fresh challenge and caller-chosen validity. This is separate from agent submission lookup and never mutates request state.
- Added `Authority.LookupDecision`: after checking current enrollment/revocation, an enrolled approver receives an authority-signed found/not-found snapshot. A found response contains the pinned signed request, authoritative status and, when already decided, the stored decision action/device. Pending, authorized, executing and terminal states are all inspectable snapshots.
- The response is a snapshot only. Recovery does not submit another decision, consume a pending request, claim execution or rerun an uncertain/finished job. Tests cover lost-receipt recovery, authenticated absence, another enrolled device, impersonation, revocation, expiry and request-digest mismatch.
- This remains an internal boundary. Broker transport, service composition, trusted enrollment CLI and desktop UX remain unfinished.
- Codespaces snapshot: `.codespaces/decision-recovery-map.1789245997/belief_map.sexp` (121 files, 306 edges, 765 entities), earlier maps/cache retained.

### Broker authority transport boundary

- Added `internal/broker` with a versioned, sequential-JSON connection for the only four broker-accessible authority operations: signed agent submission, agent submission lookup, signed decision submission and device decision lookup. The current transport is an injectable stream (tested with an in-memory pipe); there is still no listener, daemon, socket path or deployment.
- The broker `Authority` interface intentionally has no signing, enrollment, revocation, rules or execution methods. The authority independently authenticates agent/device signatures, verifies pinned server/request identity and durably consumes decisions; broker routing fields and status cannot authorize work.
- The broker-side client holds no authority signing key. Its round-trip test verifies a server-signed frozen request, rejects broker modification, obtains an authority-signed decision receipt, executes once through the trusted authority in the test composition, recovers the terminal state through device/agent lookup, and confirms an `authority.execute` method is unknown.
- This is a composition boundary only. Privileged service binaries, Unix-socket ownership/authentication, operation admission, immutable transfer staging, pending-request events, agent result transport, packaging and deployment remain unfinished.
- Codespaces snapshot: `.codespaces/broker-boundary-map.1789248020/belief_map.sexp` (125 files, 337 edges, 780 entities), earlier maps/cache retained.

### Peer-verified Unix transport

- Added a Linux Unix-socket authority listener and broker dialer. The listener binds under an unguessable transient name, applies mode `0660` and the configured broker group, then atomically publishes the configured socket path before accepting traffic. Closing removes the published path.
- Both ends require exact peer UID/GID through Linux `SO_PEERCRED` before protocol bytes are exchanged. The broker dialer also rejects a non-socket or world-writable socket path. Parent-directory ownership remains a composition-root responsibility; the listener does not mutate a directory hierarchy.
- The listener tracks accepted connections and closes from context cancellation. Tests cover socket permissions, atomic publication/cleanup, wrong peer identity, world-writable rejection, authenticated protocol flow and shutdown.
- This remains internal: service binaries/configuration, privilege separation, trusted enrollment CLI, operation admission, immutable staging, event/result transports, packaging and deployment remain unfinished.
- Codespaces snapshot: `.codespaces/unix-transport-map.1789249323/belief_map.sexp` (129 files, 341 edges, 794 entities), earlier maps/cache retained.

### Service composition and configuration

- Added an internal service composition/config layer with deliberately separate defaults for privileged authority state (`/var/lib/racg-authority`) and unprivileged broker state (`/var/lib/racg-broker`), plus one authority socket under `/run/racg`. Authority state owns only its derived database and exclusive lock files; it does not share interactive `racg serve` state.
- Authority service startup validates canonical paths and exact broker UID/GID, prepares a symlink-safe private state directory, acquires a nonblocking exclusive state lock, opens the authority database, and creates the peer-verified listener before returning. Broker startup prepares its own private state and dials the exact authority UID/GID.
- Added explicit service TOML keys and validation that authority/broker state directories remain separate in either direction (including nesting), the socket is outside either state tree, and socket paths agree. Context cancellation closes the listener and returns normally; close removes the socket, closes SQLite and releases the lock.
- Tests cover defaults, TOML parsing, shared/nested-state rejection, socket-in-state rejection, unsafe/symlinked state, duplicate-process lock rejection, broker connection, authority admission rejection, socket cleanup and restart after lock release. Full race tests, vet and Linux amd64/arm64 builds passed.
- This remains internal, with no CLI command or deployment artifact. Real operation admission, immutable staging, execution backend wiring, trusted key/enrollment administration, service binaries, events/results and packaging remain unfinished.
- Codespaces snapshot: `.codespaces/service-composition-map.1789250229/belief_map.sexp` (133 files, 356 edges, 823 entities), earlier maps/cache retained.

### Trusted keys and local administration

- Authority signing identity is generated as standard Ed25519/PKCS#8/PEM and stored under privileged authority state as mode `0600`. Loading rejects symlinks/non-regular files and unsafe modes; creation writes bytes durably to a temporary file and atomically publishes them. This is unattended server identity storage, not the desktop user key's passphrase-protected age format.
- Added a separate trusted admin Unix socket (mode `0600`, exact admin UID/GID via `SO_PEERCRED`) with a narrow registry protocol: list/rotate/revoke devices and list/rotate/revoke agents. It has no decision, execution or server-signing methods and no bearer token.
- Added authority administrative listings and explicit rotate methods. Credential rotation is re-enrollment: pending signatures from the old key fail; consumed decisions and running jobs remain their recorded state. Revocation prevents new decisions and lookups.
- The authority process now serves broker and trusted-admin listeners together and normalizes context cancellation. Tests cover persistent identity, mode/PEM rejection, admin enrollment, signed submission/decision/execution through broker transport, rotation rejection of old device keys, revocation registry state and both peer boundaries.
- This remains internal with no CLI command, service installer or deployment artifact. A separate server-identity key-rotation/migration design, operation admission, immutable staging, execution backend wiring, desktop transport, packaging and deployment remain unfinished.
- Codespaces snapshot: `.codespaces/admin-trust-map.1789253064/belief_map.sexp` (137 files, 385 edges, 858 entities), earlier maps/cache retained.

### Authority operation admission and immutable staging

- Added authority-owned strict admission for the service operation set (`cmd.run`, `fs.read`, `fs.patch_unified`, `fs.upload`, `fs.download`, `conf.set`). Unknown operation fields are rejected so a broker cannot carry behavior-affecting data outside the reviewed display schema.
- Added agent-signed upload staging metadata and authority-owned bytes in SQLite. The agent signs server/client/upload IDs, size and SHA-256; `Authority.StageUpload` authenticates the current enrolled agent, verifies exact bytes and stores them before any operation references them. Retry with the same upload ID/digest is idempotent; reuse with different bytes is rejected.
- `Authority.Submit` now admits operations inside the same transaction that freezes request bytes and submission retry identity. It replaces upload references with authority-assigned size/digest metadata and durably claims each staged byte to the generated request. Admission failure leaves no request or submission; transaction rollback releases claims.
- `Authority.StagedUploadForRequest` exposes immutable bytes only to the trusted execution backend after that exact request has been authorized and claimed. It rechecks owning agent, request claim, size and digest before returning bytes. The broker protocol can relay signed staging bytes but still cannot authorize their use.
- Tests cover staged stdin binding and execution, tampered bytes, single claim semantics, unsupported operations, unknown fields, forged metadata fields and all operation schemas. Full race tests, vet and Linux amd64/arm64 builds passed.
- Remaining: authority-owned download snapshots, streaming transfer transport and explicit resource limits, actual backend dispatch for all operation types, grants/rules, pending events/results, service binaries and desktop transport.
- Codespaces snapshot: `.codespaces/admission-staging-map.1789258681/belief_map.sexp` (140 files, 430 edges, 885 entities), earlier maps/cache retained.

### Stored-operation execution adapter

- Added `Authority.ExecuteStored` as the privileged dispatch adapter. After the existing durable execution claim, it reparses the authority-owned signed operation with the same strict admission schema and dispatches all six operation types to the existing executor implementations. It does not accept broker bytes, paths or status.
- `cmd.run` uses immutable authority-staged stdin, explicit/default timeout and existing process-group/output handling. `fs.upload` reads only the claimed authority-staged bytes. Staged bytes are deleted after a command/upload reaches terminal state; target side effects remain exactly-once-uncertain after a crash.
- `fs.download` snapshots through the existing executor into an authority-owned SQLite artifact with size/SHA-256/mode/name. Retrieval is separate from execution and refuses non-success requests or integrity mismatch. `fs.read`, `fs.patch_unified` and `conf.set` retain the interactive executor semantics.
- Execution options normalize to the existing defaults/output/kill-grace/transfer values until service configuration exposes explicit deployment settings. Tests cover staged stdin deletion, truncated read, upload atomic write/mode/staging cleanup, patch, config edit and authority-owned download snapshot.
- This adapter is not yet automatically wired to broker decisions by the service composition, and agent result/download delivery is not yet implemented. Grants/rules, live events, cancellation transport, operation/resource configuration, service binaries and desktop transport remain unfinished.
- Codespaces snapshot: `.codespaces/operation-runner-map.1789262721/belief_map.sexp` (142 files, 454 edges, 893 entities), earlier maps/cache retained.

### Automatic execution and authenticated result delivery

- The privileged service now wraps its narrow broker authority surface with an execution supervisor. After `SubmitDecision` durably consumes an `ALLOW_ONCE` decision, it dispatches `Authority.ExecuteStored` on a shutdown-tracked worker. The authority socket exposes no execution method; DENY decisions dispatch nothing.
- Authority startup now calls crash recovery after acquiring exclusive state ownership and before opening listeners; interrupted `EXECUTING` requests become `UNCERTAIN` and are never rerun. Graceful shutdown waits for bounded terminal workers before closing SQLite.
- Added explicit authority execution settings (default timeout, output limit, transfer limit, kill grace) to the internal service config, with non-negative validation and established defaults. Zero values retain those defaults until explicitly configured.
- Agent submission lookup now carries the authority-signed terminal `ExecutionResult`. Successful `fs.download` lookup also carries the authority-owned artifact metadata and exact bytes inside the signed response; verification rejects digest mismatch, unexpected downloads, missing successful download artifacts and forged statuses. Pending/denied/non-download responses have no result/artifact.
- Tests cover broker-decision dispatch through service composition, agent lookup after terminal execution, direct execution result/download delivery, result integrity, execution config parsing and graceful worker accounting. Full race tests, vet and Linux amd64/arm64 builds passed.
- Still remaining: live events/cancel transport, reusable grants/rules, service binaries/installer, desktop transport/notifications and packaging.
- Codespaces snapshot: `.codespaces/result-delivery-map.1789264785/belief_map.sexp` (143 files, 475 edges, 902 entities), earlier maps/cache retained.

### Reusable service grants and rules

- Added canonical, agent-scoped `GrantScope` records for `ALLOW_UNTIL` and `ALLOW_ALWAYS`. A scope wraps the existing interactive `rules.Rule` matcher and the exact enrolled agent; a grant is never authority for every client. Unknown scope fields, wrong agents, ambiguous path rules, empty command segments and unsupported operations are rejected.
- A reusable decision now durably creates a grant in the same transaction that consumes the pending request and marks it `AUTHORIZED`. New submissions call authority-side matching before freezing: a matching active grant creates an authorized request linked to that grant; nonmatching or expired operations remain pending. Grants are keyed to one agent and require the enrolling approver device to remain active.
- `claimExecution` rechecks grant linkage, agent ownership, revocation and expiry immediately before trusted dispatch. Explicit admin transport can list and revoke grants; revocation prevents new matches and pending dispatch but does not rewind already-terminal jobs.
- The service execution supervisor dispatches `ALLOW_ONCE`, grant-created `AUTHORIZED` submissions and `ALLOW_UNTIL`/`ALLOW_ALWAYS` decisions exactly once per process, with shutdown-tracked workers. Crashes remain `UNCERTAIN` and never rerun.
- Tests cover matching/nonmatching/foreign-agent submissions, permanent grants, expiry, device revocation, canonical-scope rejection, session-action rejection, admin listing/revocation and full service auto-execution. Full race tests, vet and Linux amd64/arm64 builds passed.
- Still remaining: desktop scope-builder UX, explicit import of legacy unsigned rules, live cancel/events, service binaries/installer and packaging.
- Codespaces snapshot: `.codespaces/service-grants-map.1789267545/belief_map.sexp` (146 files, 521 edges, 921 entities), earlier maps/cache retained.

### Desktop transport and profile foundation

- Added a device-signed pending-list protocol. An enrolled approver device requests a fresh challenge-bound snapshot; the authority signs both empty and non-empty pending queues with their server-signed operation envelopes. This prevents a broker from hiding work by claiming an empty queue and keeps read-only inspection distinct from approval.
- Exposed `ListPending` through the narrow broker protocol and authority authority implementation. It authenticates the current non-revoked device key, never mutates queue state, and returns only a point-in-time snapshot.
- Added desktop-side atomic profile persistence (`0600`, symlink-safe publication, unsafe-parent rejection), a generic protocol connection, a transport that verifies pending snapshots and decision receipts against the pinned server/device identities, and explicit `--connect` wiring into the Service tab. The UI polls on the configured interval, updates a verified request list, announces fresh requests with system notifications, and submits selected Allow once/Deny decisions.
- Tests cover signed empty/non-empty pending snapshots, consumed-request removal, revoked/forged devices, broker transport polling and decision submission/replay, profile round-trip/mode validation and notification text escaping. App race tests, native build/help, full root race tests, vet and Linux amd64/arm64 builds passed.
- Remaining desktop work: reconnect/backoff policy, result and download rendering, enrollment command/UX, tray/background lifecycle and packaging.
- Codespaces snapshot: `.codespaces/desktop-ui-transport-map.1789300955/belief_map.sexp` (153 files, 603 edges, 959 entities), earlier maps/cache retained.

### Two-process service deployment commands

- Added `racg service-authority` and `racg service-broker` with discoverable help, TOML configuration and explicit flag overrides. Authority startup owns/recovering state, opens privileged/admin listeners and serves the signed protocol; broker startup opens an unprivileged TCP/Unix relay, dials the exact peer-verified authority socket per client, and forwards bytes without authorization power.
- The relay keeps no authority state/key and cannot sign or authorize. Broker listener URIs validate `tcp`, `tcp4`, `tcp6` and `unix`; Unix sockets use atomic publication, mode `0600`/`0660` and an inherited/configured GID. Explicit UID/GID flags correctly permit UID/GID 0.
- Added example systemd units and a deployment README for dedicated authority/broker users, private state directories and hardening. They are examples, not an installer/release package.
- Added `racg service-admin` over the exact peer-verified admin socket. It can inspect authority identity, export a mode-0600 desktop profile, list devices/agents/grants, enroll/rotate credentials with Ed25519 public keys and revoke credentials/grants. No bearer token or signing key crosses this boundary.
- Added a full `service-admin` UX: identity/export-profile/list/enroll/rotate/revoke commands with JSON output, `@path` public-key input, atomic profile writes, detailed safety help and integration tests over a real peer-verified admin listener.
- Added an authenticated service-agent client with passphrase-encrypted Ed25519 keys (`age`/scrypt), pinned-server profile loading, generic relay dialing, signed submissions, authenticated result polling and verified atomic `fs.download` artifact delivery. Added `racg service-agent` commands for keygen/public-key/run/download with explicit timeouts and result JSON.
- The broker remains untrusted: requests, lookup snapshots, execution results and download artifacts are verified against the SSH-pinned authority key; the agent key can submit/poll but never approve. `UNCERTAIN` results exit nonzero and are never automatically retried.
- Tests cover encrypted agent-key round trips, signed service submission, terminal result polling and verified fs.download artifact delivery. Full race tests, vet and Linux amd64/arm64 builds passed.
- Added service-agent immutable staging delivery. `service-agent run --stdin-file` and `service-agent upload --local --remote` sign staged bytes, send them through the untrusted relay, let authority admission assign metadata and claim them atomically to the request, then wait for authenticated execution results. Added explicit submission/staging validity and result timeout flags.
- Tests cover agent-signed staged `fs.upload` through the relay protocol, authority claim/admission, executor atomic write/mode and authenticated terminal result. Full race tests, vet and Linux amd64/arm64 builds passed.
- Tests cover relay forwarding with signed queue verification, authority/broker help boundaries, and flag/config validation. Full race tests, vet and Linux amd64/arm64 builds passed.
- Remaining: package/installer, health/readiness endpoints, secrets/KDF policy, reusable-grant scope builder and desktop result/download rendering.
- Codespaces snapshot: `.codespaces/admin-cli-map.1789310182/belief_map.sexp` (159 files, 696 edges, 993 entities), earlier maps/cache retained.

### Signed agent cancellation

- Added an agent-signed cancellation protocol bound to server/agent/request identity, original submission nonce, fresh challenge and caller-chosen validity. A cancellation authorizes mutation only for the originating agent.
- Added `Authority.CancelSubmission` and broker method `CancelSubmission`. The authority durably transitions only `PENDING_APPROVAL` or authorized-not-dispatched requests to `CANCELED`; an already claimed `EXECUTING` request returns an authority-signed refusal/status snapshot and is never falsely claimed killed. The trusted executor can still persist `KILLED` independently, but cancellation never rewrites a running job's state.
- Added `serviceagent.Transport.Cancel`, broker relay support and `racg service-agent cancel`. The agent verifies the authority response, challenge, request identity and `CANCELED` consistency before reporting success. Already-canceled requests return a signed idempotent success snapshot.
- Tests cover cancellation binding/expiry, pending and authorized pre-dispatch cancellation, running-job refusal, final-state preservation, foreign/revoked agent rejection and broker protocol surface. Full race tests, vet and Linux amd64/arm64 builds passed.
- Latest successful architecture snapshot remains `.codespaces/agent-staging-map.1789344784/belief_map.sexp` (164 files, 743 edges, 1022 entities); a newer map rebuild was blocked by an incompatible skill parser update, and earlier maps/cache remain retained.

### Desktop build feasibility and UI integration

- Selected Fyne 2.8.1 in the isolated desktop module; GUI dependencies remain outside the root server build.
- Added explicit `--connect` and `--poll-interval` CLI flags plus a Service tab. The UI polls signed snapshots, announces fresh IDs through system notifications, supports inspecting verified requests, and submits selected `ALLOW_ONCE`/`DENY` decisions only after local signature and authority receipt verification. Offline file inspection and signing remain available without `--connect`.
- Added an unprivileged relay command and privileged authority command. The relay accepts TCP/Unix listeners, dials the peer-verified local authority socket for every client, and blindly forwards protocol bytes; it has no signing key or authorization method. Commands load service TOML, normalize defaults, print readiness, and stop cleanly on context signals.
- Added example systemd units/users/state layout and safety hardening for the two processes. They are deployment examples, not an installer or release package.
- Added background poller cancellation, Fyne main-thread UI updates, device-key locking coordination for transport signatures, URI validation and widget tests using a fake signed protocol connection.
- Official setup reference: https://docs.fyne.io/started/quick/ ; tray lifecycle reference: https://docs.fyne.io/explore/systray/ .
- This workstation is Pop!_OS 24.04, unprivileged UID 1000. GCC and the GL/X11/Xcursor/Xrandr/Xinerama/Xi development interfaces are available. `pkg-config` reports the Xxf86vm development interface missing; `libxxf86vm-dev` is not installed.
- A read-only `apt-get -s install libxxf86vm-dev` simulation proposes installing only that package, without upgrades or removals. Installing it is a system-wide environment change requiring user direction; no package installation has been performed.
- Latest preserved architecture snapshot: `.codespaces/execution-claim-map.qbvAZ6/belief_map.sexp` (109 files, 270 edges, 710 entities).

### Linux desktop offline inspection preview

- User installed `libxxf86vm-dev`; pkg-config now resolves all checked GL/X11/Xxf86vm/Wayland interfaces.
- Added `apps/approver` as an isolated module with Fyne 2.8.1, compatible with Go 1.22.2. Root go.mod/go.sum and static server dependency graph remain unchanged.
- The development window verifies a signed request file against a separately trusted server profile before displaying it. Identity fields are quoted, invisible Unicode formatting/control characters are escaped, and verification failure clears stale content.
- Preview help and project-facing documentation explicitly state: no network, signing, approval or execution; no keys/profiles saved. This is not the completed desktop client. Password-protected signing keys, timed unlock, live service transport and notifications remain unfinished.
- Native binary built successfully and `--help` ran. A demo window was launched with generated public-profile/signed-request fixtures under `/tmp/racg-preview-fixture-4163871496`; no private key was saved and no requested operation executed.
- Computer-use recognized the process/window, but this Linux provider exposes no screenshots and the Fyne content was absent from the accessibility tree. The operator subsequently visually confirmed the native window, signature verification and `/usr/bin/uptime` operation display without truncation.
- Root race tests, CLI help checks, vet and static amd64/arm64 server builds passed. Preview verification/model tests, headless widget tests (`go test -tags ci ./...`) and desktop vet passed.
- Codespaces snapshot: `.codespaces/desktop-preview-map.qE1zOH/belief_map.sexp` (113 files, 276 edges, 722 entities), earlier maps/cache retained.

### Offline signing preview

- Added local Ed25519 device-key creation and unlocking in `apps/approver` using the age v1 passphrase format (scrypt through `filippo.io/age v1.2.1`). Key files are mode 0600, written atomically, and never overwritten by creation.
- Added `Lock now`, optional duration-based auto-lock and explicit help text that locking blocks new signatures but does not revoke envelopes already sent. Key locking and decision validity are independent. Go cannot guarantee erasure of every transient key copy.
- After pinned-server verification, the preview can sign only `ALLOW_ONCE` or `DENY` over the exact stored request digest and display the envelope for explicit copy. It still has no transport, broker, notification or execution path; the authority independently checks enrollment, revocation, expiry and pending state before consuming a decision.
- Tests cover key round-trip, file mode, wrong passphrase, overwrite protection, locking, decision verification and device mismatch; widget tests exercise create, verify, invalid validity, signing and lock. Full root tests and race tests, vet, native/app headless checks and static Linux amd64/arm64 server builds passed.
- The operator visually confirmed encrypted-key creation, request verification, an `ALLOW_ONCE` decision envelope, matching request digest, and the explicit not-sent/not-approved/not-executed status.
- Codespaces snapshot: `.codespaces/offline-signing-map.1789231938/belief_map.sexp` (118 files, 288 edges, 740 entities), earlier maps/cache retained.
