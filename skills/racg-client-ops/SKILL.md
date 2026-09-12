---
name: racg-client-ops
description: Use when an agent needs to run commands or transfer files through RACG approval gateway, log in with a pairing code, wait for approved execution, inspect output, cancel requests, or propose narrow auto-approve rules.
---

# RACG Client Operations

Use RACG when command execution must go through a human-approved gateway instead of running directly on the host. Prefer RACG for remote/server diagnostics, long-running jobs, commands that need auditability, or workflows where the human operator approves requests in the RACG TUI.

## Core Workflow

The separate desktop development preview (`apps/approver/`,
`racg-approver --help`) inspects offline signed request files and can create an
offline Allow once/Deny envelope. It cannot send an approval, connect or
execute; do not direct pending interactive requests there.

On HTTP 500 `DECISION_PERSISTENCE_FAILED`, retain `error.request_id`: automatic approval failed, but the request exists and remains pending. Ask the operator to fix server storage and review that request in TUI, then resume with `racg request wait <id>`; do not resubmit.

If a manual decision cannot be persisted, the server leaves the request pending without applying new rules or dispatching execution. Ask the operator to resolve the storage error shown in TUI; do not resubmit the operation as a workaround.

Manual approval and denial are local to the server TUI. Agent tokens cannot approve or deny requests over HTTP: the legacy `POST /v1/requests/{id}/decision` endpoint returns `403 REMOTE_DECISION_DISABLED`. Do not retry it or attempt self-approval; submit and wait for the operator. Existing authorized rules may still auto-approve matching requests. Signed remote approval is not yet available. This protection requires an updated, restarted server, not just an updated client.

1. Resolve server auth:
   - If the user provides a pairing code, run `racg login --host <url> --pairing-code <code>`.
   - Treat a client/server version warning from `racg login` as a recommendation, not a login failure. Ask the user before updating either side.
   - Otherwise check `racg session status`.
   - Do not expose saved tokens in chat or logs.
2. Submit commands with `racg run -- <argv...>`.
   - Use `--no-wait` for long-running commands or when the user wants to approve in TUI first.
   - Use `--wait-timeout` for bounded waits.
   - For multiline shell, use `racg run --script <file>` or `racg run --script-stdin`; do not embed a large script in `sh -lc`.
   - For SQL or exact command input, use `racg run --stdin-file <file> -- <argv...>` or pipe into `racg run --stdin -- <argv...>`.
3. For config edits in `env`, `json`, or `yaml`, prefer `racg config set` over ad-hoc shell/Python scripts.
   - Use dotted keys for `json`/`yaml`, for example `server.port` or `image.tag`.
   - Set `--type` for non-string values such as booleans, integers, floats, null, or JSON fragments.
   - Keep backups enabled unless the human explicitly asks not to.
   - For a missing config file, use `--create`; RACG validates the complete content and atomically creates the file with mode `0600`. The parent directory must already exist.
4. For plain text files such as HAProxy, nginx, systemd units, or native `.cfg` files, use `racg file read` and `racg file patch` with a unified diff. `file read` shows line numbers by default; use `--plain` for exact text.
   - Do not treat native text configs as YAML just because a compose/stack file references them.
   - Read the current file before generating the unified diff.
5. Resume or continue waiting for an existing request without resubmitting it:
   - `racg request wait <id> [--wait-timeout 30m]`
   - A local wait timeout or connection failure does not cancel or repeat the remote request.
6. For running requests, inspect partial output with:
   - `racg request logs <id> --live`
   - `racg request tail <id>`
7. For finished requests, inspect final streams with:
   - `racg request logs <id> --stdout`
   - `racg request logs <id> --stderr`
8. Stop requests with `racg request cancel <id>` when the user asks to interrupt, cancel, kill, or stop a pending/running request.
9. For binary, archive, or large file transfer, use:
   - `racg file upload <local> <remote> [--mode 0600]`
   - `racg file download <remote> <local> [--force]`
   - Do not encode file content into shell commands, JSON, or base64. RACG streams bytes and verifies SHA-256.

## When To Read References

- Read `references/cli.md` for exact command syntax, config editing, flags, output expectations, and common polling patterns.
- Read `references/safety.md` before proposing auto-approve rules or sending commands with destructive words such as delete, patch, apply, secret, sudo, or firewall tooling.
- When a human wants to pre-authorize a narrow operation, mention that session and always rules can be created directly in the server TUI under `3 Rules`; a placeholder request is not required.
- Read `references/examples.md` for concrete diagnostics, Kubernetes, Git, and long-running command examples.

## Operating Rules

- Use narrow commands and explicit argv. Avoid large opaque shell strings unless the user specifically needs shell composition.
- Use script/stdin modes for multiline code, SQL, templates, quotes, or literal `$VARIABLE` content. RACG stages exact bytes and uses their SHA-256 for integrity verification and audit. Saved rules match the approved argv scope, not the stdin hash.
- For simple `env`/`json`/`yaml` config key updates, use `racg config set` instead of generating scripts or raw patches.
- A server checks for updates once in the background with a three-second deadline. This never blocks offline startup.
- In the Server tab, `↑` means an update is available and `↻` means the binary was replaced but the running server still needs a deliberate restart.
- The TUI Update action verifies and replaces the binary but never restarts the server or interrupts running jobs. Ask the user before triggering it.
- For arbitrary text edits, use `racg file read` plus `racg file patch`; avoid ad-hoc scripts when a unified diff is enough.
- RACG masks common secret forms in displayed output by default. Use `--unredacted` only when exact command or file output is required; it does not change approval rules.
- For whole-file transfer, use `racg file upload` or `racg file download`; use `--force` only when replacing the named local destination is intended.
- Prefer read-only diagnostics before mutating operations.
- If a request is pending approval, do not repeatedly resubmit the same command; use `racg request wait <id>`, tail live output, or cancel if requested.
- When reporting results, summarize `status`, `exit_code`, and relevant stdout/stderr sections. Do not paste huge logs unless asked; use live/final log commands to retrieve focused snippets.
- If RACG returns `PAIRING_CODE_USED`, reuse the existing saved client config if available, or ask for a fresh pairing code.
