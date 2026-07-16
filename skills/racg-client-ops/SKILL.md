---
name: racg-client-ops
description: Use when an agent needs to run commands or transfer files through RACG approval gateway, log in with a pairing code, wait for approved execution, inspect output, cancel requests, or propose narrow auto-approve rules.
---

# RACG Client Operations

Use RACG when command execution must go through a human-approved gateway instead of running directly on the host. Prefer RACG for remote/server diagnostics, long-running jobs, commands that need auditability, or workflows where the human operator approves requests in the RACG TUI.

## Core Workflow

1. Resolve server auth:
   - If the user provides a pairing code, run `racg login --host <url> --pairing-code <code>`.
   - Otherwise check `racg session status`.
   - Do not expose saved tokens in chat or logs.
2. Submit commands with `racg run -- <argv...>`.
   - Use `--no-wait` for long-running commands or when the user wants to approve in TUI first.
   - Use `--wait-timeout` for bounded waits.
3. For config edits in `env`, `json`, or `yaml`, prefer `racg config set` over ad-hoc shell/Python scripts.
   - Use dotted keys for `json`/`yaml`, for example `server.port` or `image.tag`.
   - Set `--type` for non-string values such as booleans, integers, floats, null, or JSON fragments.
   - Keep backups enabled unless the human explicitly asks not to.
   - For a missing config file, use `--create`; RACG validates the complete content and atomically creates the file with mode `0600`. The parent directory must already exist.
4. For plain text files such as HAProxy, nginx, systemd units, or native `.cfg` files, use `racg file read` and `racg file patch` with a unified diff.
   - Do not treat native text configs as YAML just because a compose/stack file references them.
   - Read the current file before generating the unified diff.
5. For running requests, inspect partial output with:
   - `racg request logs <id> --live`
   - `racg request tail <id>`
6. For finished requests, inspect final streams with:
   - `racg request logs <id> --stdout`
   - `racg request logs <id> --stderr`
7. Stop requests with `racg request cancel <id>` when the user asks to interrupt, cancel, kill, or stop a pending/running request.
8. For binary, archive, or large file transfer, use:
   - `racg file upload <local> <remote> [--mode 0600]`
   - `racg file download <remote> <local> [--force]`
   - Do not encode file content into shell commands, JSON, or base64. RACG streams bytes and verifies SHA-256.

## When To Read References

- Read `references/cli.md` for exact command syntax, config editing, flags, output expectations, and common polling patterns.
- Read `references/safety.md` before proposing auto-approve rules or sending commands with destructive words such as delete, patch, apply, secret, sudo, or firewall tooling.
- Read `references/examples.md` for concrete diagnostics, Kubernetes, Git, and long-running command examples.

## Operating Rules

- Use narrow commands and explicit argv. Avoid large opaque shell strings unless the user specifically needs shell composition.
- For simple `env`/`json`/`yaml` config key updates, use `racg config set` instead of generating scripts or raw patches.
- For arbitrary text edits, use `racg file read` plus `racg file patch`; avoid ad-hoc scripts when a unified diff is enough.
- For whole-file transfer, use `racg file upload` or `racg file download`; use `--force` only when replacing the named local destination is intended.
- Prefer read-only diagnostics before mutating operations.
- If a request is pending approval, do not repeatedly resubmit the same command; wait, tail live output after approval, or cancel if requested.
- When reporting results, summarize `status`, `exit_code`, and relevant stdout/stderr sections. Do not paste huge logs unless asked; use live/final log commands to retrieve focused snippets.
- If RACG returns `PAIRING_CODE_USED`, reuse the existing saved client config if available, or ask for a fresh pairing code.
