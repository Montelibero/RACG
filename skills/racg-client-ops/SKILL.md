---
name: racg-client-ops
description: Use when an agent needs to run shell commands through RACG approval gateway, log in with a pairing code, wait for approved execution, inspect live or final stdout/stderr, cancel pending/running requests, or propose safe auto-approve rules for repeated read-only diagnostics.
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
3. For running requests, inspect partial output with:
   - `racg request logs <id> --live`
   - `racg request tail <id>`
4. For finished requests, inspect final streams with:
   - `racg request logs <id> --stdout`
   - `racg request logs <id> --stderr`
5. Stop requests with `racg request cancel <id>` when the user asks to interrupt, cancel, kill, or stop a pending/running request.

## When To Read References

- Read `references/cli.md` for exact command syntax, flags, output expectations, and common polling patterns.
- Read `references/safety.md` before proposing auto-approve rules or sending commands with destructive words such as delete, patch, apply, secret, sudo, or firewall tooling.
- Read `references/examples.md` for concrete diagnostics, Kubernetes, Git, and long-running command examples.

## Operating Rules

- Use narrow commands and explicit argv. Avoid large opaque shell strings unless the user specifically needs shell composition.
- Prefer read-only diagnostics before mutating operations.
- If a request is pending approval, do not repeatedly resubmit the same command; wait, tail live output after approval, or cancel if requested.
- When reporting results, summarize `status`, `exit_code`, and relevant stdout/stderr sections. Do not paste huge logs unless asked; use live/final log commands to retrieve focused snippets.
- If RACG returns `PAIRING_CODE_USED`, reuse the existing saved client config if available, or ask for a fresh pairing code.
