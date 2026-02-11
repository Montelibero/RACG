# RACG

RACG is a local Approval Gateway for privileged operations. A client sends requests (`cmd.run`, `fs.read`, `fs.patch_unified`), human approves/denies in terminal UI, and execution is audited in SQLite.

## Features

- HTTP API + WebSocket events
- Built-in TUI approvals dashboard (mouse + hotkeys)
- Session pairing with bearer tokens
- Rule engine (`ALLOW_SESSION` / `ALLOW_ALWAYS`)
- SQLite audit trail: sessions, requests, decisions, executions, rules
- Command execution with timeout/kill/output limits

## Local run

```bash
racg serve -listen-addr 127.0.0.1 -port 8777
```

For development-specific run settings, see `docs/developer-run.md`.

## Install on server (one line)

```bash
curl -fsSL https://raw.githubusercontent.com/Montelibero/RACG/main/scripts/install.sh | bash
```

Install a specific version:

```bash
curl -fsSL https://raw.githubusercontent.com/Montelibero/RACG/main/scripts/install.sh | RACG_VERSION=v0.1.1 bash
```

Options for installer:

- `RACG_REPO` (default: `Montelibero/RACG`)
- `RACG_VERSION` (default: `latest`)
- `RACG_PREFIX` (default: `/usr/local/bin`)

## Releases

GitHub Actions builds release binaries for Linux on tag push (`v*`).

Create release:

```bash
git tag v0.1.1
git push origin v0.1.1
```

Artifacts in GitHub Release:

- `racg_<version>_linux_amd64.tar.gz`
- `racg_<version>_linux_arm64.tar.gz`
- `checksums.txt`

## API quick check

```bash
curl -sS http://127.0.0.1:8777/v1/info
curl -sS http://127.0.0.1:8777/openapi.json
```
