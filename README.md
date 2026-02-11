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

Release process for maintainers is documented in `docs/developer-run.md`.

## API quick check

```bash
curl -sS http://127.0.0.1:8777/v1/info
curl -sS http://127.0.0.1:8777/openapi.json
```

## Safe vs Dangerous (`ALLOW_ALWAYS`)

`ALLOW_ALWAYS` разрешен для запросов без dangerous-флагов.

Обычно safe (можно сохранять как always):
- `fs.read` (например чтение `~/.bashrc`, лучше указывать абсолютный путь)
- `cmd.run` с безопасными командами чтения/диагностики (`cat`, `ls`, `uname`, `date` и т.п.)

Dangerous (по умолчанию `ALLOW_ALWAYS` запрещен):
- `WRITE_ETC` (`fs.patch_unified`/`conf.set_kv` по `/etc/...`)
- `APT_REMOVE` (`apt/apt-get remove|purge`)
- `FIREWALL` (`iptables`, `nft`, `ufw`)
- `DESTRUCTIVE_FS` (`rm`, `/bin/rm`)
- `SERVICE_SSH_RISK` (`systemctl stop|disable ...ssh...`)

Примечание: `ALLOW_ALWAYS` для dangerous можно включить флагом `allow_always_for_dangerous=true` в конфиге.
