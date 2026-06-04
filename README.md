# RACG

RACG is a local Approval Gateway for privileged operations. A client sends requests (`cmd.run`, `fs.read`, `fs.patch_unified`), human approves/denies in terminal UI, and execution is audited in SQLite.

## Features

- HTTP API + WebSocket events
- Built-in TUI approvals dashboard (mouse + hotkeys)
- Session pairing with bearer tokens
- Client helpers for login, approve-and-wait command runs, live logs, tail, and cancel
- Rule engine (`ALLOW_SESSION` / `ALLOW_ALWAYS`)
- Read-only diagnostics rule presets
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
curl -fsSL https://raw.githubusercontent.com/Montelibero/RACG/main/scripts/install.sh | RACG_VERSION=v0.2.0 bash
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

## Client helper commands

Agent-oriented quickstart is in `docs/agent-quickstart.md`.

Log in once with the pairing code shown by `racg serve`:

```bash
racg login --host http://127.0.0.1:8777 --pairing-code ABC123
racg session status
```

Then run client helper commands without passing a token each time:

```bash
racg run -- bash -lc 'date && uname -a'
racg request cancel <request_id>
racg request logs <request_id> --live
racg request tail <request_id>
racg request logs <request_id> --stdout
racg request logs <request_id> --stderr
racg logout
```

You can still override saved config with `--host`, `--token`, `RACG_HOST`, and `RACG_TOKEN`. Client login state is stored in `~/.config/racg/client.json` by default; set `RACG_CLIENT_CONFIG` to use a different path.

`racg run` creates a `cmd.run` request and waits until it reaches a terminal status, then prints compact sections: `request_id`, `status`, `exit_code`, `stdout`, `stderr`.
`racg request logs` reads raw stream endpoints (`/v1/requests/<id>/logs/stdout` and `/v1/requests/<id>/logs/stderr`) so large output can be consumed without parsing the full request JSON.
Use `racg request logs <id> --live` for the current in-memory live output snapshot while a request is still running, or `racg request tail <id>` to follow live output until the request reaches a terminal status.
Use `racg request cancel <id>` to cancel a pending approval or stop a running command.

## Agent skill

This repository includes an agentskills.io-style skill for agents that operate through RACG:

```text
skills/racg-client-ops/
```

Install it by copying the skill directory into your agent's skills directory. For Codex:

```bash
mkdir -p ~/.codex/skills
cp -R skills/racg-client-ops ~/.codex/skills/
```

The skill teaches agents the RACG client workflow: login, `racg run`, live logs, tail, cancel, safe diagnostics, and narrow auto-approve rule guidance.

## Rule presets

Install narrow read-only diagnostics rules into the SQLite rules store:

```bash
racg rules presets list
racg rules presets install readonly-diagnostics --db racg.db
```

`readonly-diagnostics` auto-approves:
- `git status`
- `git log`
- `kubectl get`
- `kubectl describe`
- `kubectl logs`
- `curl *health*`

It does not include write/destructive operations such as `kubectl apply/delete/patch`, `git push`, `sudo`, firewall commands, or filesystem deletion.

## Rule scopes

In the TUI, `Allow session` and `Allow always` open a scope editor for command requests. For shell requests with multiple command segments, the editor shows one scope per segment. A scope is one command pattern, for example:

```text
docker stop nginx
docker stop n*
```

Command scopes are stored as argv-prefix rules. `*` inside an argument is a glob, and extra arguments after the scope are allowed. Shell separators are rejected in scope patterns: `&&`, `||`, `|`, `;`, and `&` must be approved as separate command segments.

For shell requests such as:

```bash
bash -lc 'docker stop nginx && echo ok && rm /'
```

RACG analyzes each shell segment independently. Auto-approve only happens when every segment matches a rule. The TUI request details show `[ALLOW]` and `[BLOCK]` lines with the matching rule or block reason.

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

## Viewing rules in TUI

Press `3 Rules` in the built-in TUI to view rules without leaving `racg serve`.
The page shows persisted `ALLOW_ALWAYS` rules and in-memory `ALLOW_SESSION` rules.
Session rules expire when the server/session ends and cannot be disabled or deleted from the persisted rules store.
