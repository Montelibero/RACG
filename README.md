# RACG

RACG is a local Approval Gateway for privileged operations. A client sends requests such as `cmd.run`, `fs.read`, `fs.patch_unified`, `fs.upload`, or `fs.download`; a human approves or denies them in the terminal UI, and execution is audited in SQLite.

## Features

- HTTP API + WebSocket events
- Built-in TUI approvals dashboard (mouse + hotkeys)
- Session pairing with bearer tokens
- Client helpers for login, approve-and-wait command runs, live logs, tail, and cancel
- Approved binary file upload/download with SHA-256 verification and atomic writes
- Rule engine (`ALLOW_SESSION` / `ALLOW_ALWAYS`)
- Read-only diagnostics rule presets
- SQLite audit trail: sessions, requests, decisions, executions, rules
- Command execution with timeout/kill/output limits

## Local run

```bash
racg serve -listen-addr 127.0.0.1 -port 8777
```

By default the server stores audit history and `ALLOW_ALWAYS` rules in a stable user-state database:

```text
~/.local/state/racg/racg.db
```

Use a server profile when you intentionally want separate rule/history sets, for example Docker diagnostics vs network diagnostics:

```bash
racg serve --profile docker -listen-addr 127.0.0.1 -port 8777
racg serve --profile network -listen-addr 127.0.0.1 -port 8778
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

Update an installed binary from GitHub Releases:

```bash
racg update --check
racg update
sudo racg update --target /usr/local/bin/racg
```

`racg update` verifies the release checksum before replacing the binary. If the target path is not writable, rerun with privileges or pass `--sudo`. A running `racg serve` process keeps using the old in-memory binary until it is restarted.

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
racg login --host server --pairing-code ABC123
export RACG_CLIENT_NAME=server
racg session status
```

`racg login` saves a named client profile under `~/.config/racg/clients/`. It does not change global client state. Without `--name`, the profile name is derived from the hostname only: `--host server:8777` saves profile `server`. Select a profile per shell with `RACG_CLIENT_NAME`, or per command with `--name`:

```bash
racg login --name prod --host prod.example --pairing-code ABC123
racg login --name staging --host staging.example --pairing-code DEF456
export RACG_CLIENT_NAME=prod
racg run --name staging -- date
```

Then run client helper commands without passing a token each time:

```bash
racg run -- bash -lc 'date && uname -a'
racg run --execution-timeout 2m -- long-running-command
racg run --script ./maintenance.sh --interpreter /bin/bash
racg run --stdin-file ./query.sql -- isql -database main.fdb
racg request wait <request_id> --wait-timeout 30m
racg request cancel <request_id>
racg request logs <request_id> --live
racg request tail <request_id>
racg request logs <request_id> --stdout
racg request logs <request_id> --stderr
racg file read /apps/haproxy/haproxy.cfg
racg file read /apps/haproxy/haproxy.cfg --plain --unredacted
racg file patch /apps/haproxy/haproxy.cfg --diff-file /tmp/haproxy.patch
racg file upload ./bundle.tar.gz /srv/releases/bundle.tar.gz
racg file download /var/log/app/archive.gz ./archive.gz
racg config set /app/.env PORT 8080 --format env
racg config set values.yaml image.tag v1.2.3 --format yaml
racg config set config.json server.debug true --format json --type bool
racg config set /etc/netplan/60-static.yaml network '{"version":2}' --format yaml --type json --create
racg logout
```

You can still override saved config with `--host`, `--token`, `RACG_HOST`, and `RACG_TOKEN`. Set `RACG_CLIENT_CONFIG` to use one explicit config file, or `RACG_CLIENT_NAME` to select a saved profile for the current shell. Without `--name`, `RACG_CLIENT_NAME`, `RACG_CLIENT_CONFIG`, or `--host` plus `--token`, client commands fail instead of reading global mutable state.

`racg run` creates a `cmd.run` request and waits until it reaches a terminal status. While waiting, status transitions and periodic heartbeats are written to stderr; live combined output and the final timing/exit-code report are written to stdout. Use `--status-interval 0` to disable heartbeats.
`racg request wait <id>` resumes observation of an existing request without creating or repeating it. It follows live output, survives temporary connection failures for `--reconnect-timeout` (default `5m`), and returns the remote process exit code. A local `--wait-timeout` only stops the client: it never cancels the remote request. Run the same `request wait` command again to resume.
Use `--execution-timeout 2m` to limit the remote process. The legacy `--timeout <seconds>` form remains supported. This execution timeout is independent from local `--wait-timeout`.
Use `racg run --script <local-file>` or `--script-stdin` for multiline shell code without command-line quoting. Use `--stdin-file <local-file> -- <argv...>` or `--stdin -- <argv...>` to pass SQL or other exact bytes to any command. RACG stages the bytes, shows their content and SHA-256 in the approval TUI, sends them directly to process stdin, and removes the staged copy after denial, cancellation, or execution. No persistent remote file is created. The SHA-256 verifies and audits the staged bytes; reusable session/always rules match the approved argv scope regardless of stdin content.
`racg request logs` reads dedicated stream endpoints (`/v1/requests/<id>/logs/stdout` and `/v1/requests/<id>/logs/stderr`) so large output can be consumed without parsing the full request JSON.
Use `racg request logs <id> --live` for the current in-memory live output snapshot while a request is still running, or `racg request tail <id>` to follow live output until the request reaches a terminal status.
Use `racg request cancel <id>` to cancel a pending approval or stop a running command.
Use `racg config set` to request a format-aware config edit without shell scripts. It supports `env`, `json`, and `yaml`; writes a backup next to an existing file by default; validates the result before replacing the file; and uses dotted keys for `json`/`yaml`. Pass `--create` to atomically create a missing file with mode `0600`; its parent directory must already exist.
Use `racg file read` and `racg file patch` for plain text files such as HAProxy, nginx, systemd unit files, or other non-JSON/YAML configs. `file patch` submits an `fs.patch_unified` request and expects a unified diff.
`racg file read` numbers lines by default so unified-diff hunk coordinates are visible; pass `--plain` for the original text. RACG masks common password, token, authorization, credential-URL, and private-key forms in command and file output by default. Pass `--unredacted` to `run`, `request wait/logs/tail`, or `file read` when the exact raw output is required. Redaction is best-effort presentation filtering; stored audit output and hashes remain unchanged.
Use `racg file upload <local> <remote>` and `racg file download <remote> <local>` for binary or large files. Both create approval requests. File bytes are streamed outside JSON, checked with SHA-256, and written atomically. Upload preserves an existing target's permissions or uses `0644` for a new file; pass `--mode 0600` when needed. Download refuses to replace a local file unless `--force` is passed. The server default transfer limit is 100 MiB and can be changed with `racg serve --max-transfer-bytes N`.

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
racg rules presets install readonly-diagnostics
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
- `fs.download` для явно разрешённого пути
- `cmd.run` с безопасными командами чтения/диагностики (`cat`, `ls`, `uname`, `date` и т.п.)

Dangerous (по умолчанию `ALLOW_ALWAYS` запрещен):
- `WRITE_ETC` (`fs.patch_unified`/`fs.upload`/`conf.set` по `/etc/...`)
- `APT_REMOVE` (`apt/apt-get remove|purge`)
- `FIREWALL` (`iptables`, `nft`, `ufw`)
- `DESTRUCTIVE_FS` (`rm`, `/bin/rm`)
- `SERVICE_SSH_RISK` (`systemctl stop|disable ...ssh...`)

Примечание: `ALLOW_ALWAYS` для dangerous можно включить флагом `allow_always_for_dangerous=true` в конфиге.

## Viewing rules in TUI

Press `3 Rules` in the built-in TUI to view rules without leaving `racg serve`.
The page shows persisted `ALLOW_ALWAYS` rules and in-memory `ALLOW_SESSION` rules.
Use `Add Session` (`s`, also works on a Russian keyboard layout) to create an in-memory rule for a selected session. Use `Add Always` (`a`) to create a persisted rule. The form supports command scopes and exact, prefix, or glob path scopes for existing file/config operations. Command scopes use the same parser as approval scopes, so shell separators must be represented by separate rules.
Manual persisted rules obey `allow_always_for_dangerous`; dangerous `Add Always` rules are rejected unless that server option is explicitly enabled. Session rules remain available for temporary authorization.
Session rules expire when the server/session ends and can be deleted from the Rules page. Persisted rules can be enabled, disabled, or deleted; changes take effect in the live rule engine immediately.
