# RACG CLI Reference

## Auth

Log in with a pairing code shown by `racg serve`:

```bash
racg login --host http://127.0.0.1:8777 --pairing-code ABC123
```

Check saved auth:

```bash
racg session status
```

Client config defaults to `~/.config/racg/client.json`. Override it for isolated sessions:

```bash
RACG_CLIENT_CONFIG=/tmp/racg-client.json racg login --host http://127.0.0.1:8777 --pairing-code ABC123
```

Auth precedence is explicit flags, then environment variables, then saved config:

```bash
racg run --host http://127.0.0.1:8777 --token "$RACG_TOKEN" -- date
RACG_HOST=http://127.0.0.1:8777 RACG_TOKEN=... racg request logs <id> --live
```

## Run

Submit and wait:

```bash
racg run -- bash -lc 'date && uname -a'
```

Submit without waiting:

```bash
racg run --no-wait -- /bin/sh -c 'while true; do date; sleep 3; done'
```

Useful flags:

```text
--cwd <dir>              command working directory
--timeout <seconds>      command timeout
--no-wait                print request id and return immediately
--poll-interval <dur>    wait/tail polling interval
--wait-timeout <dur>     maximum wait duration for racg run
```

Expected compact output includes:

```text
request_id: <uuid>
status: <PENDING_APPROVAL|RUNNING|SUCCEEDED|FAILED|KILLED|...>
exit_code: <n>
stdout:
...
stderr:
...
```

## Logs

Current live combined output while a request is running:

```bash
racg request logs <id> --live
```

Follow live combined output until terminal status:

```bash
racg request tail <id>
```

Final raw streams after request completion:

```bash
racg request logs <id> --stdout
racg request logs <id> --stderr
```

`--stdout` and `--stderr` require a finished request. If the server returns `REQUEST_NOT_FINISHED`, use `--live` or `tail`.

## Cancel

Cancel pending approval or stop a running command:

```bash
racg request cancel <id>
```

After cancel, verify status:

```bash
racg request logs <id> --live
```

For direct HTTP status checks, use:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" "$HOST/v1/requests/<id>"
```
