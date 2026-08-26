# RACG Examples

## Basic Diagnostics

```bash
racg run -- date
racg run -- uname -a
racg run -- df -h
racg run -- free -m
```

## Long-Running Output

Submit:

```bash
racg run --no-wait -- /bin/sh -c 'while true; do date +"tick %H:%M:%S"; sleep 3; done'
```

After approval:

```bash
racg request wait <id>
racg request logs <id> --live
racg request tail <id>
```

If the local terminal closes or waiting times out, resume the same request:

```bash
racg request wait <id> --wait-timeout 30m
```

Stop it:

```bash
racg request cancel <id>
```

## Git

Read-only:

```bash
racg run -- git status --short --branch
racg run -- git log --oneline -20
racg run -- git diff --stat
```

Avoid auto-approving commands that mutate history or working tree:

```text
git reset
git checkout --
git clean
git push --force
```

## Kubernetes Read-Only

```bash
racg run -- kubectl get pods -A
racg run -- kubectl describe pod <pod> -n <namespace>
racg run -- kubectl logs <pod> -n <namespace> --tail=200
```

For live logs:

```bash
racg run --no-wait -- kubectl logs -f <pod> -n <namespace>
racg request tail <id>
```

## Kubernetes Mutations

Keep mutation requests explicit and narrow:

```bash
racg run -- kubectl apply -f /path/to/manifest.yaml
```

Before submitting, summarize:

```text
operation: kubectl apply
target: /path/to/manifest.yaml
namespace: <namespace if known>
risk: cluster mutation
rollback: known/unknown
```

Do not auto-approve apply/delete/patch operations.

## Health Checks

```bash
racg run -- curl -fsS http://127.0.0.1:8080/health
racg run -- curl -fsS https://example.com/healthz
```

If output is large or streaming, use `--no-wait` and `request tail`.

## Config Edits

Update a `.env` value:

```bash
racg config set /srv/app/.env PORT 8080 --format env
```

Update JSON with a boolean value:

```bash
racg config set /srv/app/config.json server.debug false --format json --type bool
```

Update YAML with a dotted key:

```bash
racg config set /srv/app/values.yaml image.tag v1.2.3 --format yaml
```

For non-string YAML/JSON values, pass `--type bool`, `--type int`, `--type float`, `--type null`, or `--type json`. Leave backups enabled unless the human explicitly requests `--no-backup`.

Create a missing structured config without an intermediate empty file:

```bash
racg config set /etc/netplan/60-static.yaml network '{"version":2}' --format yaml --type json --create
```

The parent directory must already exist. RACG validates the complete config and atomically creates it with mode `0600`.

## Plain Text Config Edits

HAProxy config is plain text, not YAML. Read it first:

```bash
racg file read /apps/haproxy/haproxy.cfg --max-bytes 65536
```

Then submit a unified diff:

```bash
racg file patch /apps/haproxy/haproxy.cfg --diff-file /tmp/haproxy.patch
```

Transfer complete files without base64 or shell wrappers:

```bash
racg file upload ./bundle.tar.gz /srv/releases/bundle.tar.gz
racg file download /srv/releases/bundle.tar.gz ./bundle.tar.gz
```

Example diff body:

```diff
@@ -1,3 +1,3 @@
 global
-    maxconn 2000
+    maxconn 4000
```

Use this same flow for nginx configs, systemd unit files, and other native text configs.
