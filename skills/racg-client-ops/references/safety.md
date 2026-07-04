# RACG Safety Reference

## Command Review

Prefer commands whose intent is visible in argv:

```bash
racg run -- kubectl get pods -A
```

Use shell only when shell features are necessary:

```bash
racg run -- bash -lc 'set -euo pipefail; date; uname -a'
```

Before submitting a command, identify:

- cwd
- argv
- timeout
- whether it reads, writes, restarts, deletes, patches, applies, or exposes secrets
- expected stdout/stderr size

## Risk Words

Treat these as requiring extra care and usually manual approval:

```text
delete
patch
apply
secret
sudo
su
ufw
iptables
systemctl restart
kubectl delete
kubectl patch
kubectl apply
```

If a command includes these words, state the risk and keep the operation narrow.

## Config Edits

For `env`, `json`, and `yaml` key updates, prefer:

```bash
racg config set <path> <key> <value> --format <env|json|yaml>
```

This is safer than ad-hoc scripts because RACG validates structured formats and writes a backup by default. Use `--type` for non-string JSON/YAML values. Treat config edits under `/etc/` or production service directories as mutations requiring clear human approval.

For non-structured text files, prefer:

```bash
racg file read <path>
racg file patch <path> --diff-file <patch>
```

`racg file patch` applies a unified diff through `fs.patch_unified`. Read the current file first, keep the diff narrow, and explain the changed lines. Native configs such as `haproxy.cfg` are not YAML.

## Auto-Approve Rules

Auto-approve only narrow read-only prefixes. Good candidates:

```text
git status
git log
kubectl get
kubectl describe
kubectl logs
curl *health*
```

Avoid auto-approve for:

```text
kubectl apply
kubectl delete
kubectl patch
helm upgrade
systemctl restart
sudo
secret reads
firewall changes
```

Install the built-in read-only preset when appropriate:

```bash
racg rules presets list
racg rules presets install readonly-diagnostics
```

## Human Approval UX

For long or complex shell commands, explain the command in concise sections:

```text
cwd: /path
timeout: 120s
argv: bash -lc '...'
risk: read-only diagnostics | writes files | may restart service
expected output: short | long logs | live stream
```

Do not ask the human to approve vague commands. Split broad actions into diagnostics first, then specific mutations.
