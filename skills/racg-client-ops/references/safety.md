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

Use `--execution-timeout` to constrain remote execution. Do not confuse it with `--wait-timeout`, which only stops local observation and deliberately leaves the approved remote request running. Resume observation with `racg request wait <id>` instead of submitting the command again.

For multiline scripts and SQL, use `--script`, `--script-stdin`, `--stdin-file`, or `--stdin` instead of adding quoting layers. RACG shows exact staged content before approval and uses its SHA-256 for integrity verification and audit. Saved session/always rules match the approved argv scope regardless of stdin content, so keep that scope narrow.
These modes are not secret transport: the approval TUI intentionally displays their content. Do not place passwords or tokens in script/stdin input when they must remain hidden from the approver or audit workflow.

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

For a missing config, use explicit `--create`. RACG creates the validated file with mode `0600` only when its parent directory already exists; do not create an intermediate empty file through a shell command.

For non-structured text files, prefer:

```bash
racg file read <path>
racg file patch <path> --diff-file <patch>
```

`racg file patch` applies a unified diff through `fs.patch_unified`. Read the current file first, keep the diff narrow, and explain the changed lines. Native configs such as `haproxy.cfg` are not YAML.

For complete binary or large files, prefer approved transfers over base64 or shell wrappers:

```bash
racg file upload <local> <remote> [--mode 0600]
racg file download <remote> <local> [--force]
```

Treat `fs.upload` as a write operation scoped to the exact remote path. `fs.download` is read-only but may expose sensitive file contents, so keep its path rule narrow. Use `--force` only when replacing the exact local destination is intended.

## Auto-Approve Rules

The server operator can create rules manually in the TUI under `3 Rules` with `Add Session` or `Add Always`. A session rule must target one selected session and remains in memory; an always rule is persisted and obeys `allow_always_for_dangerous`. Command scopes use argv-prefix matching with per-argument `*` globs and reject shell separators. File/config operations support exact, prefix, and glob path scopes.

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
