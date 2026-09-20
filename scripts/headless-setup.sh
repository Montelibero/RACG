#!/usr/bin/env bash
# Headless RACG deployment for Ubuntu: privileged pipeline on a unix socket
# plus the unprivileged public facade. Idempotent — safe to re-run after
# `racg update`.
#
# Usage:
#   sudo bash scripts/headless-setup.sh
#   sudo RACG_PORT=8777 bash scripts/headless-setup.sh
set -euo pipefail

RACG_BIN="${RACG_BIN:-/usr/local/bin/racg}"
RACG_SOCKET="${RACG_SOCKET:-/run/racg/pipeline.sock}"
RACG_PORT="${RACG_PORT:-8777}"
RACG_STATE_DIR="${RACG_STATE_DIR:-/var/lib/racg}"
FACADE_USER="racg-remote"

if [[ "$(id -u)" != "0" ]]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required (this script targets Ubuntu)" >&2
  exit 1
fi

if [[ ! -x "${RACG_BIN}" ]]; then
  echo "racg binary not found at ${RACG_BIN}" >&2
  echo "Install it first: curl -fsSL https://raw.githubusercontent.com/Montelibero/RACG/main/scripts/install.sh | bash" >&2
  exit 1
fi

id -u "${FACADE_USER}" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "${FACADE_USER}"
install -d -m 0750 -o root -g "${FACADE_USER}" "${RACG_STATE_DIR}"

cat > /etc/systemd/system/racg-pipeline.service <<UNIT
[Unit]
Description=RACG privileged pipeline
After=network.target

[Service]
User=root
Group=${FACADE_USER}
Environment=HOME=${RACG_STATE_DIR}
RuntimeDirectory=racg
RuntimeDirectoryMode=0750
ExecStart=${RACG_BIN} serve --headless --socket ${RACG_SOCKET}
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/racg-facade.service <<UNIT
[Unit]
Description=RACG remote-approver facade
After=network.target racg-pipeline.service
Requires=racg-pipeline.service

[Service]
User=${FACADE_USER}
ExecStart=${RACG_BIN} remote-approver --listen 0.0.0.0:${RACG_PORT} --socket ${RACG_SOCKET}
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now racg-pipeline.service racg-facade.service >/dev/null 2>&1 || \
systemctl restart racg-pipeline.service racg-facade.service

echo "Waiting for the facade health check..."
ok=0
for _ in $(seq 1 10); do
  if curl -fsS "http://127.0.0.1:${RACG_PORT}/healthz" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 1
done

if [[ "${ok}" != "1" ]]; then
  echo "Facade did not become healthy; check: journalctl -u racg-pipeline -u racg-facade -n 50" >&2
  exit 1
fi

public_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<NEXT

Headless deployment is up.

Next steps:
  1) Phone enrollment (QR prints right here; pick a tailscale address if asked):
       sudo ${RACG_BIN} approver-setup --public-url http://SERVER:${RACG_PORT}
     (run it again for every additional phone)
  2) Agent login:
       sudo ${RACG_BIN} pairing-code
       racg login --host http://SERVER:${RACG_PORT} --pairing-code ABC123

Detected server address: ${public_ip:-unknown}
NEXT
