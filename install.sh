#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/stun-server"
CONFIG_DIR="/etc/stun-server"
SERVICE_FILE="/etc/systemd/system/stun.service"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root: sudo ./install.sh" >&2
  exit 1
fi

apt-get update
apt-get install -y python3.12 python3.12-venv python3-pip rsync ufw

if ! id -u stun >/dev/null 2>&1; then
  useradd --system --home-dir /opt/stun-server --shell /usr/sbin/nologin stun
fi

mkdir -p "${APP_DIR}" "${CONFIG_DIR}"
rsync -a --delete \
  --exclude ".venv" \
  --exclude "__pycache__" \
  "${SOURCE_DIR}/" "${APP_DIR}/"

python3.12 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/python" -m pip install --upgrade pip
"${APP_DIR}/.venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

cat > "${CONFIG_DIR}/config.toml" <<'CONFIG'
[server]
host = "0.0.0.0"
port = 3478
metrics_host = "127.0.0.1"
metrics_port = 8080
log_level = "INFO"
rate_limit_per_minute = 600
allowlist = []
include_software = true
include_fingerprint = true
require_fingerprint = false
# integrity_password = "change-me"
CONFIG

cp "${APP_DIR}/systemd/stun.service" "${SERVICE_FILE}"
chown -R stun:stun "${APP_DIR}"
chmod 0755 "${APP_DIR}"
chmod +x "${APP_DIR}/install.sh"

ufw allow 3478/udp || true

systemctl daemon-reload
systemctl enable stun.service
systemctl restart stun.service

echo "STUN server installed and running."
echo "Validate with: python ${APP_DIR}/examples/client.py <SERVER_PUBLIC_IP>"
