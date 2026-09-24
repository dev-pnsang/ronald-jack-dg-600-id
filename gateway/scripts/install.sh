#!/usr/bin/env bash
# Install binary + config + systemd unit (requires root).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${ROOT}/build/checkin-gateway"
if [[ ! -x "$BIN" ]]; then
  echo "Build first: $ROOT/scripts/build.sh" >&2
  exit 1
fi

install -d /usr/local/bin
install -m 0755 "$BIN" /usr/local/bin/checkin-gateway

install -d /etc/checkin-gateway
if [[ ! -f /etc/checkin-gateway/checkin-gateway.conf ]]; then
  install -m 0640 "$ROOT/config/checkin-gateway.conf.example" /etc/checkin-gateway/checkin-gateway.conf
  echo "Created /etc/checkin-gateway/checkin-gateway.conf — edit before start."
fi

install -d /var/lib/checkin-gateway
if ! id checkin-gateway &>/dev/null; then
  useradd --system --home /var/lib/checkin-gateway --shell /usr/sbin/nologin checkin-gateway
fi
chown -R checkin-gateway:checkin-gateway /var/lib/checkin-gateway
chown root:checkin-gateway /etc/checkin-gateway/checkin-gateway.conf
chmod 640 /etc/checkin-gateway/checkin-gateway.conf

install -m 0644 "$ROOT/systemd/checkin-gateway.service" /etc/systemd/system/checkin-gateway.service
systemctl daemon-reload
echo "Installed. Enroll then enable:"
echo "  sudo -u checkin-gateway /usr/local/bin/checkin-gateway --config /etc/checkin-gateway/checkin-gateway.conf --enroll cp_pair_...."
echo "  sudo systemctl enable --now checkin-gateway"
