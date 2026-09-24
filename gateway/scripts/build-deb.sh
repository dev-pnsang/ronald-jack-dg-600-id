#!/usr/bin/env bash
# Build a .deb that installs checkin-gateway + systemd + ctl helper.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${CHECKIN_GATEWAY_VERSION:-1.2.0}"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo arm64)"
NAME="checkin-gateway"
PKG="${NAME}_${VERSION}_${ARCH}"
OUT_DIR="${CHECKIN_GATEWAY_DEB_OUT:-$ROOT/dist}"
STAGE="$OUT_DIR/$PKG"

echo "==> Building binary"
"$ROOT/scripts/build.sh"

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" \
  "$STAGE/usr/bin" \
  "$STAGE/usr/sbin" \
  "$STAGE/etc/checkin-gateway" \
  "$STAGE/lib/systemd/system" \
  "$STAGE/usr/share/doc/$NAME" \
  "$STAGE/var/lib/checkin-gateway"

install -m 0755 "$ROOT/build/checkin-gateway" "$STAGE/usr/bin/checkin-gateway"
install -m 0755 "$ROOT/scripts/checkin-gatewayctl" "$STAGE/usr/sbin/checkin-gatewayctl"
install -m 0644 "$ROOT/config/checkin-gateway.conf.example" \
  "$STAGE/etc/checkin-gateway/checkin-gateway.conf"
install -m 0644 "$ROOT/systemd/checkin-gateway.service" \
  "$STAGE/lib/systemd/system/checkin-gateway.service"
install -m 0644 "$ROOT/README.md" "$STAGE/usr/share/doc/$NAME/README.md"
install -m 0644 /dev/null "$STAGE/var/lib/checkin-gateway/.keep" 2>/dev/null || \
  : > "$STAGE/var/lib/checkin-gateway/.keep"

# Prefer packaged paths in example shipped as default conf
sed -i 's|^data_dir=.*|data_dir=/var/lib/checkin-gateway|' \
  "$STAGE/etc/checkin-gateway/checkin-gateway.conf" || true

cat > "$STAGE/DEBIAN/control" <<EOF
Package: $NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: libcurl4 | libcurl3t64, libssl3 | libssl1.1, libsqlite3-0, adduser
Maintainer: CommaDesk <support@controlplane.io>
Description: CommaDesk checkin gateway for Ronald Jack DG-600-ID
 Linux agent that syncs ZK attendance punches to CommaDesk Device Identity
 ingest (twice daily ATTLOG + HMAC device auth).
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if ! id checkin-gateway >/dev/null 2>&1; then
  adduser --system --group --home /var/lib/checkin-gateway \
    --shell /usr/sbin/nologin --no-create-home checkin-gateway || true
fi
mkdir -p /var/lib/checkin-gateway
chown -R checkin-gateway:checkin-gateway /var/lib/checkin-gateway
if [ -f /etc/checkin-gateway/checkin-gateway.conf ]; then
  chown root:checkin-gateway /etc/checkin-gateway/checkin-gateway.conf
  chmod 640 /etc/checkin-gateway/checkin-gateway.conf
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl enable checkin-gateway.service || true
fi
echo "checkin-gateway installed."
echo "  1) sudo checkin-gatewayctl set-server https://YOUR-HOST/api/v1"
echo "  2) sudo checkin-gatewayctl enroll 'cp_pair_....'"
echo "  3) sudo checkin-gatewayctl enable"
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop checkin-gateway.service >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/prerm"

cat > "$STAGE/DEBIAN/conffiles" <<EOF
/etc/checkin-gateway/checkin-gateway.conf
EOF

mkdir -p "$OUT_DIR"
dpkg-deb --build "$STAGE" "$OUT_DIR/${PKG}.deb"
echo "Built: $OUT_DIR/${PKG}.deb"
ls -lh "$OUT_DIR/${PKG}.deb"
