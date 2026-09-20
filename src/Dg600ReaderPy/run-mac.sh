#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Web GUI ổn định trên macOS (Tk hệ thống hay ẩn Label/Entry).
PYTHON="${PYTHON:-/usr/bin/python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  PYTHON="python3"
fi
DEPS_DIR=".deps"

if ! PYTHONPATH="$DEPS_DIR${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" -c "import zk" >/dev/null 2>&1; then
  echo "Dang cai pyzk bang $PYTHON ..."
  "$PYTHON" -m pip install --target "$DEPS_DIR" -r requirements.txt
fi

export PYTHONPATH="$DEPS_DIR${PYTHONPATH:+:$PYTHONPATH}"
echo "Chay WEB GUI voi: $PYTHON"
exec "$PYTHON" web_gui.py "$@"
