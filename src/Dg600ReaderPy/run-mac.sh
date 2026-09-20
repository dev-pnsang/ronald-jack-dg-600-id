#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PYTHON="${PYTHON:-python3}"
if ! "$PYTHON" -c "import zk" >/dev/null 2>&1; then
  echo "Dang cai pyzk ..."
  "$PYTHON" -m pip install --user -r requirements.txt
fi
exec "$PYTHON" dg600_reader.py "$@"
