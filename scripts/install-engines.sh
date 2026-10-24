#!/usr/bin/env bash
set -euo pipefail
ATLAS_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -x "$ATLAS_ROOT/.venv/bin/python" ]]; then
  ATLAS_PYTHON="$ATLAS_ROOT/.venv/bin/python"
else
  ATLAS_PYTHON=python3
fi
exec "$ATLAS_PYTHON" "$ATLAS_ROOT/atlas.py" setup-engines "$@"
