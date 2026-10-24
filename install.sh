#!/usr/bin/env bash
set -euo pipefail
ATLAS_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python3 -m venv "$ATLAS_ROOT/.venv"
"$ATLAS_ROOT/.venv/bin/python" -m pip install --require-hashes -r "$ATLAS_ROOT/requirements-runtime.lock"
"$ATLAS_ROOT/.venv/bin/python" -m pip install --no-deps "$ATLAS_ROOT"
chmod +x "$ATLAS_ROOT/atlas"
mkdir -p "$HOME/.local/bin" "$HOME/.local/share/man/man1"
# Wrapper resolves the project path reliably; moving the folder requires reinstalling.
printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$ATLAS_ROOT/atlas" > "$HOME/.local/bin/atlas"
chmod +x "$HOME/.local/bin/atlas"
cp "$ATLAS_ROOT/man/atlas.1" "$HOME/.local/share/man/man1/atlas.1"
printf 'Installed. Add ~/.local/bin to PATH, then type atlas to open the colorful menu.\n'

if [[ "${ATLAS_SKIP_ENGINES:-0}" != 1 ]]; then
  "$ATLAS_ROOT/.venv/bin/python" "$ATLAS_ROOT/atlas.py" setup-engines
fi
