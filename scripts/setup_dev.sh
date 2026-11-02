#!/usr/bin/env bash
set -euo pipefail

# Always install into the repository's virtual environment. Never use sudo pip
# or write packages into the OS-managed Python installation (PEP 668).
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "Error: '$PYTHON_BIN' was not found. Install Python 3 and retry." >&2
    exit 1
fi

if [[ ! -x .venv/bin/python ]]; then
    echo "Creating project virtual environment at $ROOT_DIR/.venv"
    if ! "$PYTHON_BIN" -m venv .venv; then
        cat >&2 <<'EOF'
Could not create the virtual environment. On Ubuntu/Debian, install venv
support for your Python version, then run this script again:

  sudo apt update
  sudo apt install python3-venv

If you use a version-specific Python interpreter, install its matching venv
package (for example, python3.12-venv or python3.14-venv).
EOF
        exit 1
    fi
fi

VENV_PYTHON="$ROOT_DIR/.venv/bin/python"

echo "Upgrading pip inside the project virtual environment..."
"$VENV_PYTHON" -m pip install --upgrade pip

echo "Installing MSFAuto and development dependencies..."
"$VENV_PYTHON" -m pip install -e '.[dev]'

cat <<EOF

Setup complete.

Activate the environment with:
  source .venv/bin/activate

Run MSFAuto with:
  python -m msfauto

Run checks with:
  python -m pytest
  python -m ruff check .
EOF
