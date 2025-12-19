#!/usr/bin/env bash
set -euo pipefail

echo "[*] Purview SIT Analyzer – setup (macOS)"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv-purview"

# ---------------------------------------
# 1. Ensure Homebrew exists
# ---------------------------------------
if ! command -v brew >/dev/null 2>&1; then
  echo "[!] Homebrew not found"
  echo "    Install from https://brew.sh and re-run setup"
  exit 1
fi

# ---------------------------------------
# 2. Install system dependencies if missing
# ---------------------------------------
echo "[*] Checking system dependencies..."

BREW_DEPS=(
  boost
  cmake
  nlohmann-json
)

for dep in "${BREW_DEPS[@]}"; do
  if ! brew list "$dep" >/dev/null 2>&1; then
    echo "[*] Installing missing dependency: $dep"
    brew install "$dep"
  else
    echo "[✓] $dep already installed"
  fi
done

# ---------------------------------------
# 3. Ensure python3 exists
# ---------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 not found"
  echo "    Install with: brew install python"
  exit 1
fi

# ---------------------------------------
# 4. Create Python virtual environment
# ---------------------------------------
if [ ! -d "$VENV_DIR" ]; then
  echo "[*] Creating Python venv: .venv-purview"
  python3 -m venv "$VENV_DIR"
else
  echo "[✓] Python venv already exists"
fi

# ---------------------------------------
# 5. Activate venv
# ---------------------------------------
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

# ---------------------------------------
# 6. Upgrade pip tooling
# ---------------------------------------
echo "[*] Upgrading pip tooling"
pip install --upgrade pip setuptools wheel

# ---------------------------------------
# 7. Install Python dependencies
# ---------------------------------------
echo "[*] Installing Python dependencies"

pip install \
  pdfminer.six \
  pandas \
  numpy \
  psutil

# ---------------------------------------
# 8. Sanity check
# ---------------------------------------
python - <<'EOF'
import sys
import pdfminer
print("[✓] Python version:", sys.version.split()[0])
print("[✓] pdfminer version:", pdfminer.__version__)
EOF

echo
echo "[✓] Setup complete"
echo
echo "Next steps:"
echo "  1. ./run.sh <files>"