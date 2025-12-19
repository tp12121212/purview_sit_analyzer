#!/usr/bin/env bash
set -euo pipefail

V4_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$V4_DIR/.." && pwd)"

ENGINE_SRC="$V4_DIR/engine"
ENGINE_BUILD="$ENGINE_SRC/build"
ENGINE_BIN="$ENGINE_BUILD/boost_regex_runner"

PYTHON_DIR="$V4_DIR/python"
EXPECTED_VENV="$REPO_ROOT/.venv-purview"

# ---------------------------------------
# Python environment handling (fixed)
# ---------------------------------------

if [ -n "${VIRTUAL_ENV:-}" ]; then
  echo "[✓] Using active Python venv:"
  echo "    $VIRTUAL_ENV"
elif [ -d "$EXPECTED_VENV" ]; then
  echo "[*] Activating Python venv:"
  echo "    $EXPECTED_VENV"
  # shellcheck source=/dev/null
  source "$EXPECTED_VENV/bin/activate"
else
  echo "[!] No Python virtual environment found"
  echo "    Expected: $EXPECTED_VENV"
  echo "    Run ../setup.sh first"
  exit 1
fi

# ---------------------------------------
# Sanity check engine source
# ---------------------------------------
if [ ! -f "$ENGINE_SRC/CMakeLists.txt" ]; then
  echo "[!] CMakeLists.txt not found at:"
  echo "    $ENGINE_SRC/CMakeLists.txt"
  exit 1
fi

# ---------------------------------------
# Build Boost runner if needed
# ---------------------------------------
if [ ! -f "$ENGINE_BIN" ]; then
  echo "[*] Building Boost regex runner..."
  cmake -S "$ENGINE_SRC" -B "$ENGINE_BUILD"
  cmake --build "$ENGINE_BUILD"
else
  echo "[✓] Boost regex runner already built"
fi

# ---------------------------------------
# Run analyzer
# ---------------------------------------
cd "$PYTHON_DIR"
python3 analyzer.py "$@"