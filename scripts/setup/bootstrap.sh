#!/usr/bin/env bash
# Create a local Python virtualenv and install Python dependencies.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
echo "HieraStream setup (ROOT=$ROOT)"

need() { command -v "$1" >/dev/null 2>&1 || echo "MISSING: $1"; }

need cmake
need g++
need go
need pkg-config
need python3

if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "macOS: brew install cmake gmp pbc openssl@3 go pkg-config"
  test -d /opt/homebrew/opt/pbc && echo "PBC: ok" || echo "PBC: install via brew install pbc"
else
  echo "Linux: install cmake, g++, golang, pkg-config, libgmp-dev, libssl-dev, and PBC"
fi

python3 -m venv "$ROOT/.venv" 2>/dev/null || true
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"
pip install -q -r "$ROOT/requirements.txt"
echo "Python venv ready."
echo "Next: make build && make test"
