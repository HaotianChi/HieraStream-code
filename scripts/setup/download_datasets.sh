#!/usr/bin/env bash
# Download public evaluation corpora into data/datasets/*/raw/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
python - <<'PY'
from data.adapters.registry import prepare_dataset
for name in ["uci_heart_failure", "hf_remote_monitoring", "hm3_synthetic", "vitaldb"]:
    print("==>", name)
    prepare_dataset(name, smoke=False, download=True)
PY
