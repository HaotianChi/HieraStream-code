# HieraStream

[English](README.md) | [中文](README.zh-CN.md)

Prototype and evaluation artifact for:

> **HieraStream: Secure Cloud Sharing of Longitudinal Healthcare Data with Dynamic Hierarchical Authorization**

HieraStream provides hierarchical, authorization-consistent encrypted sharing of longitudinal healthcare data, with dynamic authorization updates enforced through dual-layer cryptography and ledger-backed authorization state.

## Repository layout

```text
core/            Cryptography, authorization, protocol, PeerMVCC/Fabric client, storage
data/            Dataset adapters
experiments/     Experiment runners, configs, and baseline adapters
results/         Publication figures, plot data, and tables
scripts/         Environment setup and figure generation
tests/           Unit and integration tests
run.py           Command-line entry point
```

## Requirements

- Python 3.10+
- Go 1.21+ (ledger unit tests)
- Optional: CMake, GMP, PBC, OpenSSL (native cryptography)

```bash
brew install cmake gmp pbc openssl@3 go pkg-config   # macOS
```

## Install

```bash
git clone https://github.com/HaotianChi/HieraStream-artifact.git
cd HieraStream-artifact
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional native cryptography: `bash scripts/setup/bootstrap.sh && make build`

## Quick start

```bash
export HIERASTREAM_CRYPTO_BACKEND=algebraic
python run.py demo
python run.py test
make fabric-test
```

## Publication figures

```text
results/figures/
results/data/
results/tables/
```

```bash
python scripts/reproduce/generate_publication_figures.py
```

## Experiments

```bash
python run.py experiment e1 --config experiments/configs/final/E1_crypto.yaml
```

Evaluation configs are under `experiments/configs/final/`.

## Datasets

Raw corpora are not redistributed. Place downloads under `data/datasets/<name>/raw/`
(see `data/README.md`), or run:

```bash
bash scripts/setup/download_datasets.sh
```
