# HieraStream

[English](README.md) | [中文](README.zh-CN.md)

原型与评测代码：

> **HieraStream: Secure Cloud Sharing of Longitudinal Healthcare Data with Dynamic Hierarchical Authorization**

HieraStream 面向纵向医疗数据的层次化、授权一致加密共享，通过双层密码学与账本侧授权状态支持动态授权更新。

## 仓库结构

```text
core/            密码学、授权、协议、PeerMVCC/Fabric 客户端、存储
data/            数据集适配器
experiments/     实验入口、配置与基线适配
results/         论文图、画图数据与表格
scripts/         环境安装与出图脚本
tests/           单元与集成测试
run.py           命令行入口
```

## 环境要求

- Python 3.10+
- Go 1.21+（账本单元测试）
- 可选：CMake、GMP、PBC、OpenSSL（原生密码学）

```bash
brew install cmake gmp pbc openssl@3 go pkg-config   # macOS
```

## 安装

```bash
git clone https://github.com/HaotianChi/HieraStream-artifact.git
cd HieraStream-artifact
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

可选原生密码学：`bash scripts/setup/bootstrap.sh && make build`

## 快速开始

```bash
export HIERASTREAM_CRYPTO_BACKEND=algebraic
python run.py demo
python run.py test
make fabric-test
```

## 论文图

```text
results/figures/
results/data/
results/tables/
```

```bash
python scripts/reproduce/generate_publication_figures.py
```

## 实验

```bash
python run.py experiment e1 --config experiments/configs/final/E1_crypto.yaml
```

评测配置位于 `experiments/configs/final/`。

## 数据集

原始语料不随仓库分发。请下载至 `data/datasets/<name>/raw/`
（见 `data/README.md`），或执行：

```bash
bash scripts/setup/download_datasets.sh
```
