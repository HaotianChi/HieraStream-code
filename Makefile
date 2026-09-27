# HieraStream

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD_DIR ?= $(ROOT)/build
VENV ?= $(ROOT)/.venv
PYTHON ?= $(VENV)/bin/python
CMAKE ?= cmake
export PKG_CONFIG_PATH := /opt/homebrew/opt/openssl@3/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)

ifeq ($(shell uname -s),Darwin)
  PBC_ROOT ?= /opt/homebrew/opt/pbc
else
  PBC_ROOT ?= /usr/local
endif

.PHONY: help build test venv chaincode-build fabric-test integration-test clean configure

help:
	@echo "HieraStream targets:"
	@echo "  make build             - C++17 crypto (PBC/GMP/OpenSSL) + pybind11"
	@echo "  make test              - pytest + Go chaincode / peerval tests"
	@echo "  make fabric-test       - peer MVCC + chaincode unit tests"
	@echo "  make integration-test  - demo + unit suite"
	@echo "  make chaincode-build   - build Go chaincode stub"
	@echo "  make clean             - remove build artifacts"

venv:
	@test -x $(PYTHON) || python3 -m venv $(VENV)
	$(PYTHON) -m pip install -q -r "$(ROOT)/requirements.txt"

configure: venv
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && $(CMAKE) $(ROOT) \
	  -DCMAKE_BUILD_TYPE=Release \
	  -DHIERASTREAM_BUILD_TESTS=ON \
	  -DHIERASTREAM_BUILD_PYTHON=ON \
	  -DPython3_EXECUTABLE=$(PYTHON) \
	  -DPBC_ROOT=$(PBC_ROOT)

build: configure
	$(CMAKE) --build $(BUILD_DIR) -j
	@mkdir -p $(ROOT)/core/crypto/bindings
	@mod=$$(ls $(BUILD_DIR)/core/crypto/hierastream_native*.so $(BUILD_DIR)/core/crypto/hierastream_native*.dylib 2>/dev/null | head -1); \
	  if [ -n "$$mod" ]; then cp "$$mod" $(ROOT)/core/crypto/bindings/; echo "installed $$mod"; \
	  else echo "WARNING: hierastream_native module not produced"; fi

# Default CI-oriented suite (algebraic crypto; no native PBC build required).
test: venv
	HIERASTREAM_CRYPTO_BACKEND=$${HIERASTREAM_CRYPTO_BACKEND:-algebraic} \
	  $(PYTHON) -m pytest $(ROOT)/tests/unit $(ROOT)/tests/crypto $(ROOT)/tests/authorization \
	  $(ROOT)/tests/fabric $(ROOT)/tests/e2e -q

fabric-test:
	cd $(ROOT)/core/blockchain/peerval && go test ./...
	cd $(ROOT)/core/blockchain/chaincode/hierastream && go test ./...
	HIERASTREAM_CRYPTO_BACKEND=$${HIERASTREAM_CRYPTO_BACKEND:-algebraic} \
	  $(PYTHON) -m pytest $(ROOT)/tests/fabric -q

chaincode-build:
	@mkdir -p $(BUILD_DIR)
	cd $(ROOT)/core/blockchain/chaincode/hierastream && go test ./...
	cd $(ROOT)/core/blockchain/chaincode/hierastream && go build -o $(BUILD_DIR)/hierastream_chaincode_stub .
	cd $(ROOT)/core/blockchain/peerval && go test ./...

integration-test: build
	$(PYTHON) $(ROOT)/run.py demo
	$(PYTHON) $(ROOT)/run.py test

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(ROOT)/core/crypto/bindings/hierastream_native*.so \
	      $(ROOT)/core/crypto/bindings/hierastream_native*.dylib
