# Targets named in the README: setup, demo, test. Plus lint and clean.
PYTHON ?= python3
VENV   ?= .venv
BIN    := $(VENV)/bin

.PHONY: setup demo test lint clean

setup:  ## venv + pyspark, cryptography, pyyaml (+ dev tools)
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

demo:  ## synthetic customers -> examples/policy.yaml -> before/after
	$(BIN)/pii-toolkit demo --policy examples/policy.yaml --workdir out/demo

test:
	$(BIN)/pytest

lint:
	$(BIN)/ruff check .

clean:
	rm -rf out spark-warehouse .pytest_cache .ruff_cache
