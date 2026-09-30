#!/usr/bin/env bash
# ==============================================================================
# Automated Test Runner: Executes Full ZTNA Verification Suite
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "==================================================================="
echo "Zero Trust Network Access (ZTNA) - Automated Test Suite"
echo "==================================================================="

echo -e "\n[*] [1/3] Running Open Policy Agent (OPA) Rego Unit Tests..."
if command -v opa >/dev/null 2>&1; then
    opa test policies/ -v
else
    echo "[!] OPA CLI not installed locally. Executing via Docker..."
    docker run --rm -v "${ROOT_DIR}/policies:/policies" openpolicyagent/opa:latest test /policies -v
fi

echo -e "\n[*] [2/3] Checking Code Linting (flake8)..."
python -m flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics

echo -e "\n[*] [3/3] Running Python Pytest Suite (Integration + Unit)..."
python -m pytest tests/ -v

echo -e "\n==================================================================="
echo "[✓] All Zero Trust Test Suites Passed Successfully!"
echo "==================================================================="
