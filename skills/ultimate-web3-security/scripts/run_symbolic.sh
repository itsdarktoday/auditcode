#!/usr/bin/env bash
# Symbolic verification runner using Halmos
set -euo pipefail

TARGET_DIR="${1:-.}"
TEST_PATH="${2:-test/symbolic}"

if ! command -v halmos &> /dev/null; then
    echo "⚠️ Halmos not found in PATH. Install via: pip install halmos"
    exit 1
fi

echo "🔬 Running Halmos Symbolic Execution on ${TEST_PATH}..."
halmos --root "${TARGET_DIR}" --match-path "${TEST_PATH}/*.sol" -vvvv
