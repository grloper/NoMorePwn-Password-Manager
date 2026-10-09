#!/usr/bin/env bash
# Single source of truth for 'is this change OK'. Exit code is the truth.
# Mirrors the lint + unit + extension steps of .github/workflows/test.yml.
# NOT checked here: tests/browser_capture_e2e.py and tests/native_capture_e2e.py (need Playwright
# Chromium + Qt runtime; still run by test.yml), Windows-only behaviour (test.yml's Windows matrix),
# the PyInstaller/Inno Setup release build, the real GUI, and anything touching a real vault.
# Requires: python with requirements-test.txt + ruff installed, node/npm.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PY="${PYTHON:-python}"

# Never touch a developer's real vault (config reads NOMOREPWN_DATA once, at import).
NOMOREPWN_DATA="$(mktemp -d)"
export NOMOREPWN_DATA
export QT_QPA_PLATFORM=offscreen PYTHONIOENCODING=utf-8
trap 'rm -rf "$NOMOREPWN_DATA"' EXIT

"$PY" -m ruff check .
"$PY" -m unittest discover -s tests -v

( cd extension && npm ci --ignore-scripts && npm test )
"$PY" extension/build.py
git diff --exit-code -- extension/dist   # committed extension/dist must match its sources
echo "verify: ALL CHECKS PASSED"
