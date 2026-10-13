#!/bin/bash
# Installs dapi and its dev tools (pytest, ruff) into .venv for Claude Code cloud sessions.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

if command -v uv >/dev/null 2>&1; then
  [ -d .venv ] || uv venv -q .venv
  uv pip install -q --python .venv/bin/python -e '.[dev]'
else
  [ -d .venv ] || python3 -m venv .venv
  .venv/bin/pip install -q -e '.[dev]'
fi

# TypeScript compiler for the generated-client tests (skipped by the tests if unavailable).
if ! command -v tsc >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  npm install -g --silent typescript@5.6.3 || true
fi

if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo "export PATH=\"$CLAUDE_PROJECT_DIR/.venv/bin:\$PATH\"" >> "$CLAUDE_ENV_FILE"
fi
