#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

if [ ! -f .env ]; then
  echo "Creating .env from .env.example..."
  cp .env.example .env
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "Error: uv is required to set up this project." >&2
  echo "Install uv from https://docs.astral.sh/uv/ and rerun this script." >&2
  exit 1
fi

echo "Synchronizing environment from uv.lock..."
uv sync --all-groups --frozen

echo "Environment setup complete."
