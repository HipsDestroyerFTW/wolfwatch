#!/usr/bin/env bash
# Quick local dev launcher — no Docker required
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Create .env if not present
if [ ! -f .env ]; then
  cp .env.example .env
  echo "[!] .env created from .env.example — edit it and add your ANTHROPIC_API_KEY"
fi

# Use venv if available, otherwise install with --user
if [ ! -d .venv ] && python3 -m venv --help &>/dev/null; then
  echo "[*] Creating virtual environment..."
  python3 -m venv .venv
fi

if [ -d .venv ]; then
  source .venv/bin/activate
  echo "[*] Installing/updating dependencies (venv)..."
  pip install -q -r requirements.txt
else
  echo "[*] Installing/updating dependencies (user)..."
  pip install -q --user -r requirements.txt
fi

# Kill any existing instance on port 8000
fuser -k 8000/tcp 2>/dev/null || true
sleep 1

echo "[*] Starting Wolf Industries DarkWeb Monitor on http://localhost:8000"
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
