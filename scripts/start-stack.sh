#!/usr/bin/env bash
# Start VaultScan backend + frontend together
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Backend"
cd "$ROOT/backend"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python app.py &
BACK_PID=$!

cleanup() {
  kill "$BACK_PID" 2>/dev/null || true
}
trap cleanup EXIT

sleep 1
echo "==> Frontend (http://localhost:3000)  API (http://localhost:8000)"
cd "$ROOT/frontend"
if [[ ! -d node_modules ]]; then
  npm install
fi
# Prefer stable webpack path; clears broken Turbopack cache if present
if [[ -f .next/dev/build-manifest.json ]] || [[ -d .next/dev/cache/turbopack ]]; then
  echo "==> Clearing previous Turbopack/dev cache (.next)"
  rm -rf .next
fi
npm run dev
