#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "missing .env"; exit 1; }
set -a; . ./.env; set +a

PYTHON="${LEADERBOARD_PYTHON:-python3}"
"$PYTHON" scripts/collect.py

if git diff --quiet -- data/board.json 2>/dev/null; then
  echo "[publish] board unchanged; nothing to push"
  exit 0
fi

git add index.html data/board.json data/seasons.json scripts/ .gitignore 2>/dev/null || true
[ -f data/vault.json ] && git add data/vault.json 2>/dev/null || true
git commit -q -m "board: $(date -u '+%Y-%m-%d %H:%M UTC')" || true
git push -q origin HEAD 2>/dev/null && echo "[publish] pushed" || echo "[publish] push failed (no remote yet?)"
