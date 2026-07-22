#!/bin/bash
# Sample the lab, rebuild the board, and publish it.
#
# Runs wherever there is SSH access to the cluster. Uses the operator's existing SSH agent;
# no key material is read, copied or committed. Only data/board.json (pseudonymised) and the
# static page are pushed -- raw samples, the pseudonym mapping and .env stay local by way of
# .gitignore.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "missing .env (copy .env.example)"; exit 1; }
set -a; . ./.env; set +a

PYTHON="${LEADERBOARD_PYTHON:-python3}"
"$PYTHON" scripts/collect.py

# Publish only if the board actually changed, to avoid a commit every five minutes.
if git diff --quiet -- data/board.json 2>/dev/null; then
  echo "[publish] board unchanged; nothing to push"
  exit 0
fi

git add index.html data/board.json scripts/ .gitignore .env.example README.md 2>/dev/null || true
git commit -q -m "board: $(date -u '+%Y-%m-%d %H:%M UTC')" || true
git push -q origin HEAD 2>/dev/null && echo "[publish] pushed" || echo "[publish] push failed (no remote yet?)"
