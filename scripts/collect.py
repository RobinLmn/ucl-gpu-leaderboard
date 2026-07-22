"""Sample GPU usage across the UCL CS teaching labs and append it to a history file.

The lab machines are only reachable through the SSH gateway, so a public page cannot poll
them. This runs wherever there is SSH access, appends one snapshot per invocation to
``data/history.jsonl``, and rebuilds ``data/board.json`` — the single file the site reads.

Read-only: it runs ``nvidia-smi`` and ``ps``, and never starts, stops or touches a job.

  python scripts/collect.py            # take one sample
  python scripts/collect.py --loop 300 # keep sampling every 5 minutes
"""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import hashlib
import json
import os
import secrets
import subprocess
import time
from collections import defaultdict
from pathlib import Path

# Read from the environment so no username or hostname is ever committed. Set these in a
# local .env (gitignored):  UCL_GATEWAY=user@gateway.example.ac.uk  UCL_USER=user
GATEWAY = os.environ.get("UCL_GATEWAY", "")
USER = os.environ.get("UCL_USER", "")
DOMAIN = os.environ.get("UCL_DOMAIN", "")

# lab105 machines are named after duck breeds, lab121 after fish. barbury-l is a 3090 Ti
# that is not listed on the TSG page at all.
LAB105 = ["aylesbury-l", "barnacle-l", "brent-l", "bufflehead-l", "cackling-l", "canada-l",
          "crested-l", "eider-l", "gadwall-l", "goosander-l", "gressingham-l", "harlequin-l",
          "mallard-l", "mandarin-l", "pintail-l", "pocher-l", "ruddy-l", "scaup-l",
          "scoter-l", "shelduck-l", "shoveler-l", "smew-l", "wigeon-l"]
LAB121 = ["albacore-l", "barbel-l", "chub-l", "cripps-l", "dory-l", "elver-l", "flounder-l",
          "goldeye-l", "hake-l", "inanga-l", "javelin-l", "koi-l", "lamprey-l", "mackerel-l",
          "mullet-l", "nase-l", "opah-l", "pike-l", "plaice-l", "quillback-l", "roach-l",
          "rudd-l", "shark-l", "skate-l", "tench-l", "tope-l", "uaru-l", "vimba-l",
          "whitebait-l", "yellowtail-l", "zander-l"]
UNLISTED = ["barbury-l"]
HOSTS = LAB105 + LAB121 + UNLISTED

ROOT = Path(__file__).resolve().parent.parent
HISTORY = ROOT / "data" / "history.jsonl"
BOARD = ROOT / "data" / "board.json"
NAMES = ROOT / "data" / "names.local.json"

# Real usernames identify real people, and the board is published on the open web. Every
# name is replaced by a stable handle derived from a locally generated salt, so the ranking
# still works but nothing outside this machine can recover who anyone is. The salt and the
# mapping live only in gitignored files.
HANDLE_ADJECTIVES = ["Feral", "Nocturnal", "Caffeinated", "Unhinged", "Sleepless", "Rogue",
                     "Turbo", "Silent", "Greedy", "Cursed", "Radiant", "Spectral"]
HANDLE_NOUNS = ["Gremlin", "Goblin", "Wizard", "Kraken", "Badger", "Phantom", "Yak",
                "Otter", "Basilisk", "Moth", "Warlock", "Heron"]


def handle_for(user: str) -> str:
  """Stable, salted pseudonym. Not reversible without the local salt file."""
  names = json.loads(NAMES.read_text()) if NAMES.exists() else {}
  salt = names.setdefault("_salt", secrets.token_hex(16))
  mapping = names.setdefault("users", {})
  if user not in mapping:
    digest = hashlib.sha256((salt + user).encode()).digest()
    handle = (f"{HANDLE_ADJECTIVES[digest[0] % len(HANDLE_ADJECTIVES)]} "
              f"{HANDLE_NOUNS[digest[1] % len(HANDLE_NOUNS)]}")
    taken = set(mapping.values())
    suffix = 2
    base = handle
    while handle in taken:
      handle = f"{base} {suffix}"
      suffix += 1
    mapping[user] = handle
  NAMES.parent.mkdir(parents=True, exist_ok=True)
  NAMES.write_text(json.dumps(names, indent=1))
  return mapping[user]

# A sample older than this is ignored when accumulating GPU-hours, so a laptop that was
# asleep for six hours does not credit anyone with six hours of imaginary compute.
MAX_GAP_SECONDS = 20 * 60
WEEK_SECONDS = 7 * 24 * 3600

PROBE = r"""
echo REACHED
nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu --format=csv,noheader 2>/dev/null | head -1 | sed 's/^/GPU|/'
nvidia-smi --query-compute-apps=pid,used_memory --format=csv,noheader 2>/dev/null | while IFS=, read -r pid mem; do
  pid=$(echo $pid | tr -d ' ')
  u=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
  [ -n "$u" ] && echo "PROC|$u|$(echo $mem | tr -d ' ')"
done
"""


def ssh(host: str, script: str, timeout: int = 45) -> str:
  cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
         "-o", "StrictHostKeyChecking=no", "-o", f"ProxyJump={GATEWAY}",
         "-l", USER, f"{host}.{DOMAIN}", "bash -s"]
  try:
    return subprocess.run(cmd, input=script, capture_output=True, text=True,
                          timeout=timeout).stdout
  except (subprocess.TimeoutExpired, OSError):
    return ""


def short_model(name: str) -> str:
  if "3090" in name: return "RTX 3090 Ti"
  if "4070" in name: return "RTX 4070 Ti S"
  return name.replace("NVIDIA GeForce ", "").strip() or "unknown"


def probe(host: str, tries: int = 2) -> dict:
  """Sample one host. An unreachable host is recorded as such, never as idle."""
  for _ in range(tries):
    out = ssh(host, PROBE)
    if "REACHED" in out:
      gpu, users, mem, util = "unknown", [], 0, 0
      for line in out.splitlines():
        if line.startswith("GPU|"):
          parts = [p.strip() for p in line[4:].split(",")]
          if parts:
            gpu = short_model(parts[0])
          if len(parts) >= 4:
            mem = int(parts[1].split()[0])
            util = int(parts[3].split()[0])
        elif line.startswith("PROC|"):
          _, user, _ = (line.split("|") + ["", ""])[:3]
          users.append(user)
      return {"host": host, "state": "up", "gpu": gpu,
              "users": sorted(set(users)), "mem": mem, "util": util}
  return {"host": host, "state": "unreachable", "gpu": "unknown", "users": [], "mem": 0, "util": 0}


def sample() -> dict:
  with futures.ThreadPoolExecutor(max_workers=14) as pool:
    hosts = list(pool.map(probe, HOSTS))
  return {"t": int(time.time()), "hosts": hosts}


def build_board(samples: list[dict]) -> dict:
  """Turn the raw history into everything the page needs."""
  now = int(time.time())
  recent = [s for s in samples if now - s["t"] <= WEEK_SECONDS]
  latest = samples[-1] if samples else {"t": now, "hosts": []}

  gpu_hours: dict[str, float] = defaultdict(float)
  host_busy: dict[str, float] = defaultdict(float)
  host_total: dict[str, float] = defaultdict(float)
  host_model: dict[str, str] = {}
  peak = {"users": 0, "t": None}
  night_hours: dict[str, float] = defaultdict(float)

  for previous, current in zip(recent, recent[1:]):
    gap = current["t"] - previous["t"]
    if gap <= 0 or gap > MAX_GAP_SECONDS:
      continue                      # gap in coverage: credit nobody
    hours = gap / 3600.0
    hour_of_day = time.localtime(current["t"]).tm_hour
    live = 0
    for host in current["hosts"]:
      if host["state"] != "up":
        continue
      host_model[host["host"]] = host["gpu"]
      host_total[host["host"]] += hours
      if host["users"]:
        host_busy[host["host"]] += hours
        live += 1
      for user in host["users"]:
        gpu_hours[user] += hours
        if hour_of_day >= 23 or hour_of_day < 6:
          night_hours[user] += hours
    if live > peak["users"]:
      peak = {"users": live, "t": current["t"]}

  live_users: dict[str, list[str]] = defaultdict(list)
  free, busy, unreachable = [], [], []
  for host in latest["hosts"]:
    if host["state"] != "up":
      unreachable.append(host["host"])
    elif host["users"]:
      busy.append(host)
      for user in host["users"]:
        live_users[user].append(host["host"])
    else:
      free.append(host)

  leaderboard = [
    {"user": handle_for(user), "hours": round(hours, 2),
     "live": len(live_users.get(user, [])),
     "night": round(night_hours.get(user, 0.0), 2)}
    for user, hours in sorted(gpu_hours.items(), key=lambda kv: -kv[1])
  ]
  utilisation = [
    {"host": host, "gpu": host_model.get(host, "unknown"),
     "busy_pct": round(100 * host_busy.get(host, 0.0) / total, 1), "hours": round(total, 1)}
    for host, total in sorted(host_total.items()) if total > 0
  ]
  utilisation.sort(key=lambda r: -r["busy_pct"])

  return {
    "generated": now,
    "window_hours": round((recent[-1]["t"] - recent[0]["t"]) / 3600.0, 2) if len(recent) > 1 else 0.0,
    "samples": len(recent),
    "leaderboard": leaderboard,
    "live": {
      "free": [{"host": h["host"], "gpu": h["gpu"]} for h in free],
      "busy": [{"host": h["host"], "gpu": h["gpu"],
                "users": [handle_for(u) for u in h["users"]],
                "mem": h["mem"], "util": h["util"]} for h in busy],
      "unreachable": unreachable,
    },
    "hosts": utilisation,
    "peak": peak,
  }


def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--loop", type=int, default=0, help="seconds between samples (0 = once)")
  args = parser.parse_args()

  if not (GATEWAY and USER and DOMAIN):
    raise SystemExit("set UCL_GATEWAY, UCL_USER and UCL_DOMAIN (see .env.example); "
                     "they are intentionally not baked into this file")

  HISTORY.parent.mkdir(parents=True, exist_ok=True)
  while True:
    snap = sample()
    up = sum(1 for h in snap["hosts"] if h["state"] == "up")
    with HISTORY.open("a") as f:
      f.write(json.dumps(snap) + "\n")

    samples = [json.loads(l) for l in HISTORY.read_text().splitlines() if l.strip()]
    board = build_board(samples)
    BOARD.write_text(json.dumps(board, indent=1))
    print(f"[collect] {time.strftime('%H:%M:%S')} up={up}/{len(HOSTS)} "
          f"busy={len(board['live']['busy'])} free={len(board['live']['free'])} "
          f"samples={board['samples']}", flush=True)

    if not args.loop:
      return
    time.sleep(args.loop)


if __name__ == "__main__":
  main()
