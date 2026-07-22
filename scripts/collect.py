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

GATEWAY = os.environ.get("UCL_GATEWAY", "")
USER = os.environ.get("UCL_USER", "")
DOMAIN = os.environ.get("UCL_DOMAIN", "")

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
SEASONS = ROOT / "data" / "seasons.json"

HANDLE_ADJECTIVES = ["Feral", "Nocturnal", "Caffeinated", "Unhinged", "Sleepless", "Rogue",
                     "Turbo", "Silent", "Greedy", "Cursed", "Radiant", "Spectral"]
HANDLE_NOUNS = ["Gremlin", "Goblin", "Wizard", "Kraken", "Badger", "Phantom", "Yak",
                "Otter", "Basilisk", "Moth", "Warlock", "Heron"]

def handle_for(user: str) -> str:
  names = json.loads(NAMES.read_text()) if NAMES.exists() else {}
  salt = names.setdefault("_salt", secrets.token_hex(16))
  mapping = names.setdefault("users", {})
  if user not in mapping:
    digest = hashlib.sha256((salt + user).encode()).digest()
    handle = (f"{HANDLE_ADJECTIVES[digest[0] % len(HANDLE_ADJECTIVES)]}"
              f"{HANDLE_NOUNS[digest[1] % len(HANDLE_NOUNS)]}")
    taken = set(mapping.values())
    suffix = 2
    base = handle
    while handle in taken:
      handle = f"{base}{suffix}"
      suffix += 1
    mapping[user] = handle
  NAMES.parent.mkdir(parents=True, exist_ok=True)
  NAMES.write_text(json.dumps(names, indent=1))
  return mapping[user]

MAX_GAP_SECONDS = 20 * 60
WEEK_SECONDS = 7 * 24 * 3600

PROBE = r"""
echo REACHED
echo "TIME|$(date +%s)"
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
  """Whatever the card reports, minus the vendor noise.

  This used to map any "3090" to "RTX 3090 Ti", which asserts a model rather than
  reading one — a plain 3090 would have been relabelled a Ti.
  """
  if "No devices" in name:
    return "no GPU"
  short = name.replace("NVIDIA GeForce ", "").replace(" SUPER", " S").strip()
  return short or "unknown"

def probe(host: str, tries: int = 2) -> dict:
  for _ in range(tries):
    out = ssh(host, PROBE)
    if "REACHED" in out:
      gpu, users, mem, util, clock = "unknown", [], 0, 0, 0
      for line in out.splitlines():
        if line.startswith("GPU|"):
          parts = [p.strip() for p in line[4:].split(",")]
          if parts:
            gpu = short_model(parts[0])
          if len(parts) >= 4:
            mem = int(parts[1].split()[0])
            util = int(parts[3].split()[0])
        elif line.startswith("TIME|"):
          clock = int(line[5:].strip() or 0)
        elif line.startswith("PROC|"):
          _, user, _ = (line.split("|") + ["", ""])[:3]
          users.append(user)
      return {"host": host, "state": "up", "gpu": gpu,
              "users": sorted(set(users)), "mem": mem, "util": util, "clock": clock}
  return {"host": host, "state": "unreachable", "gpu": "unknown", "users": [], "mem": 0, "util": 0, "clock": 0}

def cluster_time(hosts: list[dict]) -> int:
  """Median clock across reachable machines, falling back to the local one.

  The collector runs on whatever laptop is awake, and a laptop whose clock has
  drifted would stamp the whole history wrong. The lab machines are NTP-synced.
  """
  clocks = sorted(h["clock"] for h in hosts if h.get("clock"))
  return clocks[len(clocks) // 2] if clocks else int(time.time())

def sample() -> dict:
  with futures.ThreadPoolExecutor(max_workers=14) as pool:
    hosts = list(pool.map(probe, HOSTS))
  t = cluster_time(hosts)
  for h in hosts:
    h.pop("clock", None)
  return {"t": t, "hosts": hosts}

def _events(recent: list[dict]) -> dict:
  free_since: dict[str, int] = {}        # host -> when it last became free
  holder_since: dict[tuple, int] = {}    # (host, user) -> when they took it
  draws: dict[str, list[float]] = defaultdict(list)      # user -> seconds-to-claim
  holds: dict[str, float] = defaultdict(float)           # user -> longest single hold (h)
  idle_util: dict[str, list[float]] = defaultdict(list)  # user -> util% while holding
  reboot_claims: dict[str, int] = defaultdict(int)       # user -> cards taken post-reboot
  gatecrash: dict[str, int] = defaultdict(int)           # user -> cards joined while occupied

  for previous, current in zip(recent, recent[1:]):
    if not (0 < current["t"] - previous["t"] <= MAX_GAP_SECONDS):
      free_since.clear(); holder_since.clear()
      continue
    before = {h["host"]: h for h in previous["hosts"]}
    when = current["t"]
    local = time.localtime(when)
    post_reboot = local.tm_wday in (0, 3, 1, 4) and (local.tm_hour < 9 or local.tm_hour >= 19)

    for host in current["hosts"]:
      name, users = host["host"], set(host["users"])
      was = before.get(name)
      if host["state"] != "up" or was is None:
        continue
      old_users = set(was["users"])

      if not old_users and not users:
        free_since.setdefault(name, when)
      if old_users and not users:            # released
        free_since[name] = when
      for user in users - old_users:         # claimed
        if old_users:                        # someone was already on it
          gatecrash[user] += 1
        if name in free_since:
          draws[user].append(max(0, when - free_since[name]))
        if post_reboot:
          reboot_claims[user] += 1
        holder_since[(name, user)] = when
        free_since.pop(name, None)
      for user in old_users - users:         # let go
        started = holder_since.pop((name, user), None)
        if started:
          holds[user] = max(holds[user], (when - started) / 3600.0)
      for user in users:                     # still holding
        idle_util[user].append(host["util"])
        started = holder_since.get((name, user))
        if started:
          holds[user] = max(holds[user], (when - started) / 3600.0)

  quickest = sorted(((u, min(v)) for u, v in draws.items() if v), key=lambda kv: kv[1])
  squatters = sorted(((u, sum(v) / len(v)) for u, v in idle_util.items() if len(v) >= 6),
                     key=lambda kv: kv[1])
  return {
    "quickest_draw": [{"user": u, "seconds": int(s)} for u, s in quickest[:5]],
    "longest_hold": [{"user": u, "hours": round(h, 1)}
                     for u, h in sorted(holds.items(), key=lambda kv: -kv[1])[:5]],
    "reboot_rush": [{"user": u, "claims": c}
                    for u, c in sorted(reboot_claims.items(), key=lambda kv: -kv[1])[:5]],
    "squatters": [{"user": u, "util": round(v, 1)} for u, v in squatters[:5]],
    "gatecrasher": [{"user": u, "count": c}
                    for u, c in sorted(gatecrash.items(), key=lambda kv: -kv[1])[:5]],
  }

def _gpu_hours(window: list[dict]) -> dict[str, float]:
  hours: dict[str, float] = defaultdict(float)
  for previous, current in zip(window, window[1:]):
    gap = current["t"] - previous["t"]
    if gap <= 0 or gap > MAX_GAP_SECONDS:
      continue
    for host in current["hosts"]:
      if host["state"] == "up":
        for user in host["users"]:
          hours[user] += gap / 3600.0
  return hours

def season_state(now: int, samples: list[dict]) -> dict:
  state = json.loads(SEASONS.read_text()) if SEASONS.exists() else {}
  anchor = state.setdefault("anchor", samples[0]["t"] if samples else now)
  past = state.setdefault("past", [])
  index = max(0, (now - anchor) // WEEK_SECONDS)

  while len(past) < index:
    start = anchor + len(past) * WEEK_SECONDS
    window = [s for s in samples if start <= s["t"] < start + WEEK_SECONDS]
    ranked = sorted(_gpu_hours(window).items(), key=lambda kv: -kv[1])
    champion = handle_for(ranked[0][0]) if ranked else None
    streak = 0
    if champion:
      streak = 1
      for previous in reversed(past):
        if previous.get("champion") != champion:
          break
        streak += 1
    past.append({"n": len(past) + 1, "start": start, "end": start + WEEK_SECONDS,
                 "champion": champion, "hours": round(ranked[0][1], 2) if ranked else 0.0,
                 "streak": streak})

  SEASONS.parent.mkdir(parents=True, exist_ok=True)
  SEASONS.write_text(json.dumps(state, indent=1))
  return {"anchor": anchor, "index": index, "past": past}

def build_board(samples: list[dict]) -> dict:
  now = samples[-1]["t"] if samples else int(time.time())
  season = season_state(now, samples)
  season_start = season["anchor"] + season["index"] * WEEK_SECONDS
  recent = [s for s in samples if s["t"] >= season_start]
  latest = samples[-1] if samples else {"t": now, "hosts": []}

  gpu_hours = _gpu_hours(recent)
  host_busy: dict[str, float] = defaultdict(float)
  host_total: dict[str, float] = defaultdict(float)
  host_model: dict[str, str] = {}
  peak = {"gpus": 0, "users": 0, "t": None}
  night_hours: dict[str, float] = defaultdict(float)

  for previous, current in zip(recent, recent[1:]):
    gap = current["t"] - previous["t"]
    if gap <= 0 or gap > MAX_GAP_SECONDS:
      continue                      # gap in coverage: credit nobody
    hours = gap / 3600.0
    hour_of_day = time.localtime(current["t"]).tm_hour
    live = 0
    live_people = set()
    for host in current["hosts"]:
      if host["state"] != "up":
        continue
      host_model[host["host"]] = host["gpu"]
      host_total[host["host"]] += hours
      if host["users"]:
        host_busy[host["host"]] += hours
        live += 1
      live_people.update(host["users"])
      for user in host["users"]:
        if hour_of_day >= 23 or hour_of_day < 6:
          night_hours[user] += hours
    if len(live_people) > peak["users"]:
      peak = {"gpus": live, "users": len(live_people), "t": current["t"]}

  hoard: dict[str, int] = defaultdict(int)
  hoard_when: dict[str, int] = {}
  for snap in recent:
    per_user: dict[str, int] = defaultdict(int)
    for host in snap["hosts"]:
      if host["state"] == "up":
        for u in host["users"]:
          per_user[u] += 1
    for u, n in per_user.items():
      if n > hoard[u]:
        hoard[u] = n
        hoard_when[u] = snap["t"]

  share_peak: dict[str, int] = defaultdict(int)
  share_who: dict[str, list[str]] = {}
  for snap in recent:
    for host in snap["hosts"]:
      if host["state"] == "up" and len(host["users"]) > share_peak[host["host"]]:
        share_peak[host["host"]] = len(host["users"])
        share_who[host["host"]] = list(host["users"])

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

  ev = _events(recent)
  ev["biggest_hoard"] = [{"user": u, "cards": n, "t": hoard_when.get(u)}
                         for u, n in sorted(hoard.items(), key=lambda kv: -kv[1])[:5]]
  for key in ("quickest_draw", "longest_hold", "reboot_rush", "squatters", "gatecrasher",
              "biggest_hoard"):
    for row in ev[key]:
      if key == "squatters":
        row["cards"] = len(live_users.get(row["user"], []))
      row["user"] = handle_for(row["user"])

  now_sharers = {h["host"]: h["users"] for h in latest["hosts"] if h.get("users")}
  contested = sorted(
    ({"host": host, "gpu": host_model.get(host, "unknown"), "peak": peak_n,
      "peak_users": [handle_for(u) for u in share_who.get(host, [])],
      "now": len(now_sharers.get(host, [])),
      "now_users": [handle_for(u) for u in now_sharers.get(host, [])]}
     for host, peak_n in share_peak.items() if peak_n > 0),
    key=lambda r: (-r["peak"], -r["now"], r["host"]))

  return {
    "generated": now,
    "season": {"n": season["index"] + 1, "start": season_start,
               "ends": season_start + WEEK_SECONDS,
               "past": [dict(row) for row in season["past"][-6:]]},
    "trophies": ev,
    "contested": contested[:8],
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
