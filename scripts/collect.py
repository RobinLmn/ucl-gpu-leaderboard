from __future__ import annotations

import argparse
import base64
import concurrent.futures as futures
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import time
from collections import defaultdict
from pathlib import Path

GATEWAY = os.environ.get("UCL_GATEWAY", "")
USER = os.environ.get("UCL_USER", "")
DOMAIN = os.environ.get("UCL_DOMAIN", "")
UNLOCK_KEY = os.environ.get("UCL_UNLOCK_KEY", "")

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
VAULT = ROOT / "data" / "vault.json"

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

def known_users() -> dict:
  """Every raw username we have ever minted a handle for."""
  names = json.loads(NAMES.read_text()) if NAMES.exists() else {}
  return names.get("users", {})

def scrub(text: str) -> str:
  """Swap any username appearing in free text for its handle.

  Longest first, so a name that contains another name is not half-replaced.
  """
  for raw, handle in sorted(known_users().items(), key=lambda kv: -len(kv[0])):
    text = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(raw)}(?![A-Za-z0-9_])",
                  f"⟨{handle}⟩", text)
  return text

PBKDF2_ROUNDS = 600_000

def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
  out = bytearray()
  counter = 0
  while len(out) < length:
    out += hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
    counter += 1
  return bytes(out[:length])

def vault_salt() -> bytes:
  """Stable per-install, so a reader's browser can cache the stretched key.

  It lives beside the handle salt in the file git never sees. Keeping it fixed
  is safe because the nonce is fresh on every seal, which is what actually has
  to be unique.
  """
  names = json.loads(NAMES.read_text()) if NAMES.exists() else {}
  salt = names.setdefault("_vault_salt", secrets.token_hex(16))
  NAMES.parent.mkdir(parents=True, exist_ok=True)
  NAMES.write_text(json.dumps(names, indent=1))
  return bytes.fromhex(salt)

def seal(plaintext: bytes, passphrase: str) -> dict:
  """Encrypt-then-MAC with keys stretched from the passphrase.

  Only PBKDF2 and HMAC-SHA256, because both stdlib Python and WebCrypto have
  them and nothing else needs installing on either side. The published blob is
  world-readable, so the stretching is what stands between a passer-by and the
  names: pick a passphrase that survives an offline guessing run.
  """
  salt, nonce = vault_salt(), secrets.token_bytes(16)
  material = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt,
                                 PBKDF2_ROUNDS, dklen=64)
  cipher_key, mac_key = material[:32], material[32:]
  ciphertext = bytes(a ^ b for a, b in
                     zip(plaintext, _keystream(cipher_key, nonce, len(plaintext))))
  b64 = lambda raw: base64.b64encode(raw).decode()
  return {"v": 1, "kdf": "pbkdf2-sha256", "rounds": PBKDF2_ROUNDS,
          "salt": b64(salt), "nonce": b64(nonce), "ct": b64(ciphertext),
          "tag": b64(hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest())}

MAX_GAP_SECONDS = 20 * 60
GATECRASH_UTIL = 15
LEAK_MB = 500
BUCKET_SECONDS = 15 * 60
FAMILIES = {"3090": "rtx3090", "4070": "rtx4070"}
WEEK_SECONDS = 7 * 24 * 3600

GPU_FIELDS = ["name", "memory.used", "memory.total", "utilization.gpu",
              "driver_version", "utilization.memory", "temperature.gpu",
              "power.draw", "power.limit", "fan.speed", "clocks.sm",
              "clocks.max.sm", "persistence_mode", "compute_mode"]
# Everything after the first four is presentation only; the first four keep the
# positions the sampler has always parsed.
SMI_KEYS = ["driver", "util_mem", "temp", "power", "power_limit", "fan",
            "clock_sm", "clock_max", "persistence", "compute_mode"]

PROBE = r"""
echo REACHED
echo "TIME|$(date +%s)"
nvidia-smi --query-gpu=__FIELDS__ --format=csv,noheader 2>/dev/null | head -1 | sed 's/^/GPU|/'
nvidia-smi --query-compute-apps=pid,used_memory,process_name --format=csv,noheader 2>/dev/null | while IFS=, read -r pid mem name; do
  pid=$(echo $pid | tr -d ' ')
  u=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
  [ -n "$u" ] || continue
  et=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
  cpu=$(ps -o pcpu= -p "$pid" 2>/dev/null | tr -d ' ')
  rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
  args=$(ps -o args= -p "$pid" 2>/dev/null | tr '\n|' '  ')
  echo "PROC|$u|$(echo $mem | tr -d ' ')|$pid|$(echo $name | sed 's/^ *//')|$et|$cpu|$rss|$args"
done
ps -eo uid=,user=,pcpu= 2>/dev/null | awk '$1 >= 1000 {cpu[$2] += $3}
  END {for (u in cpu) if (cpu[u] >= 80) printf "CPU|%s|%.0f\n", u, cpu[u]}'
""".replace("__FIELDS__", ",".join(GPU_FIELDS))

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

def _int(text: str) -> int:
  digits = re.match(r"\s*(\d+)", text or "")
  return int(digits.group(1)) if digits else 0

def probe(host: str, tries: int = 2) -> dict:
  for _ in range(tries):
    out = ssh(host, PROBE)
    if "REACHED" in out:
      gpu, users, mem, mem_total, util, clock = "unknown", [], 0, 0, 0, 0
      smi, detail, cpu_only = {}, [], {}
      for line in out.splitlines():
        if line.startswith("GPU|"):
          parts = [p.strip() for p in line[4:].split(",")]
          if parts:
            gpu = short_model(parts[0])
          if len(parts) >= 4:
            mem = _int(parts[1])
            mem_total = _int(parts[2])
            util = _int(parts[3])
          smi = dict(zip(SMI_KEYS, parts[4:]))
        elif line.startswith("TIME|"):
          clock = int(line[5:].strip() or 0)
        elif line.startswith("PROC|"):
          fields = (line.split("|", 8) + [""] * 9)[:9]
          _, user, pmem, pid, name, etimes, cpu, rss, args = fields
          if not user:
            continue
          users.append(user)
          detail.append({"pid": _int(pid), "user": user, "mem": _int(pmem),
                         "name": name.strip(), "etimes": _int(etimes),
                         "cpu": cpu.strip(), "rss": _int(rss),
                         "cmd": args.strip()})
        elif line.startswith("CPU|"):
          # Real accounts only (uid >= 1000), and only once they are pegging
          # about a core: enough to tell a training run from a login shell.
          _, user, pct = (line.split("|") + ["", ""])[:3]
          if user:
            cpu_only[user] = _int(pct)
      return {"host": host, "state": "up", "gpu": gpu, "users": sorted(set(users)),
              "mem": mem, "mem_total": mem_total, "util": util,
              "procs": len(detail), "clock": clock, "smi": smi, "detail": detail,
              # Lifted out of smi so it survives into history, which the rest
              # of that dict does not: a season-long award needs every sample.
              "temp": _int(smi.get("temp", "")),
              "cpu": {u: p for u, p in cpu_only.items() if u not in set(users)}}
  return {"host": host, "state": "unreachable", "gpu": "unknown", "users": [],
          "mem": 0, "mem_total": 0, "util": 0, "procs": 0, "clock": 0,
          "smi": {}, "detail": [], "temp": 0, "cpu": {}}

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

TRANSIENT = ("smi", "detail")

def lean(snap: dict) -> dict:
  """The snapshot as history wants it: aggregates only.

  Per-process detail is worth showing for the live moment but would multiply
  the size of a file we re-read in full on every cycle, so it never lands there.
  """
  return {"t": snap["t"],
          "hosts": [{k: v for k, v in h.items() if k not in TRANSIENT}
                    for h in snap["hosts"]]}

def _in_reboot_window(when: int) -> bool:
  """The labs restart Monday and Thursday evenings, 19:30 to midnight.

  The claim itself may land in the small hours that follow, so the window runs
  on into Tuesday / Friday morning.
  """
  lt = time.localtime(when)
  if lt.tm_wday in (0, 3):
    return lt.tm_hour > 19 or (lt.tm_hour == 19 and lt.tm_min >= 30)
  if lt.tm_wday in (1, 4):
    return lt.tm_hour < 9
  return False

def _events(recent: list[dict]) -> dict:
  free_since: dict[str, int] = {}        # host -> when it last became free
  holder_since: dict[tuple, int] = {}    # (host, user) -> when they took it
  draws: dict[str, list[float]] = defaultdict(list)      # user -> seconds-to-claim
  holds: dict[str, float] = defaultdict(float)           # user -> longest single hold (h)
  idle_util: dict[str, list[float]] = defaultdict(list)  # user -> util% while holding
  reboot_claims: dict[str, int] = defaultdict(int)       # user -> first onto a machine that just came back
  came_back: set[str] = set()                            # freshly restarted, still unclaimed
  gatecrash: dict[str, int] = defaultdict(int)           # user -> cards joined while actually in use

  for previous, current in zip(recent, recent[1:]):
    if not (0 < current["t"] - previous["t"] <= MAX_GAP_SECONDS):
      free_since.clear(); holder_since.clear()
      continue
    before = {h["host"]: h for h in previous["hosts"]}
    when = current["t"]
    reboot_time = _in_reboot_window(when)

    for host in current["hosts"]:
      name, users = host["host"], set(host["users"])
      was = before.get(name)
      if host["state"] != "up" or was is None:
        continue
      if reboot_time and (was["state"] != "up" or (was["users"] and not users)):
        came_back.add(name)        # back from the restart, or wiped clean by it
      old_users = set(was["users"])

      if not old_users and not users:
        free_since.setdefault(name, when)
      if old_users and not users:            # released
        free_since[name] = when
      for user in users - old_users:         # claimed
        if old_users and was["util"] > GATECRASH_UTIL:   # busy, not just parked
          gatecrash[user] += 1
        if name in free_since:
          draws[user].append(max(0, when - free_since[name]))
        if reboot_time and name in came_back:
          reboot_claims[user] += 1
          came_back.discard(name)
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

def _series(window: list[dict]) -> list[dict]:
  """Cluster load per 15-minute bucket, split by card family."""
  buckets: dict[int, dict] = {}
  for snap in window:
    slot = snap["t"] - snap["t"] % BUCKET_SECONDS
    bucket = buckets.setdefault(slot, {})
    for family in FAMILIES.values():
      bucket.setdefault(family, [])
    totals = {family: {"util": 0, "mem": 0.0, "busy": 0, "procs": 0, "up": 0}
              for family in FAMILIES.values()}
    for host in snap["hosts"]:
      if host["state"] != "up":
        continue
      family = next((v for k, v in FAMILIES.items() if k in host["gpu"]), None)
      if family is None:
        continue
      row = totals[family]
      row["up"] += 1
      row["util"] += host["util"]
      row["mem"] += host["mem"] / 1024.0
      row["procs"] += host.get("procs", len(host["users"]))
      if host["users"]:
        row["busy"] += 1
    for family, row in totals.items():
      if row["up"]:
        bucket[family].append(row)

  points = []
  for slot in sorted(buckets):
    point = {"t": slot}
    for family, rows in buckets[slot].items():
      if not rows:
        continue
      n = len(rows)
      point[family] = {
        "util": round(sum(r["util"] / r["up"] for r in rows) / n, 1),
        "mem": round(sum(r["mem"] for r in rows) / n, 1),
        "busy": round(sum(r["busy"] for r in rows) / n, 1),
        "procs": round(sum(r["procs"] for r in rows) / n, 1),
      }
    points.append(point)
  return points

def build_board(samples: list[dict], live_snap: dict = None) -> dict:
  now = samples[-1]["t"] if samples else int(time.time())
  season = season_state(now, samples)
  season_start = season["anchor"] + season["index"] * WEEK_SECONDS
  recent = [s for s in samples if s["t"] >= season_start]
  latest = live_snap or (samples[-1] if samples else {"t": now, "hosts": []})

  gpu_hours = _gpu_hours(recent)
  host_busy: dict[str, float] = defaultdict(float)
  host_total: dict[str, float] = defaultdict(float)
  host_model: dict[str, str] = {}
  peak = {"gpus": 0, "users": 0, "t": None}
  night_hours: dict[str, float] = defaultdict(float)
  morning_hours: dict[str, float] = defaultdict(float)
  days_seen: dict[str, set] = defaultdict(set)   # user -> which days they turned up
  season_days: set = set()
  plough_hours: dict[str, float] = defaultdict(float)   # CPU burned, GPU untouched
  plough_peak: dict[str, int] = defaultdict(int)

  for previous, current in zip(recent, recent[1:]):
    gap = current["t"] - previous["t"]
    if gap <= 0 or gap > MAX_GAP_SECONDS:
      continue                      # gap in coverage: credit nobody
    hours = gap / 3600.0
    when = time.localtime(current["t"])
    hour_of_day = when.tm_hour
    day = time.strftime("%Y-%m-%d", when)
    season_days.add(day)
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
        days_seen[user].add(day)
        if hour_of_day >= 23 or hour_of_day < 6:
          night_hours[user] += hours
        if 6 <= hour_of_day < 9:
          morning_hours[user] += hours
      # Sat on a machine chosen for its GPU, working the CPU instead.
      if host["gpu"] not in ("unknown", "no GPU"):
        for user, pct in (host.get("cpu") or {}).items():
          if user in host["users"]:
            continue
          plough_hours[user] += hours
          plough_peak[user] = max(plough_peak[user], pct)
    if len(live_people) > peak["users"]:
      peak = {"gpus": live, "users": len(live_people), "t": current["t"]}

  restarts: dict[str, int] = defaultdict(int)
  seen_on: dict[str, set] = defaultdict(set)
  user_on_host: dict[tuple, float] = defaultdict(float)
  leak_hours: dict[str, float] = defaultdict(float)
  leak_mem: dict[str, int] = defaultdict(int)
  leak_blame: dict[str, dict] = defaultdict(lambda: defaultdict(float))
  last_holders: dict[str, list] = {}   # host -> who was on it when it last had anyone
  for previous, current in zip(recent, recent[1:]):
    gap = current["t"] - previous["t"]
    if gap <= 0 or gap > MAX_GAP_SECONDS:
      continue
    was = {h["host"]: h for h in previous["hosts"]}
    for host in current["hosts"]:
      if host["state"] != "up":
        continue
      before = was.get(host["host"])
      if before is None:
        continue
      if before["state"] != "up" or (before["users"] and not host["users"]):
        restarts[host["host"]] += 1
      if not host["users"] and host["mem"] >= LEAK_MB:
        leak_hours[host["host"]] += gap / 3600.0
        leak_mem[host["host"]] = max(leak_mem[host["host"]], host["mem"])
        # Nobody is running anything, so the memory belongs to whoever was here
        # last. Split the blame if they left together.
        blame = last_holders.get(host["host"], [])
        for user in blame:
          leak_blame[host["host"]][user] += gap / 3600.0 / len(blame)
      for user in host["users"]:
        seen_on[host["host"]].add(user)
        user_on_host[(host["host"], user)] += gap / 3600.0
      if host["users"]:
        last_holders[host["host"]] = list(host["users"])

  def _award(host, extra):
    return dict(extra, host=host, gpu=host_model.get(host, "unknown"))

  awards = {}
  if restarts:
    host, count = max(restarts.items(), key=lambda kv: (kv[1], kv[0]))
    if count:
      awards["unstable"] = _award(host, {"restarts": count})
  if leak_hours:
    host = max(leak_hours, key=lambda h: (leak_hours[h], leak_mem[h]))
    culprits = sorted(leak_blame.get(host, {}).items(), key=lambda kv: -kv[1])
    awards["forgotten"] = _award(host, {"mem": leak_mem[host],
                                        "hours": round(leak_hours[host], 1)})
    if culprits:
      awards["forgotten"]["user"] = handle_for(culprits[0][0])
      awards["forgotten"]["others"] = [handle_for(u) for u, _ in culprits[1:3]]
  # Heat and crowding, both read straight off the samples. Temperature only
  # entered history recently, so early samples simply do not vote.
  temps: dict[str, list[int]] = defaultdict(list)
  proc_peak: dict[str, int] = defaultdict(int)
  proc_when: dict[str, int] = {}
  for snap in recent:
    for host in snap["hosts"]:
      if host["state"] != "up":
        continue
      if host.get("temp"):
        temps[host["host"]].append(host["temp"])
      procs = host.get("procs")
      if procs and procs > proc_peak[host["host"]]:
        proc_peak[host["host"]] = procs
        proc_when[host["host"]] = snap["t"]

  hot = {h: sum(v) / len(v) for h, v in temps.items() if len(v) >= 4}
  if hot:
    host = max(hot, key=lambda h: (hot[h], max(temps[h])))
    awards["furnace"] = _award(host, {"temp": round(hot[host]),
                                      "peak": max(temps[host]),
                                      "samples": len(temps[host])})
  if proc_peak:
    host = max(proc_peak, key=lambda h: (proc_peak[h], host_busy.get(h, 0.0)))
    if proc_peak[host] > 1:
      awards["anthill"] = _award(host, {"procs": proc_peak[host],
                                        "t": proc_when.get(host)})

  occupancy = {h: host_busy.get(h, 0.0) / total for h, total in host_total.items() if total > 0}
  if occupancy:
    host = max(occupancy, key=lambda h: (occupancy[h], host_total[h]))
    if occupancy[host] > 0:
      awards["workhorse"] = _award(host, {"busy_pct": round(100 * occupancy[host]),
                                          "hours": round(host_busy.get(host, 0.0), 1)})
  visited = {h: len(u) for h, u in seen_on.items() if u}
  if visited:
    busy_h = lambda h: host_busy.get(h, 0.0)
    host = max(visited, key=lambda h: (visited[h], busy_h(h)))
    awards["crowded"] = _award(host, {"users": visited[host], "hours": round(busy_h(host), 1)})
    host = min(visited, key=lambda h: (visited[h], -busy_h(h)))
    awards["exclusive"] = _award(host, {"users": visited[host], "hours": round(busy_h(host), 1)})
  user_total: dict[str, float] = defaultdict(float)
  for (_, user), hours in user_on_host.items():
    user_total[user] += hours
  loyal = None
  for (host, user), hours in user_on_host.items():
    total = user_total[user]
    if total <= 0:
      continue
    share = hours / total
    if loyal is None or (share, hours) > (loyal["share"], loyal["hours"]):
      loyal = {"host": host, "user": user, "share": share, "hours": hours}
  if loyal:
    awards["loyal"] = _award(loyal["host"], {"user": handle_for(loyal["user"]),
                                             "share": round(100 * loyal["share"]),
                                             "hours": round(loyal["hours"], 1)})

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

  # When each person's current grip on each card began, without a break. Held
  # here rather than further down because the standings want it too.
  claimed_at: dict[tuple, int] = {}
  holding: dict[str, set] = {}
  for snap in recent:
    for host in snap["hosts"]:
      if host["state"] != "up":
        continue
      current_users = set(host["users"])
      for user in current_users - holding.get(host["host"], set()):
        claimed_at[(host["host"], user)] = snap["t"]
      holding[host["host"]] = current_users

  window_start = recent[0]["t"] if recent else now

  def sitting(user: str) -> dict:
    """Their longest unbroken grip on one card, as of right now.

    A hold that began before this window looks like it began when the window
    did, so the figure is a floor rather than a guess — said plainly, since
    the page shows a start time.
    """
    starts = [claimed_at.get((h, user)) for h in live_users.get(user, [])]
    starts = [s for s in starts if s]
    if not starts:
      return {}
    since = min(starts)
    return {"since": since, "floor": since <= window_start}

  leaderboard = [
    dict({"user": handle_for(user), "hours": round(hours, 2),
          "live": len(live_users.get(user, [])),
          "night": round(night_hours.get(user, 0.0), 2),
          "morning": round(morning_hours.get(user, 0.0), 2),
          "days": len(days_seen.get(user, ()))}, **sitting(user))
    for user, hours in sorted(gpu_hours.items(), key=lambda kv: -kv[1])
  ]
  utilisation = [
    {"host": host, "gpu": host_model.get(host, "unknown"),
     "busy_pct": round(100 * host_busy.get(host, 0.0) / total, 1), "hours": round(total, 1)}
    for host, total in sorted(host_total.items()) if total > 0
  ]
  utilisation.sort(key=lambda r: -r["busy_pct"])

  cards_used: dict[str, set] = defaultdict(set)
  for (host, user) in user_on_host:
    cards_used[user].add(host)

  ev = _events(recent)
  ev["biggest_hoard"] = [{"user": u, "cards": n, "t": hoard_when.get(u)}
                         for u, n in sorted(hoard.items(), key=lambda kv: -kv[1])[:5]]
  ev["playboy"] = [{"user": u, "cards": len(h)}
                   for u, h in sorted(cards_used.items(), key=lambda kv: -len(kv[1]))[:5]
                   if len(h) > 1]
  ev["ploughing"] = [{"user": u, "hours": round(h, 1), "cpu": plough_peak[u]}
                     for u, h in sorted(plough_hours.items(), key=lambda kv: -kv[1])[:5]]
  for key in ("quickest_draw", "longest_hold", "reboot_rush", "squatters", "gatecrasher",
              "biggest_hoard", "playboy", "ploughing"):
    for row in ev[key]:
      if key == "squatters":
        row["cards"] = len(live_users.get(row["user"], []))
      row["user"] = handle_for(row["user"])

  def arrivals(host: str, users: list[str]) -> list[dict]:
    ranked = sorted(users, key=lambda u: claimed_at.get((host, u), 0))
    first = claimed_at.get((host, ranked[0]), 0) if ranked else 0
    return [{"user": handle_for(u), "since": claimed_at.get((host, u)),
             "crasher": claimed_at.get((host, u), 0) > first}
            for u in ranked]

  now_sharers = {h["host"]: h["users"] for h in latest["hosts"] if h.get("users")}
  contested = sorted(
    ({"host": host, "gpu": host_model.get(host, "unknown"), "peak": peak_n,
      "peak_users": [handle_for(u) for u in share_who.get(host, [])],
      "now": len(now_sharers.get(host, [])),
      "now_users": arrivals(host, now_sharers.get(host, []))}
     for host, peak_n in share_peak.items() if peak_n > 0),
    key=lambda r: (-r["peak"], -r["now"], r["host"]))

  def live_host(h: dict) -> dict:
    """One card as the map shows it: stats in the clear, people behind handles."""
    return {"host": h["host"], "gpu": h["gpu"], "mem": h["mem"],
            "mem_total": h.get("mem_total", 0), "util": h["util"],
            "users": [handle_for(u) for u in h["users"]],
            "smi": h.get("smi", {}),
            "processes": [{"pid": p["pid"], "user": handle_for(p["user"]),
                           "mem": p["mem"], "etimes": p["etimes"], "cpu": p["cpu"],
                           "rss": p["rss"],
                           # Only the program, never the path or the arguments:
                           # a working directory or a dataset name says who you
                           # are just as loudly as a username does.
                           "name": scrub(os.path.basename(p.get("name", "")))}
                          for p in sorted(h.get("detail", []), key=lambda p: -p["mem"])]}

  return {
    "generated": now,
    "season": {"n": season["index"] + 1, "start": season_start,
               "ends": season_start + WEEK_SECONDS,
               "past": [dict(row) for row in season["past"][-6:]]},
    "trophies": ev,
    "contested": contested[:8],
    "gpu_awards": awards,
    "series": _series(recent),
    "season_days": len(season_days),
    "window_hours": round((recent[-1]["t"] - recent[0]["t"]) / 3600.0, 2) if len(recent) > 1 else 0.0,
    "samples": len(recent),
    "leaderboard": leaderboard,
    "live": {
      "free": [live_host(h) for h in free],
      "busy": [live_host(h) for h in busy],
      "unreachable": unreachable,
    },
    "hosts": utilisation,
    "peak": peak,
  }

def build_vault(latest: dict) -> dict:
  """The plaintext behind the handles, sealed with UCL_UNLOCK_KEY.

  Everything the board deliberately withholds lives here and nowhere else: the
  real usernames, and the full command lines the map only shows as a program
  name. The passphrase never leaves the collector machine and is never written
  into the payload — the browser re-derives the key from what the reader types.
  """
  procs = {}
  for host in latest["hosts"]:
    for p in host.get("detail", []):
      procs[f"{host['host']}|{p['pid']}"] = {"user": p["user"], "cmd": p["cmd"]}
  plaintext = json.dumps({"users": {h: raw for raw, h in known_users().items()},
                          "procs": procs}, separators=(",", ":")).encode()
  return seal(plaintext, UNLOCK_KEY)

def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--loop", type=int, default=0, help="seconds between samples (0 = once)")
  args = parser.parse_args()

  if not (GATEWAY and USER and DOMAIN):
    raise SystemExit("set UCL_GATEWAY, UCL_USER and UCL_DOMAIN (see .env.example); "
                     "they are intentionally not baked into this file")

  if UNLOCK_KEY and len(UNLOCK_KEY) < 16:
    raise SystemExit("UCL_UNLOCK_KEY is short enough to guess offline — the sealed "
                     "payload is published to a public repo. Use a long passphrase.")

  HISTORY.parent.mkdir(parents=True, exist_ok=True)
  while True:
    snap = sample()
    up = sum(1 for h in snap["hosts"] if h["state"] == "up")
    with HISTORY.open("a") as f:
      f.write(json.dumps(lean(snap)) + "\n")

    samples = [json.loads(l) for l in HISTORY.read_text().splitlines() if l.strip()]
    board = build_board(samples, live_snap=snap)
    board["vault"] = bool(UNLOCK_KEY)
    BOARD.write_text(json.dumps(board, indent=1))
    if UNLOCK_KEY:
      VAULT.write_text(json.dumps(build_vault(snap)))
    print(f"[collect] {time.strftime('%H:%M:%S')} up={up}/{len(HOSTS)} "
          f"busy={len(board['live']['busy'])} free={len(board['live']['free'])} "
          f"samples={board['samples']}", flush=True)

    if not args.loop:
      return
    time.sleep(args.loop)

if __name__ == "__main__":
  main()
