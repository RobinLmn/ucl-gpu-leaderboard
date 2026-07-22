# UCL GPU Leaderboard

A joke-but-useful leaderboard for the UCL CS teaching-lab GPUs: who is using what right
now, who has burned the most GPU-hours, which cards are contested and which are lonely.

**Live board:** see the GitHub Pages link for this repo.

## How it works

The lab machines sit behind an SSH gateway and are not reachable from the internet, so the
page cannot poll them. Instead a collector runs somewhere that *does* have access:

```
your machine (SSH key)  ──ssh──▶  gateway ──▶ lab machines      read-only nvidia-smi
        │
        └── writes data/board.json ──git push──▶ GitHub Pages (static)
```

The site only ever reads `data/board.json` from its own origin.

## Privacy

- **Usernames are never published.** Each is replaced by a stable handle derived from a
  locally generated salt (`Turbo Phantom`, `Nocturnal Basilisk`, …). The salt and the
  mapping live in `data/names.local.json`, which is gitignored — without it the handles
  cannot be inverted.
- **No credentials in the repo.** The gateway, username and domain come from a local
  `.env` (gitignored); `.env.example` shows the shape. No SSH key is ever read or copied.
- **Raw samples stay local.** `data/history.jsonl` holds real usernames and is gitignored.

## Running it

```bash
cp .env.example .env          # fill in gateway / user / domain
python3 scripts/collect.py    # one sample
./scripts/publish.sh          # sample + rebuild + push
```

To keep it live, run `scripts/publish.sh` on a timer (launchd on macOS, cron elsewhere).
GPU-hours accumulate only across samples less than 20 minutes apart, so a laptop that was
asleep does not credit anyone with imaginary compute.

## Method notes

- Sampling is read-only: `nvidia-smi` and `ps`. No job is started, stopped or modified.
- An unreachable machine is recorded as **unknown**, never as free. Counts are therefore
  lower bounds — conflating "no answer" with "idle" is the easiest way to get this wrong.
