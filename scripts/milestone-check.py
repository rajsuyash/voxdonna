#!/usr/bin/env python3
"""milestone-check.py — VoxDonna 90-day goal trajectory tracker.

Runs weekly (Mon 09:00 UTC) via Paperclip routine. Reads @voxdonna follower
count via X API v2, compares against the back-loaded exponential curve from
GROWTH_PLAN_90D.md, decides green/yellow/red, and Telegram-digests the result.

If red: creates a blocked Paperclip issue assigned to CEO (12b7fc5f-...) with
the trajectory delta and triage steps.

Day-0 baseline: 2026-05-12 (goal start), follower count taken when script first
runs (or read from voxdonna/data/baseline_followers.txt if it exists).

Goal deadline: 2026-08-10 (Day 90).

Env required (read from /home/suyashraj/.openclaw/.env):
- TWITTER_API_KEY, TWITTER_API_SECRET, TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_TOKEN_SECRET
- TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
- PGPASSWORD for Paperclip issue creation
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests_oauthlib import OAuth1

ROOT = Path("/home/suyashraj/clawd/voxdonna")
DATA = ROOT / "data"
BASELINE_FILE = DATA / "baseline_followers.txt"
GOAL_START = datetime(2026, 5, 12, tzinfo=timezone.utc)
GOAL_DEADLINE = datetime(2026, 8, 10, tzinfo=timezone.utc)
GOAL_TARGET = 1000
USERNAME = "voxdonna"

PAPERCLIP_DSN = ["env", "PGPASSWORD=paperclip", "psql", "-h", "127.0.0.1",
                 "-p", "54329", "-U", "paperclip", "-d", "paperclip", "-At"]
COMPANY_ID = "a54ed150-dc5b-40cc-83a3-2da628514997"
CEO_AGENT_ID = "12b7fc5f-9ae1-4b75-9c35-91c86c9cf436"
PROJECT_ID = "5a3623dd-8bb5-4ed4-be93-165fa9545186"  # SEO & Content

# Back-loaded exponential curve. (days_since_start, expected_min, red_line)
CURVE = [
    (7,   25,  20),   # Day 7: target 25-40, red <20
    (14,  80,  50),   # Day 14: target 80-120, red <50
    (30,  150, 120),  # Day 30: target 150-200, red <120
    (45,  300, 250),  # Day 45: midway
    (60,  500, 400),  # Day 60: target ~500, red <400
    (75,  750, 600),
    (90,  1000, 800), # Day 90: goal!, red <800
]


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for path in [Path("/home/suyashraj/.openclaw/.env"), Path("/home/suyashraj/clawd/.env")]:
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    # Pull Twitter creds from Paperclip DB if not in env (single source of truth)
    if not env.get("TWITTER_API_KEY"):
        result = subprocess.run(
            PAPERCLIP_DSN + ["-c",
                f"SELECT adapter_config->'env'->>'TWITTER_API_KEY' || '|' || "
                f"adapter_config->'env'->>'TWITTER_API_SECRET' || '|' || "
                f"adapter_config->'env'->>'TWITTER_ACCESS_TOKEN' || '|' || "
                f"adapter_config->'env'->>'TWITTER_ACCESS_TOKEN_SECRET' "
                f"FROM agents WHERE name='voxdonna-twitter'"],
            capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            # adapter_config.env values are { "type": "plain", "value": "..." } objects, not strings
            # Re-fetch as JSON and pull .value
            r2 = subprocess.run(PAPERCLIP_DSN + ["-c",
                "SELECT adapter_config->'env' FROM agents WHERE name='voxdonna-twitter'"],
                capture_output=True, text=True, check=False)
            try:
                env_obj = json.loads(r2.stdout.strip())
                for k in ("TWITTER_API_KEY", "TWITTER_API_SECRET",
                         "TWITTER_ACCESS_TOKEN", "TWITTER_ACCESS_TOKEN_SECRET"):
                    spec = env_obj.get(k)
                    if isinstance(spec, dict) and spec.get("value"):
                        env[k] = spec["value"]
            except json.JSONDecodeError:
                pass
    return env


def fetch_followers(env: dict[str, str]) -> int:
    auth = OAuth1(env["TWITTER_API_KEY"], env["TWITTER_API_SECRET"],
                  env["TWITTER_ACCESS_TOKEN"], env["TWITTER_ACCESS_TOKEN_SECRET"])
    url = f"https://api.x.com/2/users/by/username/{USERNAME}?user.fields=public_metrics"
    r = requests.get(url, auth=auth, timeout=30)
    r.raise_for_status()
    data = r.json()
    return data["data"]["public_metrics"]["followers_count"]


def expected_for_day(day: int) -> tuple[int, int]:
    """Return (expected_min, red_line) for the given day, interpolated linearly."""
    if day <= CURVE[0][0]:
        return (CURVE[0][1], CURVE[0][2])
    if day >= CURVE[-1][0]:
        return (CURVE[-1][1], CURVE[-1][2])
    for i in range(len(CURVE) - 1):
        d0, e0, r0 = CURVE[i]
        d1, e1, r1 = CURVE[i + 1]
        if d0 <= day <= d1:
            frac = (day - d0) / (d1 - d0)
            return (int(e0 + (e1 - e0) * frac), int(r0 + (r1 - r0) * frac))
    return (GOAL_TARGET, GOAL_TARGET - 200)


def telegram_send(env: dict[str, str], text: str) -> None:
    token = env.get("TELEGRAM_BOT_TOKEN")
    chat = env.get("TELEGRAM_CHAT_ID", "1107922833")
    if not token:
        print("WARN: TELEGRAM_BOT_TOKEN not set; skipping telegram", file=sys.stderr)
        return
    try:
        requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      data={"chat_id": chat, "text": text, "parse_mode": "HTML"},
                      timeout=15)
    except Exception as exc:
        print(f"telegram send failed: {exc}", file=sys.stderr)


def create_blocked_issue(env: dict[str, str], title: str, body: str) -> str | None:
    """Insert a blocked issue assigned to CEO. Returns identifier."""
    # Get next issue number
    nxt = subprocess.run(
        PAPERCLIP_DSN + ["-c",
            f"SELECT COALESCE(MAX(issue_number), 0) + 1 FROM issues "
            f"WHERE company_id='{COMPANY_ID}'"],
        capture_output=True, text=True, check=False)
    try:
        next_num = int(nxt.stdout.strip())
    except ValueError:
        next_num = 9999
    identifier = f"RAJA-{next_num}"
    sql = (
        f"INSERT INTO issues (company_id, project_id, title, description, status, "
        f"priority, assignee_agent_id, request_depth, issue_number, identifier) "
        f"VALUES ('{COMPANY_ID}', '{PROJECT_ID}', "
        f"$pctitle${title}$pctitle$, $pcbody${body}$pcbody$, "
        f"'blocked', 'high', '{CEO_AGENT_ID}', 0, {next_num}, '{identifier}') "
        f"RETURNING identifier;"
    )
    r = subprocess.run(
        ["env", "PGPASSWORD=paperclip", "psql", "-h", "127.0.0.1", "-p", "54329",
         "-U", "paperclip", "-d", "paperclip", "-v", "ON_ERROR_STOP=1"],
        input=sql, capture_output=True, text=True, check=False)
    if r.returncode == 0:
        return identifier
    print(f"issue creation failed: {r.stderr}", file=sys.stderr)
    return None


def main() -> int:
    env = load_env()
    if not env.get("TWITTER_API_KEY"):
        print("ERROR: missing TWITTER_API_KEY", file=sys.stderr)
        return 1

    DATA.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    day = (now - GOAL_START).days

    try:
        followers = fetch_followers(env)
    except Exception as exc:
        msg = f"❌ VoxDonna goal tracker: API failed: {exc}"
        telegram_send(env, msg)
        print(msg, file=sys.stderr)
        return 1

    # Bootstrap baseline on first run
    if not BASELINE_FILE.exists():
        BASELINE_FILE.write_text(f"{now.isoformat()}\t{followers}\n")
        baseline = followers
    else:
        first_line = BASELINE_FILE.read_text().splitlines()[0]
        baseline = int(first_line.split("\t", 1)[1])

    gained = followers - baseline
    expected, red_line = expected_for_day(day)
    days_remaining = (GOAL_DEADLINE - now).days

    if followers >= expected:
        status = "🟢 ON TRACK"
        verdict = f"At or ahead of curve. Day {day}: target {expected}, actual {followers}."
        escalate = False
    elif followers >= red_line:
        status = "🟡 BEHIND"
        verdict = (f"Below target but above red line. Day {day}: target {expected}, "
                   f"actual {followers} ({followers - expected:+d}). Tighten reply motion.")
        escalate = False
    else:
        status = "🔴 RED LINE HIT"
        verdict = (f"BELOW red line. Day {day}: target {expected}, red line {red_line}, "
                   f"actual {followers} ({followers - red_line:+d} from red, "
                   f"{followers - expected:+d} from target). Escalating to CEO.")
        escalate = True

    text = (
        f"<b>{status}</b> — VoxDonna 90-day goal\n\n"
        f"Day {day} of 90 ({days_remaining}d remaining)\n"
        f"Followers: <b>{followers}</b> (+{gained} since {GOAL_START.date()})\n"
        f"Target Day {day}: {expected}\n"
        f"Red line Day {day}: {red_line}\n\n"
        f"{verdict}\n\n"
        f"Goal deadline: {GOAL_DEADLINE.date()} → {GOAL_TARGET} followers"
    )

    telegram_send(env, text)
    print(text)

    if escalate:
        issue_id = create_blocked_issue(env,
            title=f"BLOCKED: VoxDonna trajectory below red line (Day {day}: {followers}/{red_line})",
            body=(f"# Trajectory red line hit\n\n"
                  f"Day {day}: actual {followers}, red line {red_line}, target {expected}.\n\n"
                  f"Deficit vs target: {followers - expected:+d}\n"
                  f"Deficit vs red line: {followers - red_line:+d}\n\n"
                  f"## Triage (per GROWTH_PLAN_90D.md stop conditions)\n\n"
                  f"1. Audit founder reply time last 7 days. If <30min/day, primary cause.\n"
                  f"2. Check voxdonna-twitter agent run history — any failed runs?\n"
                  f"3. Audit Tier 1 target accounts — reply-back rate. If <10%, switch to Tier 2.\n"
                  f"4. Check for shadowban indicators (zero impressions on new tweets).\n"
                  f"5. Audit Donna-voice adherence on last 7 posts. If 3+ violate SOUL.md rules, regenerate queue.\n\n"
                  f"Strategy review with founder required within 48h."))
        if issue_id:
            telegram_send(env, f"📌 Created blocked issue {issue_id} for CEO triage.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
