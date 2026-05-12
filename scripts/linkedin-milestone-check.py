#!/usr/bin/env python3
"""linkedin-milestone-check.py — 0→500 LinkedIn company page trajectory tracker.

Runs Mon 09:30 UTC via Paperclip routine. Reads @voxdonna company page
follower count via Unipile (GET /companies/{id}), compares against adjusted
back-loaded curve (no founder amplification baseline), and:
- Telegrams digest (⏳ grace / 🟢 on track / 🟡 behind / 🔴 red line)
- Creates blocked Paperclip CEO issue if below red line (Day-5 grace skips)

Day-0 baseline: 2026-05-12 (matches Twitter goal start).
Deadline: 2026-08-10 (unified Day-90 review with Twitter goal).
Target: 500. Honest expected value 350-450 per LINKEDIN_GROWTH_PLAN_90D.md.

Reads page identifier from voxdonna/data/linkedin_org_id.txt.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path("/home/suyashraj/clawd/voxdonna")
DATA = ROOT / "data"
BASELINE_FILE = DATA / "linkedin_baseline.txt"
ORG_ID_FILE = DATA / "linkedin_org_id.txt"

GOAL_START = datetime(2026, 5, 12, tzinfo=timezone.utc)
GOAL_DEADLINE = datetime(2026, 8, 10, tzinfo=timezone.utc)
GOAL_TARGET = 500

PAPERCLIP_DSN = ["env", "PGPASSWORD=paperclip", "psql", "-h", "127.0.0.1",
                 "-p", "54329", "-U", "paperclip", "-d", "paperclip", "-At"]
COMPANY_ID = "a54ed150-dc5b-40cc-83a3-2da628514997"
CEO_AGENT_ID = "12b7fc5f-9ae1-4b75-9c35-91c86c9cf436"
PROJECT_ID = "5a3623dd-8bb5-4ed4-be93-165fa9545186"  # SEO & Content

# Adjusted curve: research-derived for NO founder cross-post + NO paid spend.
# Day-90 target stays 500 per user; honest expected value ~400.
# Red line is "this run is concerning; investigate".
CURVE = [
    (0,   0,   0),
    (3,   3,   1),
    (7,   15,  6),    # admin invites + initial posts
    (14,  40,  20),
    (30,  90,  55),   # approaches 150 threshold
    (45,  160, 100),  # 9x algo acceleration kicks in past 150
    (60,  220, 150),
    (75,  330, 220),
    (90,  500, 280),  # stretch goal; expected 400, red <280
]
GRACE_PERIOD_DAYS = 5


def load_config_env() -> dict:
    """Load Unipile config + Telegram env."""
    env: dict = {}
    config_path = Path("/home/suyashraj/clawd/lead-gen/multi-touch/config.json")
    if config_path.exists():
        cfg = json.loads(config_path.read_text())
        env["unipile"] = cfg["unipile"]
    for path in [Path("/home/suyashraj/.openclaw/.env"), Path("/home/suyashraj/clawd/.env")]:
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def fetch_followers(unipile: dict, org_id: str) -> int:
    """GET /companies/{id} via Unipile, return follower_count."""
    base = unipile["base_url"].rstrip("/")
    url = f"{base}/companies/{org_id}?account_id={unipile['account_id']}"
    headers = {
        "X-API-KEY": unipile["api_key"],
        "accept": "application/json",
        "User-Agent": "Mozilla/5.0",
    }
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()
    # Unipile shape varies; try common fields
    for key in ("follower_count", "followers_count", "followerCount"):
        if key in data:
            return int(data[key])
        if "data" in data and isinstance(data["data"], dict) and key in data["data"]:
            return int(data["data"][key])
    raise ValueError(f"could not find follower_count in response: {list(data.keys())[:10]}")


def expected_for_day(day: int) -> tuple[int, int]:
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


def telegram_send(env: dict, text: str) -> None:
    token = env.get("TELEGRAM_BOT_TOKEN")
    chat = env.get("TELEGRAM_CHAT_ID", "1107922833")
    if not token:
        return
    try:
        requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      data={"chat_id": chat, "text": text, "parse_mode": "HTML"},
                      timeout=15)
    except Exception:
        pass


def create_blocked_issue(title: str, body: str) -> str | None:
    sql = (
        f"INSERT INTO issues (company_id, project_id, title, description, status, "
        f"priority, assignee_agent_id, request_depth) "
        f"VALUES ('{COMPANY_ID}', '{PROJECT_ID}', "
        f"$pctitle${title}$pctitle$, $pcbody${body}$pcbody$, "
        f"'blocked', 'high', '{CEO_AGENT_ID}', 0) "
        f"RETURNING id;"
    )
    r = subprocess.run(
        ["env", "PGPASSWORD=paperclip", "psql", "-h", "127.0.0.1", "-p", "54329",
         "-U", "paperclip", "-d", "paperclip", "-v", "ON_ERROR_STOP=1"],
        input=sql, capture_output=True, text=True, check=False)
    if r.returncode == 0:
        return r.stdout.strip().split("\n")[0] or None
    print(f"issue creation failed: {r.stderr}", file=sys.stderr)
    return None


def main() -> int:
    env = load_config_env()
    if "unipile" not in env:
        sys.exit("missing unipile config")
    if not ORG_ID_FILE.exists():
        msg = "❌ LinkedIn tracker: linkedin_org_id.txt missing — page identifier not configured yet"
        telegram_send(env, msg)
        print(msg, file=sys.stderr)
        return 1
    org_id = ORG_ID_FILE.read_text().strip()

    DATA.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    day = (now - GOAL_START).days

    try:
        followers = fetch_followers(env["unipile"], org_id)
    except Exception as exc:
        msg = f"❌ LinkedIn tracker: Unipile API failed: {exc}"
        telegram_send(env, msg)
        print(msg, file=sys.stderr)
        return 1

    if not BASELINE_FILE.exists():
        BASELINE_FILE.write_text(f"{now.isoformat()}\t{followers}\n")
        baseline = followers
    else:
        first_line = BASELINE_FILE.read_text().splitlines()[0]
        baseline = int(first_line.split("\t", 1)[1])

    gained = followers - baseline
    expected, red_line = expected_for_day(day)
    days_remaining = (GOAL_DEADLINE - now).days

    in_grace = day < GRACE_PERIOD_DAYS
    if in_grace:
        status = "⏳ GRACE PERIOD"
        verdict = (f"Day {day} of 90, still ramping up (grace window ends Day "
                   f"{GRACE_PERIOD_DAYS}). First real check at Day 7 (target 15). "
                   f"No escalation triggered.")
        escalate = False
    elif followers >= expected:
        status = "🟢 ON TRACK"
        verdict = f"At or ahead of curve. Day {day}: target {expected}, actual {followers}."
        escalate = False
    elif followers >= red_line:
        status = "🟡 BEHIND"
        verdict = (f"Below target but above red line. Day {day}: target {expected}, "
                   f"actual {followers} ({followers - expected:+d}). Tighten cadence + "
                   f"page-comment routine.")
        escalate = False
    else:
        status = "🔴 RED LINE HIT"
        verdict = (f"BELOW red line. Day {day}: target {expected}, red line {red_line}, "
                   f"actual {followers} ({followers - red_line:+d} from red, "
                   f"{followers - expected:+d} from target). Escalating to CEO.")
        escalate = True

    text = (
        f"<b>{status}</b> — VoxDonna LinkedIn 90-day goal\n\n"
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
        issue_id = create_blocked_issue(
            title=f"BLOCKED: VoxDonna LinkedIn trajectory below red line (Day {day}: {followers}/{red_line})",
            body=(f"# LinkedIn trajectory red line hit\n\n"
                  f"Day {day}: actual {followers}, red line {red_line}, target {expected}.\n\n"
                  f"Deficit vs target: {followers - expected:+d}\n"
                  f"Deficit vs red line: {followers - red_line:+d}\n\n"
                  f"## Triage (per LINKEDIN_GROWTH_PLAN_90D.md)\n\n"
                  f"1. Audit posting cadence last 7 days. <3 posts/week = primary cause.\n"
                  f"2. Audit Donna-voice adherence on last 5 posts. If 2+ violate SOUL.md = regenerate queue.\n"
                  f"3. Check page-comment activity: were 30 min/day done on Tier 1?\n"
                  f"4. Check if 150-threshold has been crossed (defines algo acceleration).\n"
                  f"5. Decision: trigger Path B (paid follower ads $300-500) or Path C "
                  f"(allow founder COMMENTS on page posts, not re-shares)?\n\n"
                  f"Strategy review with founder required within 48h."))
        if issue_id:
            telegram_send(env, f"📌 Created blocked issue (UUID {issue_id[:8]}) for CEO triage.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
