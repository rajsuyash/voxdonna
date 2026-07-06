#!/usr/bin/env python3
"""
Mention monitor for @voxdonna.

Polls X API /2/users/{my_id}/mentions since last_mention_id, scores each new
mention per the SKILL.md algorithm, appends to data/inbox.jsonl, and sends
Telegram alerts for priority>=3. Never auto-replies.

Exit codes:
  0  success (zero or more new mentions processed)
  1  unrecoverable error
  2  rate-limited (429) — caller should back off
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests_oauthlib import OAuth1

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
INBOX = DATA / "inbox.jsonl"
LAST_ID_FILE = DATA / "last_mention_id"
MY_USER_ID_FILE = DATA / "my_user_id"

ESCALATION_KEYWORDS = [
    "lawsuit", "trademark", "infringement", "gdpr", "compliance", "data breach",
]
POSITIVE_CUES = ["love", "great", "recommend", "amazing", "awesome"]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def telegram_send(text: str) -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("telegram creds missing — skipping alert", file=sys.stderr)
        return
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
            timeout=15,
        )
        if r.status_code != 200:
            print(f"telegram error {r.status_code}: {r.text}", file=sys.stderr)
    except Exception as e:
        print(f"telegram exception: {e}", file=sys.stderr)


def score_mention(text: str, author_followers: int, author_follows_us: bool) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    low = text.lower()
    if author_followers > 100_000:
        score += 5
        reasons.append(f">100K followers ({author_followers})")
    if any(k in low for k in ESCALATION_KEYWORDS):
        score += 3
        hits = [k for k in ESCALATION_KEYWORDS if k in low]
        reasons.append(f"escalation keyword: {','.join(hits)}")
    if any(k in low for k in POSITIVE_CUES):
        score += 2
        reasons.append("positive sentiment")
    if author_follows_us:
        score += 1
        reasons.append("author follows @voxdonna")
    return score, reasons


def fetch_mentions(my_id: str, since_id: str | None, auth: OAuth1) -> tuple[list, dict]:
    """Return (tweets, users_by_id). Raises on non-200, returns ([], {}) if no new."""
    params = {
        "max_results": "20",
        "tweet.fields": "created_at,author_id,public_metrics,text",
        "expansions": "author_id",
        "user.fields": "username,public_metrics,name",
    }
    if since_id:
        params["since_id"] = since_id
    url = f"https://api.twitter.com/2/users/{my_id}/mentions"
    r = requests.get(url, params=params, auth=auth, timeout=30)
    if r.status_code == 429:
        raise RuntimeError("RATE_LIMITED")
    if r.status_code != 200:
        raise RuntimeError(f"X API error {r.status_code}: {r.text}")
    body = r.json()
    tweets = body.get("data", []) or []
    includes_users = body.get("includes", {}).get("users", []) or []
    users_by_id = {u["id"]: u for u in includes_users}
    return tweets, users_by_id


def main() -> int:
    if not MY_USER_ID_FILE.exists():
        print("missing data/my_user_id", file=sys.stderr)
        return 1
    my_id = MY_USER_ID_FILE.read_text().strip()
    last_id = LAST_ID_FILE.read_text().strip() if LAST_ID_FILE.exists() else None

    try:
        auth = OAuth1(
            os.environ["TWITTER_API_KEY"],
            os.environ["TWITTER_API_SECRET"],
            os.environ["TWITTER_ACCESS_TOKEN"],
            os.environ["TWITTER_ACCESS_TOKEN_SECRET"],
        )
    except KeyError as e:
        print(f"missing twitter env var: {e}", file=sys.stderr)
        return 1

    try:
        tweets, users = fetch_mentions(my_id, last_id, auth)
    except RuntimeError as e:
        if "RATE_LIMITED" in str(e):
            print("rate-limited", file=sys.stderr)
            return 2
        print(f"fetch error: {e}", file=sys.stderr)
        return 1

    if not tweets:
        print(json.dumps({"new_mentions": 0, "alerts_sent": 0, "since_id": last_id}))
        return 0

    # Sort by id ascending so we process oldest first and update last_id at the end
    tweets_sorted = sorted(tweets, key=lambda t: int(t["id"]))
    DATA.mkdir(parents=True, exist_ok=True)
    alerts_priority = 0
    alerts_draft = 0
    seq = 0
    with INBOX.open("a") as f:
        for tw in tweets_sorted:
            seq += 1
            author_id = tw.get("author_id", "")
            author = users.get(author_id, {})
            handle = author.get("username", "unknown")
            followers = author.get("public_metrics", {}).get("followers_count", 0)
            text = tw.get("text", "")
            score, reasons = score_mention(text, followers, False)
            mention_id = f"m-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}-{seq:03d}"
            row = {
                "id": mention_id,
                "tweet_id": tw["id"],
                "author_id": author_id,
                "handle": handle,
                "followers": followers,
                "text": text,
                "created_at": tw.get("created_at", ""),
                "score": score,
                "reasons": reasons,
                "logged_at": now_iso(),
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

            tweet_url = f"https://x.com/{handle}/status/{tw['id']}"
            if score >= 5:
                msg = (
                    f"\U0001f534 PRIORITY MENTION [id: {mention_id}]\n"
                    f"From: @{handle} ({followers:,} followers)\n"
                    f"Reasons: {', '.join(reasons)}\n"
                    f"Their tweet: \"{text}\"\n"
                    f"{tweet_url}\n"
                    f"Suggested action: escalate (no draft — human review required)"
                )
                telegram_send(msg)
                alerts_priority += 1
            elif score >= 3:
                msg = (
                    f"\U0001f4dd MENTION [id: {mention_id}] score={score}\n"
                    f"From: @{handle} ({followers:,} followers)\n"
                    f"Their tweet: \"{text}\"\n"
                    f"{tweet_url}\n"
                    f"Reasons: {', '.join(reasons)}\n"
                    f"Action: draft a reply for human review (not yet drafted by monitor — use /draft {mention_id})"
                )
                telegram_send(msg)
                alerts_draft += 1

    # Update last_id to the newest tweet id we processed
    newest = max(int(t["id"]) for t in tweets_sorted)
    LAST_ID_FILE.write_text(str(newest))

    summary = {
        "new_mentions": len(tweets_sorted),
        "alerts_priority": alerts_priority,
        "alerts_draft": alerts_draft,
        "newest_id": str(newest),
    }
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
