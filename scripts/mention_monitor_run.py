#!/usr/bin/env python3
"""VoxDonna X mention monitor — single run.

- Polls GET /2/users/{me}/mentions since data/last_mention_id
- Appends every mention to data/inbox.jsonl
- Priority >=5: Telegram PRIORITY alert (no draft)
- Priority 3-4: Telegram alert (no draft posted)
- <3: log only
- Never auto-replies. Approval is gated via Telegram.
"""
import json
import os
import sys
import time
from pathlib import Path

import requests
from requests_oauthlib import OAuth1Session

REPO = Path("/home/suyashraj/clawd/voxdonna")
DATA = REPO / "data"
LAST_ID = DATA / "last_mention_id"
INBOX = DATA / "inbox.jsonl"
MY_ID = (DATA / "my_user_id").read_text().strip()

ESCALATION = ["lawsuit", "trademark", "infringement", "gdpr", "compliance", "data breach"]
POSITIVE = ["love", "great", "recommend", "awesome", "amazing"]

oauth = OAuth1Session(
    os.environ["TWITTER_API_KEY"],
    client_secret=os.environ["TWITTER_API_SECRET"],
    resource_owner_key=os.environ["TWITTER_ACCESS_TOKEN"],
    resource_owner_secret=os.environ["TWITTER_ACCESS_TOKEN_SECRET"],
)

TG_BOT = os.environ["TELEGRAM_BOT_TOKEN"]
TG_CHAT = os.environ["TELEGRAM_CHAT_ID"]


def tg(text: str) -> bool:
    r = requests.post(
        f"https://api.telegram.org/bot{TG_BOT}/sendMessage",
        json={"chat_id": TG_CHAT, "text": text, "disable_web_page_preview": True},
        timeout=15,
    )
    if r.status_code != 200:
        print(f"[tg-err] {r.status_code} {r.text}", file=sys.stderr)
        return False
    return True


def score(text: str, followers: int) -> tuple[int, list[str]]:
    s = 0
    why = []
    lc = (text or "").lower()
    if followers > 100_000:
        s += 5
        why.append(f">100K followers ({followers})")
    for kw in ESCALATION:
        if kw in lc:
            s += 3
            why.append(f"escalation:{kw}")
            break
    for cue in POSITIVE:
        if cue in lc:
            s += 2
            why.append(f"positive:{cue}")
            break
    return s, why


def main() -> int:
    params = {
        "max_results": "20",
        "tweet.fields": "created_at,author_id,public_metrics,text",
        "expansions": "author_id",
        "user.fields": "username,name,public_metrics",
    }
    since = LAST_ID.read_text().strip() if LAST_ID.exists() else ""
    if since:
        params["since_id"] = since

    r = oauth.get(f"https://api.twitter.com/2/users/{MY_ID}/mentions", params=params)
    rl_remain = r.headers.get("x-rate-limit-remaining")
    print(f"STATUS {r.status_code} rl-remaining={rl_remain}", file=sys.stderr)

    if r.status_code == 429:
        print(json.dumps({"error": "rate_limited"}))
        return 2
    if r.status_code != 200:
        print(json.dumps({"error": r.status_code, "body": r.text[:500]}))
        return 1

    body = r.json()
    tweets = body.get("data", []) or []
    users = {u["id"]: u for u in (body.get("includes", {}).get("users", []) or [])}
    meta = body.get("meta", {})

    new_count = 0
    alerts = 0
    priority_alerts = 0
    has_escalation = False

    for t in tweets:
        author = users.get(t.get("author_id"), {})
        followers = (author.get("public_metrics") or {}).get("followers_count", 0)
        handle = author.get("username") or "unknown"
        text = t.get("text", "")
        sc, why = score(text, followers)
        if any(k in (text or "").lower() for k in ESCALATION):
            has_escalation = True

        row = {
            "ts": int(time.time()),
            "tweet_id": t["id"],
            "author_id": t.get("author_id"),
            "author_handle": handle,
            "author_followers": followers,
            "created_at": t.get("created_at"),
            "text": text,
            "score": sc,
            "score_reasons": why,
        }
        with INBOX.open("a") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        new_count += 1

        url = f"https://x.com/{handle}/status/{t['id']}"
        if sc >= 5:
            msg = (
                f"🔴 PRIORITY MENTION [id: m-{t['id']}]\n"
                f"From: @{handle} ({followers} followers)\n"
                f"Their tweet: \"{text}\"\n"
                f"URL: {url}\n"
                f"Score: {sc} ({', '.join(why)})\n"
                f"Action: human review required. No auto-draft."
            )
            tg(msg)
            alerts += 1
            priority_alerts += 1
        elif sc >= 3:
            msg = (
                f"📝 MENTION [id: m-{t['id']}]\n"
                f"From: @{handle} ({followers} followers)\n"
                f"Their tweet: \"{text}\"\n"
                f"URL: {url}\n"
                f"Score: {sc} ({', '.join(why)})\n"
                f"Reply /draft m-{t['id']} to request a draft, /reject m-{t['id']} to ignore.\n"
                f"(No reply will be posted without explicit /approve.)"
            )
            tg(msg)
            alerts += 1

    newest = meta.get("newest_id")
    if newest:
        LAST_ID.write_text(newest)

    print(json.dumps({
        "new_mentions": new_count,
        "alerts_sent": alerts,
        "priority_alerts": priority_alerts,
        "escalation_keyword_seen": has_escalation,
        "newest_id": newest,
        "rate_limit_remaining": rl_remain,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
