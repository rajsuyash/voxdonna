#!/usr/bin/env python3
"""engagement-twitter.py — autonomous Twitter engagement for @voxdonna.

Fires daily (10:00 UTC via Paperclip routine). For each Tier 1 target:
1. Fetch last 24h tweets via X API v2 (excluding retweets/replies)
2. Score by relevance (voice-AI/CX keywords) + recency
3. Pick top N tweets across the whitelist
4. For each, ask Claude to draft a Donna-voice reply (per SOUL.md)
5. Validate the draft against hard rules (no em-dash, no AI-vocab, ≤280c)
6. If validation passes, post via X API POST /2/tweets with reply.in_reply_to_tweet_id
7. Append to engagement log, Telegram digest

User mode: AUTONOMOUS (no human approval). Founder explicitly removed HITL
because they don't have time to reply.

Daily cap: REPLIES_PER_DAY (default 3). Voice validator is the kill switch:
any draft that violates SOUL.md is silently skipped — better to under-post
than ship a bad reply.

To pause: UPDATE routines SET status='paused' WHERE title LIKE '%Engagement%'.

Reads creds from /home/suyashraj/clawd/.env (ANTHROPIC_API_KEY, TWITTER_*).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from requests_oauthlib import OAuth1

ROOT = Path("/home/suyashraj/clawd/voxdonna")
DATA = ROOT / "data"
LOG = DATA / "engagement-twitter-log.jsonl"
SOUL_PATH = ROOT / "SOUL.md"

# Tier 1 X accounts per GROWTH_PLAN_90D.md
TIER_1 = ["briansolis", "jaybaer", "jasonlk", "aprildunford", "destraynor", "nathanlatka"]

REPLIES_PER_DAY = 3
KEYWORDS = [  # for relevance scoring
    "ai", "voice", "customer", "cx", "support", "service", "agent", "automation",
    "saas", "b2b", "operations", "ops", "contact", "call", "experience", "chatbot",
]

BANNED_WORDS = [
    "delve", "robust", "comprehensive", "nuanced", "leverage", "pivotal",
    "landscape", "thrilled", "excited to share", "honored to", "thrilled to announce",
    "multifaceted", "intricate", "foster", "showcase", "tapestry", "underscore",
    "interplay", "furthermore", "moreover", "additionally", "fundamental", "significant",
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
    return env


def x_auth(env: dict[str, str]) -> OAuth1:
    return OAuth1(env["TWITTER_API_KEY"], env["TWITTER_API_SECRET"],
                  env["TWITTER_ACCESS_TOKEN"], env["TWITTER_ACCESS_TOKEN_SECRET"])


def fetch_recent_tweets(auth: OAuth1, handle: str, hours: int = 24) -> list[dict]:
    """Get last `hours` of tweets from @handle (excl retweets/replies)."""
    r = requests.get(f"https://api.x.com/2/users/by/username/{handle}", auth=auth, timeout=20)
    if r.status_code != 200:
        return []
    body = r.json()
    if "data" not in body:
        # X API returns 200 with {"errors": [...]} when user not found
        print(f"  @{handle} not resolvable: {str(body.get('errors', body))[:120]}", file=sys.stderr)
        return []
    uid = body["data"]["id"]
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    r2 = requests.get(
        f"https://api.x.com/2/users/{uid}/tweets",
        params={
            "max_results": "10",
            "tweet.fields": "public_metrics,created_at",
            "exclude": "retweets,replies",
            "start_time": since,
        },
        auth=auth, timeout=20)
    if r2.status_code != 200:
        return []
    out = []
    for t in r2.json().get("data", []):
        t["_author"] = handle
        out.append(t)
    return out


def score_tweet(t: dict) -> float:
    """Higher = more reply-worthy. Recency + relevance + engagement headroom."""
    text = (t.get("text") or "").lower()
    kw_hits = sum(1 for k in KEYWORDS if k in text)
    m = t.get("public_metrics") or {}
    # Sweet spot for replies: tweets with some traction but not viral (where your reply gets buried)
    likes = m.get("like_count", 0)
    replies = m.get("reply_count", 0)
    # Score components
    relevance = kw_hits * 5
    engagement_sweet = max(0, 30 - replies)  # fewer replies = more visibility for ours
    traction = min(20, likes)  # cap to avoid biasing toward viral
    return relevance + engagement_sweet + traction


def call_claude(env: dict[str, str], prompt: str, system: str) -> str:
    """Single Anthropic message call. Returns response text."""
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": env["ANTHROPIC_API_KEY"],
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 400,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    }
    r = requests.post(url, headers=headers, json=payload, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"Anthropic HTTP {r.status_code}: {r.text[:300]}")
    data = r.json()
    return data["content"][0]["text"].strip()


def draft_reply(env: dict[str, str], target_handle: str, tweet_text: str) -> str:
    """Use Claude Haiku to draft a Donna-voice reply."""
    soul = SOUL_PATH.read_text() if SOUL_PATH.exists() else ""
    system = (
        "You are Donna Paulsen from the show Suits, replying on Twitter as @voxdonna "
        "(an AI voice-agent company for B2B). Brand voice rules:\n\n" + soul +
        "\n\nGenerate ONLY the reply text. No preamble. No quotes. No 'Here's a reply:'.\n"
        "Must be ≤280 chars. No em-dashes. No AI-vocab (delve/robust/comprehensive/leverage etc).\n"
        "Donna doesn't ask questions in headers. Confident statement. One specific number if relevant.\n"
        "Reply with counter-data, sharper restatement, or anecdote with stakes. Never 'great post!'."
    )
    prompt = (
        f"Tweet from @{target_handle}:\n\n\"{tweet_text}\"\n\n"
        f"Draft Donna's reply (≤280 chars). Reply must add value, not just agree. "
        f"If you can't write something sharp and on-brand, output exactly: SKIP"
    )
    out = call_claude(env, prompt, system).strip().strip('"').strip("'")
    return out


def validate(text: str) -> list[str]:
    issues = []
    if not text or text == "SKIP":
        issues.append("model returned SKIP / empty")
        return issues
    if len(text) > 280:
        issues.append(f"length {len(text)} > 280")
    if "—" in text:
        issues.append("contains em-dash")
    low = text.lower()
    for w in BANNED_WORDS:
        if w in low:
            issues.append(f"banned word: {w!r}")
    return issues


def post_reply(auth: OAuth1, text: str, reply_to_id: str) -> tuple[int, dict]:
    payload = {"text": text, "reply": {"in_reply_to_tweet_id": reply_to_id}}
    r = requests.post("https://api.x.com/2/tweets", auth=auth, json=payload, timeout=30)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"raw": r.text[:300]}


def telegram_send(env: dict[str, str], text: str) -> None:
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


def already_replied_today(reply_to_id: str) -> bool:
    """Check engagement log to dedupe across runs (in case routine catches up)."""
    if not LOG.exists():
        return False
    today = datetime.now(timezone.utc).date().isoformat()
    for line in LOG.read_text().splitlines():
        try:
            row = json.loads(line)
            if row.get("date") == today and row.get("reply_to_id") == reply_to_id:
                return True
        except json.JSONDecodeError:
            continue
    return False


def log_entry(entry: dict) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def main() -> int:
    env = load_env()
    for k in ("ANTHROPIC_API_KEY", "TWITTER_API_KEY", "TWITTER_API_SECRET",
              "TWITTER_ACCESS_TOKEN", "TWITTER_ACCESS_TOKEN_SECRET"):
        if not env.get(k):
            sys.exit(f"missing {k} in env")
    auth = x_auth(env)

    # Daily cap check
    today = datetime.now(timezone.utc).date().isoformat()
    if LOG.exists():
        sent_today = sum(
            1 for line in LOG.read_text().splitlines()
            if (lambda r: r.get("date") == today and r.get("status") == "posted")(
                json.loads(line) if line.strip() else {})
        )
        if sent_today >= REPLIES_PER_DAY:
            print(f"daily cap reached: {sent_today}/{REPLIES_PER_DAY}. Skipping.")
            return 0

    # Fetch + score
    print("Fetching Tier 1 tweets...")
    all_tweets: list[dict] = []
    for h in TIER_1:
        all_tweets.extend(fetch_recent_tweets(auth, h, hours=24))
        time.sleep(1)  # X API courtesy

    if not all_tweets:
        print("No recent Tier 1 tweets found in last 24h.")
        telegram_send(env, "🐦 Twitter auto-engage: no Tier 1 tweets in last 24h. Skipping.")
        return 0

    # Filter out already-replied-to + score
    candidates = [(score_tweet(t), t) for t in all_tweets if not already_replied_today(t["id"])]
    candidates.sort(reverse=True, key=lambda x: x[0])

    needed = REPLIES_PER_DAY - (sent_today if LOG.exists() else 0)
    posted_summaries = []
    skipped_summaries = []

    for score, t in candidates:
        if len(posted_summaries) >= needed:
            break
        author = t["_author"]
        tweet_id = t["id"]
        tweet_text = t["text"]
        print(f"\n[score={score:.1f}] @{author} tweet {tweet_id}: {tweet_text[:120]}")

        try:
            reply = draft_reply(env, author, tweet_text)
        except Exception as exc:
            print(f"  ✗ Claude failed: {exc}")
            log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                       "author": author, "reply_to_id": tweet_id, "status": "claude_fail",
                       "error": str(exc)[:200]})
            continue

        issues = validate(reply)
        if issues:
            print(f"  ✗ validation: {issues}")
            log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                       "author": author, "reply_to_id": tweet_id, "status": "skipped",
                       "reason": ",".join(issues), "draft": reply})
            skipped_summaries.append(f"@{author}: {','.join(issues)}")
            continue

        print(f"  draft ({len(reply)}c): {reply}")
        code, resp = post_reply(auth, reply, tweet_id)
        if code in (200, 201):
            posted_id = resp.get("data", {}).get("id")
            url = f"https://x.com/voxdonna/status/{posted_id}" if posted_id else None
            print(f"  ✓ posted {posted_id}")
            log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                       "author": author, "reply_to_id": tweet_id, "status": "posted",
                       "reply_id": posted_id, "url": url, "text": reply})
            posted_summaries.append(f"→ @{author}: {url}\n   <i>{reply[:140]}</i>")
        else:
            err = json.dumps(resp)[:300]
            print(f"  ✗ X API {code}: {err}")
            log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                       "author": author, "reply_to_id": tweet_id, "status": f"post_fail_{code}",
                       "error": err, "draft": reply})

        time.sleep(3)  # Be polite to X rate-limits

    # Telegram digest
    digest = f"🐦 <b>Twitter auto-engage</b> ({today})\n\n"
    if posted_summaries:
        digest += f"Posted {len(posted_summaries)} reply(ies):\n\n" + "\n\n".join(posted_summaries)
    else:
        digest += "No replies posted this run."
    if skipped_summaries:
        digest += f"\n\nSkipped: {len(skipped_summaries)}\n" + "\n".join(skipped_summaries[:5])
    telegram_send(env, digest)
    print(f"\nDone. Posted {len(posted_summaries)} reply(ies).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
