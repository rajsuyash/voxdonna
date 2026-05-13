#!/usr/bin/env python3
"""engagement-twitter.py v2 — autonomous Twitter engagement (search-based mid-tier).

Strategy revision (May 2026): the original Tier 1 whitelist hit a structural
wall. X's 2026 reply-gating blocks @voxdonna (<100 followers) from replying
to all popular accounts. See TWITTER_GROWTH_REVISED.md.

This version:
1. Search X for recent tweets in voice-AI/CX niche via /2/tweets/search/recent
2. Fetch tweet.fields=reply_settings + author public_metrics
3. Filter client-side for reply_settings='everyone' (skip gated)
4. Score: mid-tier follower band (5-50k), recency, engagement headroom
5. For each candidate, draft Donna-voice reply via Claude Haiku
6. Validate (≤280c, no em-dash, no AI-vocab)
7. POST as reply via X API
8. Fallback for HIGH-relevance gated tweets: quote-tweet instead (QT bypasses gating)
9. Log + Telegram digest

Cap: REPLIES_PER_DAY (default 10) — autonomous-only ceiling. Bump to 25 if
founder time available for daily review.

Pause: UPDATE routines SET status='paused' WHERE title LIKE '%Engagement%'.
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

REPLIES_PER_DAY = 0  # disabled: X gates replies on new accounts beyond reply_settings field
QT_PER_DAY = 5  # PRIMARY engagement mode now — QTs bypass all reply restrictions

# Mid-tier follower band per research (5-50k = best reply ROI)
FOLLOWER_BAND_MIN = 5_000
FOLLOWER_BAND_MAX = 50_000

# Boolean search queries — buyer-intent keywords for voice-AI / CX / B2B
SEARCH_QUERIES = [
    '("voice agent" OR "voice AI" OR "AI receptionist") -is:retweet -is:reply lang:en',
    '("call center" OR "contact center") AI (automation OR support) -is:retweet -is:reply lang:en',
    '("customer support" OR "customer service") AI (deflection OR savings) -is:retweet -is:reply lang:en',
    '("AI SDR" OR "outbound calling" OR "AI phone") -is:retweet -is:reply lang:en',
    '("conversational AI" OR "voice bot") -is:retweet -is:reply lang:en',
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


def search_tweets(auth: OAuth1, query: str, hours: int = 12, max_results: int = 50) -> list[dict]:
    """Search recent tweets via X API v2 /tweets/search/recent."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    params = {
        "query": query,
        "max_results": str(max_results),
        "tweet.fields": "public_metrics,created_at,reply_settings,author_id,conversation_id",
        "expansions": "author_id",
        "user.fields": "public_metrics,verified,username",
        "start_time": since,
    }
    r = requests.get("https://api.x.com/2/tweets/search/recent", params=params, auth=auth, timeout=30)
    if r.status_code != 200:
        print(f"search HTTP {r.status_code}: {r.text[:300]}", file=sys.stderr)
        return []
    body = r.json()
    tweets = body.get("data", [])
    users = {u["id"]: u for u in body.get("includes", {}).get("users", [])}
    for t in tweets:
        t["_author"] = users.get(t.get("author_id"), {})
    return tweets


def score_candidate(t: dict) -> float:
    """Higher = better engagement target."""
    author = t.get("_author") or {}
    author_followers = (author.get("public_metrics") or {}).get("followers_count", 0)
    if author_followers < FOLLOWER_BAND_MIN / 2 or author_followers > FOLLOWER_BAND_MAX * 3:
        return -100  # way out of band, skip
    m = t.get("public_metrics") or {}
    likes = m.get("like_count", 0)
    replies = m.get("reply_count", 0)
    engagement_score = min(20, likes) + max(0, 25 - replies)
    band_bonus = 15 if FOLLOWER_BAND_MIN <= author_followers <= FOLLOWER_BAND_MAX else 0
    verified_bonus = 5 if author.get("verified") else 0
    recency_bonus = 0
    created = t.get("created_at", "")
    if created:
        try:
            age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).total_seconds() / 3600
            if age_h <= 2: recency_bonus = 20
            elif age_h <= 6: recency_bonus = 10
            elif age_h <= 12: recency_bonus = 5
        except ValueError:
            pass
    return engagement_score + band_bonus + verified_bonus + recency_bonus


def call_claude(env: dict[str, str], prompt: str, system: str) -> str:
    url = "https://api.anthropic.com/v1/messages"
    headers = {"x-api-key": env["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01",
               "content-type": "application/json"}
    payload = {"model": "claude-haiku-4-5-20251001", "max_tokens": 400, "system": system,
               "messages": [{"role": "user", "content": prompt}]}
    r = requests.post(url, headers=headers, json=payload, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"Anthropic HTTP {r.status_code}: {r.text[:300]}")
    return r.json()["content"][0]["text"].strip()


def draft_reply(env: dict[str, str], author_handle: str, tweet_text: str, is_qt: bool = False) -> str:
    soul = SOUL_PATH.read_text() if SOUL_PATH.exists() else ""
    mode = "quote-tweet" if is_qt else "reply"
    system = (
        "You are Donna Paulsen from Suits, posting as @voxdonna (B2B AI voice-agent "
        "company). Brand voice rules:\n\n" + soul +
        f"\n\nYou are drafting a {mode}. Output ONLY the {mode} text. No preamble, no quotes.\n"
        "Must be ≤280 chars. No em-dashes. No AI-vocab (delve/robust/leverage/comprehensive/nuanced/pivotal/landscape).\n"
        "Donna doesn't ask questions in headers. Confident statement. One specific number if relevant "
        "(Le Marquier: 2,500 calls/mo, 98% automated, 80% CS cost cut, 4-min average call).\n"
        "Counter-data, sharper restatement, or anecdote with stakes. Never 'great post!' or 'so true'."
    )
    prompt = (
        f"Original post by @{author_handle}:\n\n\"{tweet_text}\"\n\n"
        f"Draft Donna's {mode} (≤280 chars). Must add value. "
        f"If you can't write something sharp and on-brand, output exactly: SKIP"
    )
    return call_claude(env, prompt, system).strip().strip('"').strip("'")


def validate(text: str) -> list[str]:
    if not text or text.strip().upper() == "SKIP":
        return ["model returned SKIP / empty"]
    issues = []
    if len(text) > 280: issues.append(f"length {len(text)} > 280")
    if "—" in text: issues.append("contains em-dash")
    low = text.lower()
    for w in BANNED_WORDS:
        if w in low: issues.append(f"banned word: {w!r}")
    return issues


def post_reply(auth: OAuth1, text: str, reply_to_id: str) -> tuple[int, dict]:
    payload = {"text": text, "reply": {"in_reply_to_tweet_id": reply_to_id}}
    r = requests.post("https://api.x.com/2/tweets", auth=auth, json=payload, timeout=30)
    try: return r.status_code, r.json()
    except Exception: return r.status_code, {"raw": r.text[:300]}


def post_quote_tweet(auth: OAuth1, text: str, quote_tweet_id: str) -> tuple[int, dict]:
    payload = {"text": text, "quote_tweet_id": quote_tweet_id}
    r = requests.post("https://api.x.com/2/tweets", auth=auth, json=payload, timeout=30)
    try: return r.status_code, r.json()
    except Exception: return r.status_code, {"raw": r.text[:300]}


def telegram_send(env: dict[str, str], text: str) -> None:
    token = env.get("TELEGRAM_BOT_TOKEN")
    chat = env.get("TELEGRAM_CHAT_ID", "1107922833")
    if not token: return
    try:
        requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                      data={"chat_id": chat, "text": text, "parse_mode": "HTML"}, timeout=15)
    except Exception:
        pass


def already_engaged(tweet_id: str) -> bool:
    if not LOG.exists(): return False
    for line in LOG.read_text().splitlines():
        try:
            row = json.loads(line)
            if row.get("reply_to_id") == tweet_id or row.get("quoted_tweet_id") == tweet_id:
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
        if not env.get(k): sys.exit(f"missing {k}")
    auth = x_auth(env)

    today = datetime.now(timezone.utc).date().isoformat()
    posted_today, qt_today = 0, 0
    if LOG.exists():
        for line in LOG.read_text().splitlines():
            try:
                r = json.loads(line)
                if r.get("date") == today and r.get("status") == "posted":
                    posted_today += 1
                    if r.get("kind") == "quote_tweet": qt_today += 1
            except json.JSONDecodeError:
                continue
    if posted_today >= REPLIES_PER_DAY and qt_today >= QT_PER_DAY:
        print(f"daily cap reached: {posted_today}/{REPLIES_PER_DAY}")
        return 0

    print("Searching X for voice-AI / CX niche tweets...")
    seen_ids = set()
    all_candidates = []
    for q in SEARCH_QUERIES:
        tweets = search_tweets(auth, q, hours=12, max_results=50)
        for t in tweets:
            tid = t["id"]
            if tid in seen_ids or already_engaged(tid):
                continue
            seen_ids.add(tid)
            all_candidates.append(t)
        time.sleep(2)
    print(f"Found {len(all_candidates)} unique candidates.")

    open_reply = [t for t in all_candidates if t.get("reply_settings") == "everyone"]
    gated = [t for t in all_candidates if t.get("reply_settings") != "everyone"]

    open_scored = sorted(((score_candidate(t), t) for t in open_reply), reverse=True, key=lambda x: x[0])
    # QT pool: ALL candidates (replies didn't work anyway). Skip tweets we've already replied to in this run.
    qt_candidates = all_candidates  # everything
    qt_scored = sorted(((score_candidate(t), t) for t in qt_candidates), reverse=True, key=lambda x: x[0])
    gated_scored = qt_scored  # rename for backward compat

    posted_summaries, skipped_summaries = [], []
    needed = REPLIES_PER_DAY - posted_today
    qt_remaining = QT_PER_DAY - qt_today

    # Phase A: open-reply targets
    for score, t in open_scored:
        if len([s for s in posted_summaries if "REPLY" in s]) >= (needed - qt_remaining):
            break
        if score < 10:
            continue
        author = t["_author"]
        handle = author.get("username", "unknown")
        followers = (author.get("public_metrics") or {}).get("followers_count", 0)
        text = t["text"]
        print(f"\n[REPLY score={score:.0f}] @{handle} ({followers}f) {t['id']}")
        print(f"  {text[:160]}")
        try:
            draft = draft_reply(env, handle, text, is_qt=False)
        except Exception as exc:
            print(f"  ✗ Claude err: {exc}")
            log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                       "kind": "reply", "author": handle, "reply_to_id": t["id"],
                       "status": "claude_fail", "error": str(exc)[:200]})
            continue
        issues = validate(draft)
        if issues:
            print(f"  ✗ validate: {issues}")
            log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                       "kind": "reply", "author": handle, "reply_to_id": t["id"],
                       "status": "skipped", "reason": ",".join(issues), "draft": draft})
            skipped_summaries.append(f"@{handle}: {','.join(issues)[:60]}")
            continue
        code, resp = post_reply(auth, draft, t["id"])
        if code in (200, 201):
            pid = resp.get("data", {}).get("id")
            url = f"https://x.com/voxdonna/status/{pid}" if pid else None
            print(f"  ✓ replied {pid}")
            log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                       "kind": "reply", "author": handle, "reply_to_id": t["id"],
                       "status": "posted", "reply_id": pid, "url": url, "text": draft})
            posted_summaries.append(f"REPLY → @{handle} ({followers}f): {url}\n   <i>{draft[:140]}</i>")
        elif code == 403:
            print(f"  ✗ 403 gated (settings changed?)")
            log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                       "kind": "reply", "author": handle, "reply_to_id": t["id"],
                       "status": "gated_403", "draft": draft})
        else:
            print(f"  ✗ X {code}: {str(resp)[:200]}")
            log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                       "kind": "reply", "author": handle, "reply_to_id": t["id"],
                       "status": f"post_fail_{code}", "error": str(resp)[:200], "draft": draft})
        time.sleep(3)

    # Phase B: quote-tweet high-score gated targets
    if qt_remaining > 0:
        for score, t in gated_scored:
            qts_now = qt_today + len([s for s in posted_summaries if "QT" in s])
            if qts_now >= QT_PER_DAY:
                break
            if score < 5:
                continue
            author = t["_author"]
            handle = author.get("username", "unknown")
            followers = (author.get("public_metrics") or {}).get("followers_count", 0)
            text = t["text"]
            print(f"\n[QT score={score:.0f}] @{handle} ({followers}f) {t['id']}")
            print(f"  {text[:160]}")
            try:
                draft = draft_reply(env, handle, text, is_qt=True)
            except Exception as exc:
                print(f"  ✗ Claude err: {exc}")
                continue
            issues = validate(draft)
            if issues:
                print(f"  ✗ validate: {issues}")
                continue
            code, resp = post_quote_tweet(auth, draft, t["id"])
            if code in (200, 201):
                pid = resp.get("data", {}).get("id")
                url = f"https://x.com/voxdonna/status/{pid}" if pid else None
                print(f"  ✓ quote-tweeted {pid}")
                log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                           "kind": "quote_tweet", "author": handle, "quoted_tweet_id": t["id"],
                           "status": "posted", "reply_id": pid, "url": url, "text": draft})
                posted_summaries.append(f"QT → @{handle} ({followers}f): {url}\n   <i>{draft[:140]}</i>")
            else:
                print(f"  ✗ X {code}: {str(resp)[:200]}")
            time.sleep(3)

    digest = f"🐦 <b>Twitter auto-engage</b> ({today})\n\n"
    if posted_summaries:
        digest += f"Posted {len(posted_summaries)} engagement(s):\n\n" + "\n\n".join(posted_summaries)
    else:
        digest += "No engagements this run."
    if skipped_summaries:
        digest += f"\n\nSkipped {len(skipped_summaries)}: " + "; ".join(skipped_summaries[:5])
    telegram_send(env, digest)
    print(f"\nDone. {len(posted_summaries)} posted, {len(skipped_summaries)} skipped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
