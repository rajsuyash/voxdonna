#!/usr/bin/env python3
"""engagement-twitter.py v3 — DRAFT-ONLY mode (Telegram → founder copies → manual post).

Per TWITTER_GROWTH_REVISED.md v2: X blocked programmatic replies + QTs on all
non-Enterprise API tiers in Feb 2026. Premium+ doesn't bypass it. Account
age doesn't help. Only fix: post manually via x.com app/web.

This script's job is to do the EXPENSIVE part (search, score, Donna-voice
drafting) and hand the founder a copy-paste-ready Telegram message per
draft. Each Telegram message:
- Target handle + follower count
- Original tweet text (so founder has context without leaving Telegram)
- Donna reply pre-validated (≤280c, no em-dash, no AI-vocab)
- Direct URL to the tweet (one tap → x.com app → paste → post)

Founder time per draft: ~15 seconds when batched.

Cap: DRAFTS_PER_DAY (default 8). Bump higher if founder wants to invest more.

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

DRAFTS_PER_DAY = 8  # drafts to deliver to Telegram each run


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
    # No hard disqualifier in QT mode — let score reflect quality. Small accounts
    # still useful (their QT appears in search), big brands offer reach.
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


DONNA_FEW_SHOTS = """
Examples of authentic Donna replies to B2B/tech tweets (study the cadence):

TWEET: "AI is going to replace all customer service reps by 2027."
REPLY: No it isn\'t. It\'ll replace the 40% of tickets that are tier-1 password resets and order status. The other 60% will get better humans, paid more, talking to fewer angry people. Le Marquier ran the test. 98% automated, headcount went up.

TWEET: "Just had the worst hold experience of my life. 47 minutes."
REPLY: Your time is the cheapest thing they\'re spending. That\'s the entire problem. Call us. We\'ll fix it in a week.

TWEET: "RAG vs fine-tuning, which is the winning approach for production?"
REPLY: Neither is the answer. Routing is. Le Marquier runs intent-classified handoffs to small specialist prompts. 4-minute average call. The vector store hasn\'t been touched in three months and nobody\'s noticed.

TWEET: "Hot take: voice AI sucks at handling angry customers."
REPLY: The angry ones are the easy ones. They know what they want and they say it loud. The hard ones are the polite people who already gave up. Those are the ones that churn. Build for them.

TWEET: "Why are call centers still using IVR in 2026?"
REPLY: Because the people who buy IVR don\'t have to use it. Build the thing the CEO\'s mother would actually call. Le Marquier did. Conversion went up 31%.

TWEET: "We just hit 1000 MRR! 🎉"
REPLY: Nice. Next number is 10k, and it\'s not 10x harder. It\'s the same one customer, ten times. Pick the customer carefully.

TWEET: "Anyone else exhausted by AI hype?"
REPLY: The hype\'s fine. The problem is everyone\'s selling the same demo. Show me a phone number that picks up at 2am and closes a sale. That\'s the only AI worth being excited about.

Notice: short declarative sentences. Present tense. "No" as a complete response. One specific number when natural. Last word lands. Never asks "thoughts?". Never says "obviously" / "thrilled" / "leverage".
"""


def draft_reply(env: dict[str, str], author_handle: str, tweet_text: str, is_qt: bool = False) -> str:
    soul = SOUL_PATH.read_text() if SOUL_PATH.exists() else ""
    mode = "quote-tweet" if is_qt else "reply"
    system = (
        "You write as Donna Paulsen from Suits — TV character, sharp, knowing, never apologetic — "
        "posting on Twitter as @voxdonna (B2B AI voice-agent company).\n\n"
        "BRAND VOICE FULL DOC (read carefully — sections 4 and 5 are non-negotiable):\n"
        + soul +
        "\n\n" + DONNA_FEW_SHOTS +
        f"\n\nNow write the next {mode}. Hard rules:\n"
        "1. Output ONLY the reply text. No preamble like \"Here\'s a reply:\" or \"Sure!\".\n"
        "2. ≤280 chars total. Count strictly.\n"
        "3. ZERO em-dashes. Use period, comma, or three-dot pause.\n"
        "4. ZERO AI-vocab: delve, robust, comprehensive, nuanced, leverage, pivotal, landscape, "
        "multifaceted, intricate, foster, showcase, tapestry, underscore, interplay, furthermore, "
        "moreover, additionally, fundamental, significant, thrilled, excited, honored.\n"
        "5. ZERO weak openers: 'I think', 'I believe', 'I might be wrong', 'just', 'maybe'.\n"
        "6. ZERO closer-questions: never end with 'thoughts?', 'what do you think?', 'agree?'.\n"
        "7. First-person singular when needed. Short declarative sentences. Present tense for forecasts.\n"
        "8. One specific number if it lands naturally (Le Marquier: 2,500 calls/mo, 98% automated, "
        "80% CS cost cut, 4-min avg call). Don\'t force it.\n"
        "9. The last word must do work. Re-order so the punch lands at the end.\n"
        "10. If you can\'t write something sharp and authentically Donna, output exactly: SKIP\n"
        "\nSKIP rather than ship a mediocre reply. Under-posting beats off-voice posting."
    )
    prompt = (
        f"Tweet from @{author_handle}:\n\"{tweet_text}\"\n\n"
        f"Write Donna\'s {mode}."
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


def html_escape(s: str) -> str:
    """Minimal HTML escape for Telegram parse_mode=HTML."""
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def main() -> int:
    env = load_env()
    for k in ("ANTHROPIC_API_KEY", "TWITTER_API_KEY", "TWITTER_API_SECRET",
              "TWITTER_ACCESS_TOKEN", "TWITTER_ACCESS_TOKEN_SECRET", "TELEGRAM_BOT_TOKEN"):
        if not env.get(k): sys.exit(f"missing {k}")
    auth = x_auth(env)

    today = datetime.now(timezone.utc).date().isoformat()
    # Count drafts delivered today (idempotency across cron re-fires)
    drafts_today = 0
    if LOG.exists():
        for line in LOG.read_text().splitlines():
            try:
                r = json.loads(line)
                if r.get("date") == today and r.get("status") == "drafted":
                    drafts_today += 1
            except json.JSONDecodeError:
                continue
    if drafts_today >= DRAFTS_PER_DAY:
        print(f"daily cap reached: {drafts_today}/{DRAFTS_PER_DAY}")
        return 0
    needed = DRAFTS_PER_DAY - drafts_today

    print(f"Searching X for voice-AI / CX niche tweets (need {needed} drafts)...")
    seen_ids = set()
    all_candidates = []
    for q in SEARCH_QUERIES:
        for t in search_tweets(auth, q, hours=12, max_results=50):
            tid = t["id"]
            if tid in seen_ids or already_engaged(tid):
                continue
            seen_ids.add(tid)
            all_candidates.append(t)
        time.sleep(2)
    print(f"Found {len(all_candidates)} unique candidates.")

    # Score + sort
    scored = sorted(((score_candidate(t), t) for t in all_candidates), reverse=True, key=lambda x: x[0])

    # Send a header
    telegram_send(env, f"🐦 <b>Twitter drafts ready</b> ({today})\n\n"
                       f"Searching delivered {len(all_candidates)} candidates. "
                       f"Pushing top {needed} to you below. Copy reply → tap tweet link → paste → post. "
                       f"15 sec per draft.")

    delivered = 0
    skipped_validation = 0
    for score, t in scored:
        if delivered >= needed:
            break
        if score < 5:
            continue
        author = t["_author"]
        handle = author.get("username", "unknown")
        followers = (author.get("public_metrics") or {}).get("followers_count", 0)
        tweet_text = t["text"]
        tweet_id = t["id"]
        tweet_url = f"https://x.com/{handle}/status/{tweet_id}"

        print(f"\n[score={score:.0f}] @{handle} ({followers}f) {tweet_id}")
        try:
            draft = draft_reply(env, handle, tweet_text, is_qt=False)
        except Exception as exc:
            print(f"  ✗ Claude err: {exc}")
            log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                       "author": handle, "reply_to_id": tweet_id, "status": "claude_fail",
                       "error": str(exc)[:200]})
            continue
        issues = validate(draft)
        if issues:
            print(f"  ✗ validate: {issues}")
            log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                       "author": handle, "reply_to_id": tweet_id, "status": "skipped",
                       "reason": ",".join(issues), "draft": draft})
            skipped_validation += 1
            continue

        # Format Telegram message for copy-paste
        # Use <code> blocks for the reply so user can tap to copy on mobile
        delivered += 1
        msg = (
            f"<b>📝 Draft {delivered}/{needed}</b>\n\n"
            f"<b>Target:</b> @{handle} ({followers:,}f)\n"
            f"<b>Their post:</b>\n<i>{html_escape(tweet_text[:280])}</i>\n\n"
            f"<b>Donna reply ({len(draft)}c) — tap to copy:</b>\n"
            f"<code>{html_escape(draft)}</code>\n\n"
            f"<b>🔗 Open tweet:</b> {tweet_url}"
        )
        telegram_send(env, msg)
        log_entry({"date": today, "ts": datetime.now(timezone.utc).isoformat(),
                   "author": handle, "reply_to_id": tweet_id, "status": "drafted",
                   "follower_count": followers, "score": score, "text": draft,
                   "tweet_url": tweet_url})
        print(f"  ✓ drafted @{handle}: {draft[:100]}...")

    # Final digest
    final = f"✅ <b>{delivered} drafts delivered</b>"
    if skipped_validation:
        final += f" ({skipped_validation} skipped on voice-validation)"
    final += f"\n\nGo through them whenever. Drafts older than 24h start to age out of Phoenix-window reach."
    telegram_send(env, final)

    print(f"\nDone. {delivered} drafted, {skipped_validation} skipped.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
