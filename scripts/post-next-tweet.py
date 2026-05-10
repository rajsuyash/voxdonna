#!/usr/bin/env python3
"""
Post the next queued tweet from tweets/queue.md to @voxdonna.

Reads the first ## heading + body from queue.md, posts it via X API v2,
moves the posted tweet block to tweets/posted.md with a timestamp.

Tweet format in queue.md:
    ## tweet 001
    Tweet body here. Keep under 280 chars.
    Multiple lines OK as long as total length <= 280.
    ---

Each tweet is delimited by `---` on its own line. Heading line is ignored.
Empty queue → exit 0 (no error, just nothing to post).
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests_oauthlib import OAuth1

ROOT = Path(__file__).resolve().parent.parent
QUEUE = ROOT / "tweets" / "queue.md"
POSTED = ROOT / "tweets" / "posted.md"
X_API_URL = "https://api.x.com/2/tweets"


def load_queue() -> list[tuple[str, str]]:
    """Return list of (heading, body) tuples in queue order."""
    if not QUEUE.exists():
        return []
    raw = QUEUE.read_text()
    if not raw.strip():
        return []
    blocks = [b.strip() for b in raw.split("\n---\n") if b.strip()]
    out: list[tuple[str, str]] = []
    for block in blocks:
        lines = block.splitlines()
        heading = ""
        body_lines: list[str] = []
        for ln in lines:
            if not heading and ln.startswith("##"):
                heading = ln.lstrip("#").strip()
                continue
            body_lines.append(ln)
        body = "\n".join(body_lines).strip()
        if body:
            out.append((heading, body))
    return out


def write_remaining(blocks: list[tuple[str, str]]) -> None:
    if not blocks:
        QUEUE.write_text("")
        return
    parts = []
    for heading, body in blocks:
        parts.append(f"## {heading}\n{body}")
    QUEUE.write_text("\n---\n".join(parts) + "\n")


def append_posted(heading: str, body: str, tweet_id: str) -> None:
    POSTED.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    entry = (
        f"## {heading} — {ts} — id:{tweet_id}\n"
        f"https://x.com/voxdonna/status/{tweet_id}\n"
        f"{body}\n---\n"
    )
    if POSTED.exists():
        POSTED.write_text(entry + POSTED.read_text())
    else:
        POSTED.write_text(entry)


def post_tweet(text: str, auth: OAuth1) -> str:
    response = requests.post(
        X_API_URL,
        json={"text": text},
        auth=auth,
        timeout=30,
    )
    if response.status_code != 201:
        raise RuntimeError(
            f"X API error {response.status_code}: {response.text}"
        )
    return str(response.json()["data"]["id"])


def main() -> int:
    queue = load_queue()
    if not queue:
        print("queue empty — nothing to post")
        return 0

    heading, body = queue[0]
    if len(body) > 280:
        print(
            f"ERROR: tweet '{heading}' is {len(body)} chars (max 280). Skipping.",
            file=sys.stderr,
        )
        return 1

    if os.environ.get("DRY_RUN") == "1":
        print(f"DRY RUN — would post tweet '{heading}' ({len(body)} chars):")
        print(f"---\n{body}\n---")
        print(f"\nNext in queue after this: {len(queue) - 1} tweet(s)")
        return 0

    auth = OAuth1(
        os.environ["TWITTER_API_KEY"],
        os.environ["TWITTER_API_SECRET"],
        os.environ["TWITTER_ACCESS_TOKEN"],
        os.environ["TWITTER_ACCESS_TOKEN_SECRET"],
    )

    tweet_id = post_tweet(body, auth)
    print(f"posted tweet id={tweet_id}")
    print(f"https://x.com/voxdonna/status/{tweet_id}")

    append_posted(heading, body, tweet_id)
    write_remaining(queue[1:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
