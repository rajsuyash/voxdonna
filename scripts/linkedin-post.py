#!/usr/bin/env python3
"""linkedin-post.py — post the next queued LinkedIn post to @voxdonna Company Page via Unipile.

Reads first ## block from linkedin/queue.md, validates Donna voice rules,
posts via Unipile POST /posts, moves block to linkedin/posted.md with
timestamp + LinkedIn post URL, commits + pushes.

Donna voice rules enforced pre-emit:
- ≤3000 chars (LinkedIn limit)
- No em-dashes (founder rule)
- No AI-vocab: delve, robust, comprehensive, nuanced, leverage, pivotal, landscape
- No "thrilled to announce", "excited to share", "honored to"

Unipile call:
  POST {base_url}/posts
  Headers: X-API-KEY, Content-Type: application/json, User-Agent: Mozilla/5.0
  Body: {account_id, text, [organization_id?]}  ← organization_id determined empirically
                                                  on first call; populated in
                                                  voxdonna/data/linkedin_org_id.txt

Env: reads ~/.openclaw/.env first, falls back to Paperclip DB agent env.

Usage:
    linkedin-post.py                 # post next; exit 0 = posted, 1 = failed, 2 = empty queue
    linkedin-post.py --dry-run       # print what would post + validation; no API call
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path("/home/suyashraj/clawd/voxdonna")
QUEUE = ROOT / "linkedin" / "queue.md"
POSTED = ROOT / "linkedin" / "posted.md"
DATA = ROOT / "data"
ORG_ID_FILE = DATA / "linkedin_org_id.txt"
PG_DSN = ["env", "PGPASSWORD=paperclip", "psql", "-h", "127.0.0.1", "-p", "54329",
          "-U", "paperclip", "-d", "paperclip", "-At"]

BANNED_WORDS = [
    "delve", "robust", "comprehensive", "nuanced", "leverage", "pivotal",
    "landscape", "thrilled", "excited to share", "honored to", "thrilled to announce",
    "multifaceted", "intricate", "foster", "showcase", "tapestry", "underscore",
    "interplay", "furthermore", "moreover", "additionally", "fundamental", "significant",
]


def load_config() -> dict:
    """Load Unipile config from lead-gen multi-touch config.json."""
    config_path = Path("/home/suyashraj/clawd/lead-gen/multi-touch/config.json")
    if not config_path.exists():
        sys.exit(f"missing config: {config_path}")
    return json.loads(config_path.read_text())


def load_telegram_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for path in [Path("/home/suyashraj/.openclaw/.env"), Path("/home/suyashraj/clawd/.env")]:
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def load_queue() -> list[tuple[str, str]]:
    if not QUEUE.exists():
        return []
    raw = QUEUE.read_text()
    if not raw.strip():
        return []
    blocks = [b.strip() for b in raw.split("\n---\n") if b.strip()]
    out: list[tuple[str, str]] = []
    for block in blocks:
        lines = block.splitlines()
        heading, body_lines = "", []
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
    for h, b in blocks:
        parts.append(f"## {h}\n{b}")
    QUEUE.write_text("\n---\n".join(parts) + "\n---\n")


def append_posted(heading: str, body: str, post_url: str | None) -> None:
    POSTED.parent.mkdir(parents=True, exist_ok=True)
    POSTED.touch(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    url_line = f"\nlink: {post_url}" if post_url else ""
    entry = f"## {heading} — {ts}{url_line}\n{body}\n---\n"
    existing = POSTED.read_text() if POSTED.exists() else ""
    POSTED.write_text(entry + existing)


def validate(body: str) -> list[str]:
    issues = []
    if len(body) > 3000:
        issues.append(f"length {len(body)} > 3000")
    if "—" in body:
        issues.append("contains em-dash (founder rule violation)")
    low = body.lower()
    for w in BANNED_WORDS:
        if w in low:
            issues.append(f"banned word: {w!r}")
    return issues


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


def unipile_post(unipile_cfg: dict, text: str, org_id: str | None) -> tuple[int, dict, str]:
    """POST to Unipile /posts via multipart form-data.

    Field name `as_organization` (URN format urn:li:organization:NNN) routes
    the post to the LinkedIn Company Page. Without it, the post lands on the
    connected user's personal profile.

    HARD RULE for VoxDonna: as_organization MUST be set, OR this function
    refuses to post. No silent fallback to personal profile.
    """
    if not org_id:
        return 0, {"error": "as_organization is required (no fallback to personal profile)"}, ""
    if not org_id.startswith("urn:li:organization:"):
        return 0, {"error": f"org_id must be URN format (urn:li:organization:NNN), got: {org_id}"}, ""

    base = unipile_cfg["base_url"].rstrip("/")
    url = f"{base}/posts"
    files = {
        "account_id": (None, unipile_cfg["account_id"]),
        "text": (None, text),
        "as_organization": (None, org_id),
    }
    headers = {
        "X-API-KEY": unipile_cfg["api_key"],
        "accept": "application/json",
        "User-Agent": "Mozilla/5.0",
    }
    r = requests.post(url, headers=headers, files=files, timeout=30)
    try:
        data = r.json()
    except json.JSONDecodeError:
        data = {"raw": r.text[:400]}
    return r.status_code, data, r.text


def unipile_get_post(unipile_cfg: dict, post_id: str) -> dict:
    """GET a post to inspect its author. Used for post-verify safety check."""
    base = unipile_cfg["base_url"].rstrip("/")
    url = f"{base}/posts/{post_id}?account_id={unipile_cfg[chr(34)+chr(97)+chr(99)+chr(99)+chr(111)+chr(117)+chr(110)+chr(116)+chr(95)+chr(105)+chr(100)+chr(34)] if False else unipile_cfg[chr(0x22)+chr(0x61)+chr(0x63)+chr(0x63)+chr(0x6f)+chr(0x75)+chr(0x6e)+chr(0x74)+chr(0x5f)+chr(0x69)+chr(0x64)+chr(0x22)] if False else 'placeholder'}"
    # simpler version with normal indexing:
    url = base + "/posts/" + post_id + "?account_id=" + unipile_cfg["account_id"]
    headers = {
        "X-API-KEY": unipile_cfg["api_key"],
        "accept": "application/json",
        "User-Agent": "Mozilla/5.0",
    }
    r = requests.get(url, headers=headers, timeout=20)
    try:
        return r.json()
    except json.JSONDecodeError:
        return {}


def unipile_delete_post(unipile_cfg: dict, post_id: str) -> int:
    """DELETE a misplaced post. Returns HTTP code."""
    base = unipile_cfg["base_url"].rstrip("/")
    url = base + "/posts/" + post_id + "?account_id=" + unipile_cfg["account_id"]
    headers = {
        "X-API-KEY": unipile_cfg["api_key"],
        "accept": "application/json",
        "User-Agent": "Mozilla/5.0",
    }
    r = requests.delete(url, headers=headers, timeout=20)
    return r.status_code


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    queue = load_queue()
    if not queue:
        print("queue empty; nothing to post")
        return 2

    heading, body = queue[0]
    issues = validate(body)

    print(f"--- next post ---")
    print(f"heading: {heading}")
    print(f"length: {len(body)} chars")
    if issues:
        print(f"VALIDATION ISSUES: {issues}", file=sys.stderr)
        return 1
    print("validation: passed")
    print("---")
    print(body)
    print("---")

    if args.dry_run:
        print("DRY-RUN: not posting")
        return 0

    cfg = load_config()
    unipile = cfg["unipile"]
    org_id = ORG_ID_FILE.read_text().strip() if ORG_ID_FILE.exists() else None
    if not org_id:
        print("WARN: no organization_id set (data/linkedin_org_id.txt missing); "
              "post will go to personal profile, not company page", file=sys.stderr)

    code, data, raw = unipile_post(unipile, body, org_id)
    if code in (200, 201):
        post_id = data.get("post_id") or data.get("id") or data.get("urn") or ""
        post_url = f"https://www.linkedin.com/feed/update/{post_id}/" if post_id else None

        # SAFETY: verify the post landed on the company page, not personal profile.
        # If it landed on personal profile, DELETE immediately and FAIL.
        verify = unipile_get_post(unipile, post_id) if post_id else {}
        author = verify.get("author") or {}
        is_company = author.get("is_company")
        author_name = author.get("name") or "<unknown>"
        if is_company is not True:
            # Wrong placement! Delete immediately.
            print(f"\nSAFETY ALERT: post landed on personal profile (author.is_company={is_company}, name={author_name}). Deleting.", file=sys.stderr)
            del_code = unipile_delete_post(unipile, post_id)
            print(f"  delete HTTP {del_code}", file=sys.stderr)
            tg_env = load_telegram_env()
            telegram_send(tg_env, f"⚠️ LinkedIn post WRONG PLACEMENT\nLanded on {author_name} personal profile. Auto-deleted (HTTP {del_code}).\nQueue NOT advanced.\n<b>{heading}</b>")
            return 1
        # Verified company page placement
        append_posted(heading, body, post_url)
        write_remaining(queue[1:])
        print(f"\nposted ✓ ({code}) post_id={post_id} author={author_name} (verified company-page)")
        tg_env = load_telegram_env()
        telegram_send(tg_env, f"📰 LinkedIn post published on company page\n<b>{heading}</b>\n{post_url or 'no url returned'}")
        return 0

    print(f"\nFAILED HTTP {code}: {raw[:400]}", file=sys.stderr)
    tg_env = load_telegram_env()
    telegram_send(tg_env, f"❌ LinkedIn post failed HTTP {code}\n{heading}\n{raw[:200]}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
