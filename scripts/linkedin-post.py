#!/usr/bin/env python3
"""linkedin-post.py — publish the next queued LinkedIn post to @voxdonna Company Page via Publer.

Why Publer (and not Unipile)?
  Unipile docs were inconsistent on company-page posting. Empirical tests landed
  posts on the connected user's personal profile despite `as_organization` URN.
  Publer is purpose-built for company-page scheduling and has official LinkedIn
  Pages API integration. Endpoint shape verified via Context7 (Publer docs).

Endpoint:
  POST https://app.publer.com/api/v1/posts/schedule
Headers:
  Authorization: Bearer-API <key>
  Publer-Workspace-Id: <workspace>
  Content-Type: application/json
Body: nested `bulk.posts[].networks.linkedin{type:status, text}` + `accounts[].id`

Safety (HARD-WIRED):
  - Account ID used MUST equal the Voxdonna company page ID from
    voxdonna/data/publer_voxdonna_page_id.txt. No fallback.
  - BANLIST of known personal-profile IDs (Suyash Raj). If the page-id file
    ever contains a banned ID, script refuses to post.
  - After POST, the Publer response is inspected for the account ID it used.
    If not confirmed, no queue advancement + Telegram alert.

Env (read from ~/.openclaw/.env, gitignored):
  PUBLER_API_KEY, PUBLER_WORKSPACE_ID, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

Usage:
  linkedin-post.py            # publish next; exit 0 ok, 1 fail, 2 empty queue
  linkedin-post.py --dry-run  # validate body + show request, no API call
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path("/home/suyashraj/clawd/voxdonna")
QUEUE = ROOT / "linkedin" / "queue.md"
POSTED = ROOT / "linkedin" / "posted.md"
DATA = ROOT / "data"
PAGE_ID_FILE = DATA / "publer_voxdonna_page_id.txt"

PUBLER_BASE = "https://app.publer.com/api/v1"

# HARD banlist — these account IDs are personal profiles, must NEVER receive posts.
PERSONAL_PROFILE_BANLIST = {
    "5ecbc9aadb27975718ddc4e3",  # Suyash Raj personal LinkedIn (in_profile)
}

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
    parts = [f"## {h}\n{b}" for h, b in blocks]
    QUEUE.write_text("\n---\n".join(parts) + "\n---\n")


def append_posted(heading: str, body: str, post_url: str | None, publer_id: str | None) -> None:
    POSTED.parent.mkdir(parents=True, exist_ok=True)
    POSTED.touch(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    meta = []
    if post_url:
        meta.append(f"link: {post_url}")
    if publer_id:
        meta.append(f"publer_id: {publer_id}")
    meta_line = ("\n" + "\n".join(meta)) if meta else ""
    entry = f"## {heading} — {ts}{meta_line}\n{body}\n---\n"
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


def publer_post(env: dict[str, str], text: str, account_id: str) -> tuple[int, dict, str]:
    """POST to Publer /posts/schedule/publish for IMMEDIATE publish (not scheduled).
    Returns the job_id; caller must poll job_status to confirm placement."""
    headers = {
        "Authorization": f"Bearer-API {env['PUBLER_API_KEY']}",
        "Publer-Workspace-Id": env["PUBLER_WORKSPACE_ID"],
        "Content-Type": "application/json",
        "accept": "application/json",
    }
    payload = {
        "bulk": {
            "state": "publish",
            "posts": [
                {
                    "networks": {
                        "linkedin": {
                            "type": "status",
                            "text": text,
                        }
                    },
                    "accounts": [{"id": account_id}],
                }
            ],
        }
    }
    r = requests.post(f"{PUBLER_BASE}/posts/schedule/publish", headers=headers, json=payload, timeout=30)
    try:
        data = r.json()
    except json.JSONDecodeError:
        data = {"raw": r.text[:400]}
    return r.status_code, data, r.text


def publer_job_wait(env: dict[str, str], job_id: str, max_wait_sec: int = 60) -> dict:
    """Poll Publer job_status until complete or failed. Returns final payload."""
    import time
    headers = {
        "Authorization": f"Bearer-API {env['PUBLER_API_KEY']}",
        "Publer-Workspace-Id": env["PUBLER_WORKSPACE_ID"],
        "accept": "application/json",
    }
    url = f"{PUBLER_BASE}/job_status/{job_id}"
    deadline = time.time() + max_wait_sec
    last = {}
    while time.time() < deadline:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code != 200:
            return {"status": "http_error", "code": r.status_code, "body": r.text[:300]}
        last = r.json()
        if last.get("status") in ("complete", "completed", "failed"):
            return last
        time.sleep(3)
    return {"status": "timeout", "last": last}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    env = load_env()
    if not env.get("PUBLER_API_KEY") or not env.get("PUBLER_WORKSPACE_ID"):
        sys.exit("missing PUBLER_API_KEY or PUBLER_WORKSPACE_ID in env")

    if not PAGE_ID_FILE.exists():
        sys.exit(f"missing {PAGE_ID_FILE} (Voxdonna company page account id)")
    page_id = PAGE_ID_FILE.read_text().strip()

    # HARD safety: refuse if page_id is in the personal-profile banlist
    if page_id in PERSONAL_PROFILE_BANLIST:
        sys.exit(f"REFUSING: page_id {page_id} is on the personal-profile banlist")
    # HARD safety: page_id format check (Publer ids are 24 hex)
    if not re.fullmatch(r"[0-9a-f]{24}", page_id):
        sys.exit(f"REFUSING: page_id {page_id!r} doesn't look like a Publer account id (24 hex)")

    queue = load_queue()
    if not queue:
        print("queue empty; nothing to post")
        return 2

    heading, body = queue[0]
    issues = validate(body)

    print(f"--- next post ---")
    print(f"heading: {heading}")
    print(f"length: {len(body)} chars")
    print(f"target account: {page_id} (Voxdonna company page)")
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

    code, data, raw = publer_post(env, body, page_id)
    if code not in (200, 201):
        print(f"\nFAILED HTTP {code} on /posts/schedule/publish: {raw[:600]}", file=sys.stderr)
        telegram_send(env, f"❌ LinkedIn post failed HTTP {code}\n<b>{heading}</b>\n{raw[:200]}")
        return 1

    job_id = data.get("job_id")
    if not job_id:
        print(f"\nSAFETY: Publer accepted but returned no job_id: {raw[:400]}", file=sys.stderr)
        return 1
    print(f"\nsubmit ✓ ({code}) job_id={job_id} — polling for completion...")

    result = publer_job_wait(env, job_id, max_wait_sec=90)
    status = result.get("status")
    payload = result.get("payload") or {}
    failures = payload.get("failures") or {}
    successes = payload.get("successes") or {}

    if status not in ("complete", "completed"):
        print(f"\nSAFETY: job didn't complete cleanly: status={status} result={json.dumps(result)[:400]}", file=sys.stderr)
        telegram_send(env, f"⚠️ LinkedIn post: Publer job {status}, no placement confirmation.\n<b>{heading}</b>")
        return 1

    if failures:
        # Job completed but the post failed (e.g. no timeslot, account issue, etc)
        fail_msg = json.dumps(failures)[:500]
        print(f"\nFAILED on Publer side: {fail_msg}", file=sys.stderr)
        telegram_send(env, f"❌ LinkedIn post failed at Publer worker\n<b>{heading}</b>\n{fail_msg}")
        return 1

    # Verify the response references our account_id in successes
    success_str = json.dumps(successes)
    payload_str = json.dumps(payload)
    if page_id not in payload_str:
        print(f"\nSAFETY ALERT: completed job has no failures but payload doesn't reference page_id {page_id}", file=sys.stderr)
        print(f"  payload: {payload_str[:600]}", file=sys.stderr)
        telegram_send(env, f"⚠️ LinkedIn post: job complete but account confirmation missing. Check Voxdonna page manually.\n<b>{heading}</b>\nPayload: {payload_str[:300]}")
        return 1

    # All good
    publer_post_id = None
    try:
        for k, v in successes.items():
            if isinstance(v, list) and v:
                publer_post_id = v[0].get("id") or v[0].get("post_id")
                break
            if isinstance(v, dict):
                publer_post_id = v.get("id") or v.get("post_id")
                break
    except Exception:
        pass

    append_posted(heading, body, None, publer_post_id or job_id)
    write_remaining(queue[1:])
    print(f"\nposted ✓ job_id={job_id} publer_post_id={publer_post_id}")
    telegram_send(env, f"📰 LinkedIn post published on Voxdonna company page via Publer\n<b>{heading}</b>\nPubler id: {publer_post_id or job_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
