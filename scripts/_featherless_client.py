"""Shared Featherless OpenAI-compatible client for all direct-LLM-calling scripts.

Replaces direct Anthropic API calls. Use FEATHERLESS_API_KEY from env.

Models (per Featherless Premium tier, verified 2026-05-26):
- HAIKU_REPLACEMENT = "meta-llama/Meta-Llama-3.1-8B-Instruct"  (cheap, fast classification)
- SONNET_REPLACEMENT = "moonshotai/Kimi-K2.6"                  (reasoning, structured output)

If FEATHERLESS_API_KEY is missing, falls back gracefully (raises so caller can catch).

Usage:
    from _featherless_client import featherless_completion, HAIKU_REPLACEMENT, SONNET_REPLACEMENT
    text = featherless_completion(
        system="You are a classifier...",
        user="Classify this reply: ...",
        model=HAIKU_REPLACEMENT,
        max_tokens=200,
    )
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

try:
    import requests  # type: ignore
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

FEATHERLESS_URL = "https://api.featherless.ai/v1/chat/completions"
_UA = "voxdonna-hermes/1.0 (+https://voxdonna.com)"
HAIKU_REPLACEMENT = "meta-llama/Meta-Llama-3.1-8B-Instruct"
SONNET_REPLACEMENT = "moonshotai/Kimi-K2.6"


class FeatherlessError(RuntimeError):
    """Raised when Featherless API returns non-200 or unexpected payload."""


def featherless_completion(
    *,
    system: str,
    user: str,
    model: str = HAIKU_REPLACEMENT,
    max_tokens: int = 500,
    temperature: float = 0.7,
    timeout_sec: int = 60,
) -> str:
    """Call Featherless OpenAI-compatible /v1/chat/completions, return assistant text.

    Raises FeatherlessError on HTTP errors or malformed responses.
    """
    api_key = os.environ.get("FEATHERLESS_API_KEY")
    if not api_key:
        raise FeatherlessError("FEATHERLESS_API_KEY not set in env")

    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": _UA,
        "Accept": "application/json",
    }

    if _HAS_REQUESTS:
        try:
            r = requests.post(FEATHERLESS_URL, headers=headers, json=payload, timeout=timeout_sec)
        except requests.RequestException as e:
            raise FeatherlessError(f"Featherless network error: {e}") from e
        if r.status_code != 200:
            raise FeatherlessError(f"Featherless HTTP {r.status_code}: {r.text[:300]}")
        data = r.json()
    else:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(FEATHERLESS_URL, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")
            raise FeatherlessError(f"Featherless HTTP {e.code}: {body_text[:300]}") from e
        except urllib.error.URLError as e:
            raise FeatherlessError(f"Featherless network error: {e}") from e

    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError) as e:
        raise FeatherlessError(f"Featherless malformed response: {str(data)[:300]}") from e


__all__ = [
    "featherless_completion",
    "FeatherlessError",
    "HAIKU_REPLACEMENT",
    "SONNET_REPLACEMENT",
    "FEATHERLESS_URL",
]
