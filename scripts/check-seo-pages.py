#!/usr/bin/env python3
"""Validate the industry landing pages with a real HTML parser, not grep.

A grep for `rel="canonical"` is attribute-order sensitive and reports a page as
missing a tag it actually has, so every check here goes through html.parser and
json.loads. Run it on the pages named on the command line, or with no arguments
on the industry set.

  python3 scripts/check-seo-pages.py
  python3 scripts/check-seo-pages.py industries/solar-ai-agents.html
"""
import html as htmlmod
import json
import pathlib
import re
import sys
from html.parser import HTMLParser

SITE = "https://voxdonna.com"
DEFAULT = [
    "jewellers.html",
    "ai-for-manufacturers.html",
    "industries/index.html",
    "industries/real-estate-ai-agents.html",
    "industries/solar-ai-agents.html",
    "industries/kitchen-appliance-ai-agents.html",
    "industries/furniture-ai-agents.html",
]
BANNED = [
    "delve", "robust", "comprehensive", "nuanced", "multifaceted", "leverage",
    "pivotal", "landscape", "intricate", "vibrant", "fundamental", "significant",
    "revolutioniz", "revolutioniz", "cutting-edge", "unlock the power",
    "transform your business", "next-generation", "seamless", "game-chang",
]
STOP = {"a", "an", "the", "is", "are", "do", "does", "can", "will", "what", "how",
        "our", "my", "we", "it", "to", "of", "and", "or", "in", "on", "for", "with",
        "you", "your", "i", "if", "that", "this", "be", "as", "at", "by", "from"}
VOID = {"br", "img", "input", "meta", "link", "hr", "source", "path", "circle",
        "rect", "use", "area", "col", "embed", "track", "wbr", "polygon", "line",
        "ellipse", "stop", "polyline"}


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = None
        self.desc = None
        self.canonical = None
        self.robots = None
        self.lang = None
        self.og = {}
        self.twitter = None
        self.headings = []          # (level, text)
        self.links = []             # href
        self.imgs = []              # (src, alt)
        self.ldjson = []            # raw strings
        self.text_chunks = []
        self._cap = None
        self._buf = []
        self._in_ld = False
        self._stack = []
        self.unclosed = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html":
            self.lang = a.get("lang")
        if tag == "link" and "canonical" in a.get("rel", "").lower():
            self.canonical = a.get("href")
        if tag == "meta":
            n, prop = a.get("name", "").lower(), a.get("property", "").lower()
            if n == "description":
                self.desc = a.get("content")
            if n == "robots":
                self.robots = a.get("content")
            if n == "twitter:card":
                self.twitter = a.get("content")
            if prop.startswith("og:"):
                self.og[prop] = a.get("content")
        if tag == "script" and a.get("type", "").lower() == "application/ld+json":
            self._in_ld = True
            self._buf = []
        if tag == "title":
            self._cap, self._buf = "title", []
        if re.fullmatch(r"h[1-6]", tag):
            self._cap, self._buf = tag, []
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag == "img":
            self.imgs.append((a.get("src", ""), a.get("alt")))
        if tag not in VOID:
            self._stack.append(tag)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_ld:
            self.ldjson.append("".join(self._buf))
            self._in_ld = False
            self._buf = []
        if self._cap and tag == self._cap:
            text = re.sub(r"\s+", " ", "".join(self._buf)).strip()
            if self._cap == "title":
                self.title = text
            else:
                self.headings.append((int(self._cap[1]), text))
            self._cap, self._buf = None, []
        if tag in VOID:
            return
        if tag in self._stack:
            while self._stack and self._stack.pop() != tag:
                pass
        else:
            self.unclosed.append(tag)

    def handle_data(self, d):
        if self._in_ld or self._cap:
            self._buf.append(d)
        else:
            self.text_chunks.append(d)


def visible_text(p):
    """Everything a reader sees.

    Heading and <title> text is captured into its own bucket while parsing, so it
    has to be added back here. Leaving it out turned "is this FAQ question on the
    page?" into a false absence for every page that puts its questions in an <h3>.
    """
    return re.sub(r"\s+", " ", " ".join(p.text_chunks + [t for _, t in p.headings]))


def check(path, seen_titles, seen_descs):
    bad, warn = [], []
    raw = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    p = Page()
    p.feed(raw)

    want_canon = f"{SITE}/{'' if path == 'index.html' else path}"
    if path.endswith("/index.html"):
        want_canon = f"{SITE}/{path[:-len('index.html')]}"

    if p.lang != "en":
        bad.append(f'<html lang> is {p.lang!r}, expected "en"')
    if not p.title:
        bad.append("no <title>")
    elif len(p.title) > 65:
        warn.append(f"title is {len(p.title)} chars (>65): {p.title}")
    if not p.desc:
        bad.append("no meta description")
    elif not 120 <= len(p.desc) <= 165:
        warn.append(f"meta description is {len(p.desc)} chars (want 140-158)")
    if p.title in seen_titles:
        bad.append(f"duplicate <title> shared with {seen_titles[p.title]}")
    elif p.title:
        seen_titles[p.title] = path
    if p.desc in seen_descs:
        bad.append(f"duplicate meta description shared with {seen_descs[p.desc]}")
    elif p.desc:
        seen_descs[p.desc] = path

    if not p.canonical:
        bad.append("no rel=canonical")
    elif p.canonical != want_canon:
        bad.append(f"canonical is {p.canonical}, expected {want_canon}")
    if not p.robots:
        warn.append("no meta robots")
    elif "noindex" in p.robots:
        bad.append(f"page is noindex: {p.robots}")

    for k in ("og:type", "og:url", "og:title", "og:description", "og:image"):
        if not p.og.get(k):
            bad.append(f"missing {k}")
    if p.og.get("og:url") and p.og["og:url"] != want_canon:
        bad.append(f"og:url is {p.og['og:url']}, expected {want_canon}")
    if not p.twitter:
        warn.append("no twitter:card")

    h1s = [t for lvl, t in p.headings if lvl == 1]
    if len(h1s) != 1:
        bad.append(f"{len(h1s)} <h1> elements, expected exactly 1")
    prev = 0
    for lvl, t in p.headings:
        if prev and lvl > prev + 1:
            bad.append(f"heading jumps h{prev} -> h{lvl} at {t[:50]!r}")
        prev = lvl

    for src, alt in p.imgs:
        if alt is None:
            bad.append(f"<img> without alt: {src[:60]}")
        elif not alt.strip():
            warn.append(f"<img> with empty alt: {src[:60]}")

    if p.unclosed:
        warn.append(f"stray closing tags: {sorted(set(p.unclosed))}")

    # --- JSON-LD ---
    faq_qs = []
    if not p.ldjson:
        bad.append("no JSON-LD block")
    for i, blob in enumerate(p.ldjson):
        try:
            data = json.loads(blob)
        except json.JSONDecodeError as e:
            bad.append(f"JSON-LD block {i} is invalid JSON: {e}")
            continue
        nodes = data.get("@graph", [data]) if isinstance(data, dict) else data
        types = [n.get("@type") for n in nodes if isinstance(n, dict)]
        for forbidden in ("Review", "AggregateRating"):
            if forbidden in types:
                bad.append(f"JSON-LD contains {forbidden} (fabricated review schema is banned)")
        for n in nodes:
            if not isinstance(n, dict):
                continue
            if n.get("@type") == "FAQPage":
                for q in n.get("mainEntity", []):
                    name = (q or {}).get("name", "")
                    ans = ((q or {}).get("acceptedAnswer") or {}).get("text", "")
                    faq_qs.append((name, ans))
                    if not ans.strip():
                        bad.append(f"FAQ answer empty for {name[:50]!r}")
            if n.get("@type") == "BreadcrumbList":
                items = n.get("itemListElement", [])
                if len(items) < 2:
                    warn.append("BreadcrumbList has fewer than 2 items")
                for it in items:
                    tgt = it.get("item")
                    if isinstance(tgt, str) and not tgt.startswith("http"):
                        bad.append(f"breadcrumb item is not absolute: {tgt}")

    body = visible_text(p)
    body_norm = re.sub(r"\s+", " ", htmlmod.unescape(body)).lower()
    # Schema validity and schema eligibility are different properties. A FAQPage
    # block parses fine whether or not the questions appear on the page, so the
    # only check that can tell a compliant page from a violating one is against
    # the rendered body. Distinguish the two failure modes: a question that is
    # simply absent needs an FAQ section written, one that is present but reworded
    # needs six words aligned.
    for q, _ in faq_qs:
        probe = re.sub(r"\s+", " ", htmlmod.unescape(q)).strip().lower()
        if not probe or probe in body_norm:
            continue
        content = [w for w in re.findall(r"[a-z0-9]+", probe) if w not in STOP]
        hits = sum(1 for w in set(content) if w in body_norm)
        if content and hits / len(set(content)) >= 0.6:
            bad.append(f"FAQ question in JSON-LD is reworded on the page (must match exactly): {q[:60]!r}")
        else:
            bad.append(f"FAQ question in JSON-LD has no visible counterpart: {q[:60]!r}")

    for w in set(BANNED):
        if re.search(rf"\b{re.escape(w)}", body_norm):
            warn.append(f"banned word on page: {w!r}")

    # --- internal links resolve ---
    root = pathlib.Path(".").resolve()
    here = pathlib.Path(path).parent
    for href in p.links:
        if href.startswith(("http", "mailto:", "tel:", "#", "javascript:", "data:")):
            continue
        target = href.split("#")[0].split("?")[0]
        if not target:
            continue
        fs = (root / target.lstrip("/")) if href.startswith("/") else (root / here / target)
        if target.endswith("/"):
            fs = fs / "index.html"
        if not fs.exists():
            bad.append(f"internal link 404: {href}")

    return bad, warn


def main():
    targets = sys.argv[1:] or DEFAULT
    seen_titles, seen_descs = {}, {}
    total_bad = 0
    for t in targets:
        if not pathlib.Path(t).exists():
            print(f"\n=== {t}\n  MISSING  file does not exist")
            total_bad += 1
            continue
        bad, warn = check(t, seen_titles, seen_descs)
        total_bad += len(bad)
        print(f"\n=== {t}  ({len(bad)} error, {len(warn)} warn)")
        for b in bad:
            print(f"  ERROR  {b}")
        for w in warn:
            print(f"  warn   {w}")
    print(f"\n{total_bad} error(s) across {len(targets)} page(s)")
    return 1 if total_bad else 0


if __name__ == "__main__":
    sys.exit(main())
