#!/usr/bin/env python3
"""Rewrite the retired /blog-post.html?post=<slug>&lang=<lang> links to static URLs.

blog-post.html builds the article in the browser from a query string. Every post
has been pre-rendered to /blog/<lang>/<slug>.html since, and .htaccess 301s the
old form — so 368 in-content links across the blog sources were each costing a
redirect hop and handing Google a URL it has to follow rather than the one in
the sitemap.

A link is rewritten ONLY when blog/<lang>/<slug>.md exists on disk. Anything
that does not resolve is left exactly as it is and reported: the 301 still
catches it, and a link silently pointed at a 404 would be worse than the hop.

  python3 scripts/fix-legacy-post-links.py           # report, write nothing
  python3 scripts/fix-legacy-post-links.py --apply
"""
import collections
import glob
import pathlib
import re
import sys

ROOT = pathlib.Path(".").resolve()
LANGS = ("en", "fr", "it")

# both link syntaxes, with or without the leading slash, & or &amp;, and with
# the two parameters in either order
LEGACY = re.compile(
    r"/?blog-post\.html\?"
    r"(?:post=(?P<s1>[A-Za-z0-9._-]+)(?:&|&amp;)lang=(?P<l1>en|fr|it)"
    r"|lang=(?P<l2>en|fr|it)(?:&|&amp;)post=(?P<s2>[A-Za-z0-9._-]+)"
    r"|post=(?P<s3>[A-Za-z0-9._-]+))")


def target(slug, lang):
    return f"/blog/{lang}/{slug}.html" if (ROOT / "blog" / lang / f"{slug}.md").exists() else None


def rewrite(text, fixed, unresolved, where):
    def sub(m):
        slug = m.group("s1") or m.group("s2") or m.group("s3")
        lang = m.group("l1") or m.group("l2") or "en"
        t = target(slug, lang)
        if not t:
            unresolved[f"{slug} ({lang})"].append(where)
            return m.group(0)
        fixed[f"{lang}/{slug}"] += 1
        return t
    return LEGACY.sub(sub, text)


def main(apply):
    fixed, unresolved = collections.Counter(), collections.defaultdict(list)
    touched = 0
    # sources only. blog/*/*.html is build output of build-blog-static.js, and
    # blog-post.html's four remaining occurrences are JavaScript that builds the
    # URL at runtime, not links — both are handled where they are generated.
    targets = sorted(glob.glob("blog/*/*.md"))
    for pat in ("*.html", "industries/*.html", "jewellers/*.html", "demo/*.html", "demo/*/index.html"):
        targets += [f for f in sorted(glob.glob(pat)) if f != "blog-post.html"]
    for f in targets:
        p = pathlib.Path(f)
        orig = p.read_text(encoding="utf-8")
        new = rewrite(orig, fixed, unresolved, f)
        if new != orig:
            touched += 1
            if apply:
                p.write_text(new, encoding="utf-8")
    for k, n in sorted(fixed.items(), key=lambda kv: -kv[1])[:10]:
        print(f"{n:>4}  -> /blog/{k}.html")
    print(f"\n{sum(fixed.values())} link(s) rewritten across {touched} file(s)"
          + ("" if apply else "  [dry run]"))
    if unresolved:
        print("\nLEFT UNTOUCHED — no such .md on disk, the 301 still catches these:")
        for k, v in sorted(unresolved.items()):
            print(f"  {k}  in {sorted(set(v))}")
    return 0


sys.exit(main("--apply" in sys.argv))
