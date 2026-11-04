#!/usr/bin/env python3
"""Install one analytics snippet on every indexable page of the site.

Usage:
  python3 scripts/add-analytics.py G-XXXXXXXXXX          # Google Analytics 4
  python3 scripts/add-analytics.py G-XXXXXXXXXX --check  # report only, write nothing
  python3 scripts/add-analytics.py --remove              # take the snippet back out

The tag goes immediately before </head> on every .html file that is not marked
noindex, including the generated blog posts. Re-running is safe: a page that
already carries the snippet is skipped, and a different measurement ID replaces
the old one rather than stacking a second tag.
"""
import argparse
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import pathlib
import re
import sys

MARK_OPEN = "<!-- analytics: managed by scripts/add-analytics.py -->"
MARK_CLOSE = "<!-- /analytics -->"
BLOCK = """{open}
<script defer src="/assets/analytics.js?v=20261104b" data-measurement-id="{mid}"></script>
{close}
"""


def pages():
    # The sitemap defines the public surface; the template covers future blog posts.
    paths = {pathlib.Path("blog-post.html")}
    for element in ET.parse("sitemap.xml").getroot().findall(".//{*}loc"):
        url = urlparse(element.text or "")
        if url.hostname != "voxdonna.com":
            continue
        path = pathlib.Path(url.path.lstrip("/") or "index.html")
        if ".." in path.parts:
            raise ValueError("Unsafe sitemap path")
        if path.is_dir():
            path /= "index.html"
        if path.suffix == ".html" and path.is_file():
            paths.add(path)
    return sorted(paths)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("measurement_id", nargs="?", help="GA4 measurement ID, e.g. G-ABCD123456")
    ap.add_argument("--check", action="store_true", help="report what would change, write nothing")
    ap.add_argument("--remove", action="store_true", help="remove a previously installed snippet")
    a = ap.parse_args()

    if not a.remove:
        if not a.measurement_id:
            ap.error("a measurement ID is required unless --remove is given")
        if not re.fullmatch(r"G-[A-Z0-9]{6,12}", a.measurement_id):
            ap.error(f"'{a.measurement_id}' is not a GA4 measurement ID (expected G-XXXXXXXXXX)")

    added = replaced = skipped_noindex = removed = unchanged = 0
    for p in pages():
        path = pathlib.Path(p)
        html = path.read_text(encoding="utf-8", errors="replace")
        existing = re.search(re.escape(MARK_OPEN) + r".*?" + re.escape(MARK_CLOSE) + r"\n?", html, re.S)

        if a.remove:
            if existing:
                html = html.replace(existing.group(0), "")
                removed += 1
                if not a.check:
                    path.write_text(html, encoding="utf-8")
            continue

        if path.name != "blog-post.html" and re.search(r'<meta[^>]+name=["\']robots["\'][^>]+noindex', html, re.I):
            skipped_noindex += 1
            continue
        if "</head>" not in html:
            continue

        block = BLOCK.format(open=MARK_OPEN, close=MARK_CLOSE, mid=a.measurement_id)
        if existing:
            if existing.group(0) == block:
                unchanged += 1
                continue
            html = html.replace(existing.group(0), block)
            replaced += 1
        else:
            html = html.replace("</head>", block + "</head>", 1)
            added += 1
        if not a.check:
            path.write_text(html, encoding="utf-8")

    verb = "would " if a.check else ""
    if a.remove:
        print(f"{verb}removed from {removed} pages")
    else:
        print(f"{verb}added to {added} pages, {verb}replaced on {replaced}, "
              f"already current on {unchanged}, skipped {skipped_noindex} noindex pages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
