#!/usr/bin/env python3
"""Put the same header and footer on every page of the site.

The site had 16 different navigations and 20 different footers because every
page carried its own hand-written copy. This owns both from one place: edit the
templates below, re-run, and all 75-odd pages plus the 136 generated blog posts
follow.

What it touches, and what it deliberately does not:

  footer   replaced on every indexable page. The template is the superset of
           what the old footers carried, so nothing is lost. data-i18n keys are
           kept, and the translator ignores keys it does not know, so index.html
           still translates and other pages are unaffected.
  header   injected ONLY on pages that have no <nav> of their own. Existing
           navigations are wired into page-specific JS (language toggle, mobile
           overlay, scroll state); replacing them wholesale is how you break a
           site. Pages that already have a product menu get the missing
           Resources group added in place instead — see --fix-menus.
  skipped  noindex pages (the three dashboards, the mock-site demos, the
           private prospect pages) and everything under for/, which are bespoke
           client proposals rather than marketing pages.

Usage:
  python3 scripts/build-chrome.py --check      # report, write nothing
  python3 scripts/build-chrome.py              # footer everywhere, nav on bare pages
  python3 scripts/build-chrome.py --fix-menus  # also add Resources to short menus

After running, rebuild the generated pages so they pick the new chrome up:
  node scripts/build-blog-static.js
"""
import argparse
import glob
import hashlib
import pathlib
import re
import sys
from html.parser import HTMLParser

# Stylesheets are cached for a week by .htaccess, so the link carries a hash of
# the file. Editing chrome.css changes the hash, which changes every page's
# link, which is what makes the edit visible instead of a week late.
CSS_PATH = pathlib.Path("assets/chrome.css")
CSS_VERSION = hashlib.sha256(CSS_PATH.read_bytes()).hexdigest()[:8] if CSS_PATH.exists() else "0"
CSS_LINK = f'<link rel="stylesheet" href="/assets/chrome.css?v={CSS_VERSION}">'
CSS_LINK_RE = re.compile(r'\s*<link rel="stylesheet" href="/assets/chrome\.css(?:\?v=[0-9a-f]+)?">')
F_OPEN, F_CLOSE = '<!-- vd-chrome:footer -->', '<!-- /vd-chrome:footer -->'
N_OPEN, N_CLOSE = '<!-- vd-chrome:nav -->', '<!-- /vd-chrome:nav -->'

PRODUCTS = [
    ("/ai-voice-agents.html", "AI Voice Agents"),
    ("/whatsapp-donna-agents.html", "WhatsApp Agents"),
    ("/salesdonna.html", "Sales Meeting Agents"),
    ("/rocket-sales-agent.html", "Rocket Sales Agent"),
    ("/tendercraft.html", "TenderCraft"),
    ("/procurement-intelligence.html", "Procurement Intelligence"),
    ("/customer-intelligence.html", "Customer Risk Intelligence"),
    ("/ai-for-sap.html", "AI for SAP"),
    ("/ai-for-manufacturers.html", "AI for Manufacturers"),
    ("/sap-analytics.html", "SAP AI Copilot"),
    ("/sap-email-agent.html", "Sales Order Email Agent"),
    ("/personal-assistant.html", "Voxdonna Personal Assistant"),
    ("/donna-photoshoot.html", "Donna Photoshoot"),
    ("/virtual-try-on.html", "Virtual Try-On"),
    ("https://ocr.voxdonna.com", "Prescription OCR"),
    ("https://aisewak.com/election-campaign", "Election Campaign Agents"),
]
INDUSTRIES = [
    ("/jewellers.html", "Jewellery Retail &amp; Wholesale"),
    ("/ai-for-manufacturers.html", "SAP Manufacturers"),
    ("/industries/real-estate-ai-agents.html", "Real Estate"),
    ("/industries/solar-ai-agents.html", "Rooftop Solar"),
    ("/industries/kitchen-appliance-ai-agents.html", "Kitchen &amp; Cooking Appliances"),
    ("/industries/furniture-ai-agents.html", "Luxury &amp; Outdoor Furniture"),
    ("/industries/", "All industries"),
]
SOCIAL = [
    ("https://www.linkedin.com/company/voxdonna/", "LinkedIn"),
    ("https://www.instagram.com/vox.donna/", "Instagram"),
    ("https://x.com/voxdonna", "X / Twitter"),
    ("https://www.youtube.com/@VoxdonnaAI", "YouTube"),
    ("https://www.crunchbase.com/organization/voxdonna-ai", "Crunchbase"),
]


def link(href, text, i18n=None):
    key = f' data-i18n="{i18n}"' if i18n else ""
    ext = ' target="_blank" rel="noopener"' if href.startswith("http") else ""
    return f'      <a href="{href}"{ext}{key}>{text}</a>'


def footer_html():
    products = "\n".join(link(h, t) for h, t in PRODUCTS)
    industries = "\n".join(link(h, t) for h, t in INDUSTRIES)
    social = "\n".join(link(h, t) for h, t in SOCIAL)
    return f"""{F_OPEN}
<footer class="vd-foot">
  <div class="vd-foot-grid">
    <div class="vd-foot-col">
      <div class="vd-foot-logo">Vox<span>donna</span> AI</div>
      <p class="vd-foot-tagline" data-i18n="footer.tagline">AI agents and decision systems for sales, service and industry.</p>
    </div>
    <div class="vd-foot-col">
      <div class="vd-foot-heading">Products</div>
{products}
    </div>
    <div class="vd-foot-col">
      <div class="vd-foot-heading">Industries</div>
{industries}
    </div>
    <div class="vd-foot-col">
      <div class="vd-foot-heading">Explore</div>
{link("/demos.html", "Demos", "nav.demos")}
{link("/blog.html", "Blog", "nav.blog")}
{link("/about.html", "About", "nav.about")}
{link("/index.html#pricing", "Pricing", "nav.pricing")}
    </div>
    <div class="vd-foot-col">
      <div class="vd-foot-heading" data-i18n="footer.getstarted">Get Started</div>
{link("/index.html#contact", "Book a Discovery Call", "footer.bookcall")}
{link("mailto:hello@voxdonna.com", "hello@voxdonna.com")}
{link("tel:+33076615849", "+33 07 66 15 84 99")}
    </div>
    <div class="vd-foot-col">
      <div class="vd-foot-heading">Follow</div>
{social}
    </div>
  </div>
  <div class="vd-foot-bottom">
    &copy; 2026 Donna AI Labs Private Limited. All rights reserved.
    &nbsp;&middot;&nbsp; <a href="/index.html">Home</a>
    &nbsp;&middot;&nbsp; <a href="/privacy.html">Privacy</a>
  </div>
</footer>
{F_CLOSE}
"""


def nav_html():
    products = "\n".join(link(h, t).strip() for h, t in PRODUCTS)
    products = "\n".join(f"        {l}" for l in products.splitlines())
    industries_nav = "\n".join(link(h, t).strip() for h, t in INDUSTRIES)
    industries_nav = "\n".join(f"        {l}" for l in industries_nav.splitlines())
    return f"""{N_OPEN}
<header class="vd-nav">
  <a href="/index.html" class="vd-nav-logo">
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2L2 8L12 14L22 8L12 2Z" fill="#c17f59"/>
      <path d="M2 16L12 22L22 16" stroke="#c17f59" stroke-width="2" fill="none"/>
      <path d="M2 12L12 18L22 12" stroke="#c17f59" stroke-width="2" fill="none" opacity="0.5"/>
    </svg>
    Vox<span>donna</span>
  </a>
  <ul class="vd-nav-links">
    <li class="vd-nav-drop">
      <a href="/index.html">Products <span aria-hidden="true">&#9662;</span></a>
      <div class="vd-nav-panel">
{products}
      </div>
    </li>
    <li><a href="/demos.html">Demos</a></li>
    <li class="vd-nav-drop">
      <a href="/industries/">Industries <span aria-hidden="true">&#9662;</span></a>
      <div class="vd-nav-panel">
{industries_nav}
      </div>
    </li>
    <li><a href="/blog.html">Blog</a></li>
    <li><a href="/about.html">About</a></li>
  </ul>
  <a href="/index.html#contact" class="vd-nav-cta">Book a Demo</a>
</header>
{N_CLOSE}
"""


# The Resources group that 13 product pages are missing. Their nav CSS is
# already identical to the pages that have it, and the dropdown is pure CSS,
# so this is markup-only.
RESOURCES_LI = """      <li class="nav-drop">
        <a href="#" onclick="return false" aria-haspopup="true"><span data-i18n="nav.resources">Resources</span> <span class="nd-caret">▾</span></a>
        <div class="nav-drop-panel">
          <a href="/blog.html" data-i18n="nav.blog">Blog</a>
          <a href="/about.html" data-i18n="nav.about">About</a>
        </div>
      </li>
"""
RESOURCES_MOBILE = """    <span class="mm-label" data-i18n="nav.resources">Resources</span>
    <a href="/blog.html" data-i18n="nav.blog">Blog</a>
    <a href="/about.html" data-i18n="nav.about">About</a>
"""


# Not pages a visitor reads: an image source for YouTube thumbnails, and the
# blog renderer's own shell (its output is built by build-blog-static.js).
EXCLUDE = {"youtube-thumbnail.html"}


def pages():
    seen = []
    for pattern in ("*.html", "demo/*.html", "demo/*/index.html", "industries/*.html"):
        seen.extend(sorted(glob.glob(pattern)))
    return seen


def is_noindex(html):
    return bool(re.search(r'<meta[^>]+name=["\']robots["\'][^>]+noindex', html, re.I))


class Counter(HTMLParser):
    """Re-parse what we wrote, so a bad splice is caught here and not in a browser."""

    def __init__(self):
        super().__init__()
        self.open_tags = []
        self.footers = 0
        self.foot_links = 0
        self.in_foot = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "footer" and "vd-foot" in (a.get("class") or ""):
            self.footers += 1
            self.in_foot += 1
        if tag == "a" and self.in_foot:
            self.foot_links += 1
        if tag not in ("br", "img", "input", "meta", "link", "hr", "source", "path", "circle", "rect", "use", "area", "col", "embed", "track", "wbr"):
            self.open_tags.append(tag)

    def handle_endtag(self, tag):
        if tag == "footer" and self.in_foot:
            self.in_foot -= 1
        if tag in self.open_tags:
            while self.open_tags and self.open_tags.pop() != tag:
                pass


def splice(html, open_mark, close_mark, block, anchor_re, mode):
    """Replace a previously generated block, else the page's own, else insert."""
    existing = re.search(re.escape(open_mark) + r".*?" + re.escape(close_mark) + r"\n?", html, re.S)
    if existing:
        return html.replace(existing.group(0), block), "updated"
    if anchor_re:
        hits = list(re.finditer(anchor_re, html, re.S | re.I))
        if len(hits) == 1:
            return html[: hits[0].start()] + block + html[hits[0].end():], "replaced"
        if len(hits) > 1:
            return html, f"skipped ({len(hits)} candidates)"
    if mode == "before-body-end" and "</body>" in html:
        return html.replace("</body>", block + "</body>", 1), "added"
    if mode == "after-body-start":
        m = re.search(r"<body[^>]*>", html, re.I)
        if m:
            return html[: m.end()] + "\n" + block + html[m.end():], "added"
    return html, "no anchor"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="report what would change, write nothing")
    ap.add_argument("--fix-menus", action="store_true", help="add the missing Resources group to short product menus")
    a = ap.parse_args()

    foot, nav = footer_html(), nav_html()
    expected_links = foot.count("<a href=")
    tally, failures = {}, []

    for p in pages():
        if p in EXCLUDE:
            tally["skipped: excluded"] = tally.get("skipped: excluded", 0) + 1
            continue
        path = pathlib.Path(p)
        original = path.read_text(encoding="utf-8", errors="replace")
        if is_noindex(original):
            tally["skipped: noindex"] = tally.get("skipped: noindex", 0) + 1
            continue
        if "</head>" not in original or "</body>" not in original:
            tally["skipped: not a full page"] = tally.get("skipped: not a full page", 0) + 1
            continue

        html = original
        if CSS_LINK not in html:
            html = CSS_LINK_RE.sub("", html)
            html = html.replace("</head>", f"  {CSS_LINK}\n</head>", 1)

        html, what = splice(html, F_OPEN, F_CLOSE, foot, r"<footer[^>]*>.*?</footer>\n?", "before-body-end")
        tally[f"footer {what}"] = tally.get(f"footer {what}", 0) + 1

        has_nav = re.search(r"<nav[\s>]", html, re.I) or N_OPEN in html
        if not has_nav:
            html, what = splice(html, N_OPEN, N_CLOSE, nav, None, "after-body-start")
            tally[f"nav {what}"] = tally.get(f"nav {what}", 0) + 1

        if a.fix_menus and 'class="nav-drop"' in html and "nav.resources" not in html:
            html, added = add_resources(html)
            tally["menu " + ("fixed" if added else "unchanged")] = tally.get("menu " + ("fixed" if added else "unchanged"), 0) + 1

        if html == original:
            tally["unchanged"] = tally.get("unchanged", 0) + 1
            continue

        c = Counter()
        c.feed(html)
        if c.footers != 1:
            failures.append(f"{p}: {c.footers} generated footers after write")
            continue
        if c.foot_links != expected_links:
            failures.append(f"{p}: footer has {c.foot_links} links, expected {expected_links}")
            continue
        if not a.check:
            path.write_text(html, encoding="utf-8")

    for k in sorted(tally):
        print(f"  {tally[k]:>4}  {k}")
    for f in failures:
        print(f"  FAIL  {f}", file=sys.stderr)
    if failures:
        print(f"\n{len(failures)} page(s) left untouched because the result did not verify.", file=sys.stderr)
    print(("would write" if a.check else "wrote") + f" the shared footer with {expected_links} links")
    return 1 if failures else 0


def add_resources(html):
    """Append the Resources group to a product menu that lacks it."""
    m = re.search(r'(<ul class="nav-links">.*?)(\n\s*</ul>)', html, re.S)
    if not m:
        return html, False
    html = html[: m.end(1)] + "\n" + RESOURCES_LI.rstrip("\n") + html[m.end(1):]
    mm = re.search(r'(<div class="mobile-menu"[^>]*>.*?)(\n\s*</div>)', html, re.S)
    if mm:
        html = html[: mm.end(1)] + "\n" + RESOURCES_MOBILE.rstrip("\n") + html[mm.end(1):]
    return html, True


if __name__ == "__main__":
    sys.exit(main())
