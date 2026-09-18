"""Repair broken internal link targets in the blog markdown sources.

The generated HTML is build output, so every fix has to land in the .md or it is
gone at the next `build-blog-static.js` run. Two link syntaxes are in play:
markdown `](/x)` and raw `href="/x"` in the posts authored as HTML.
"""
import pathlib, re, glob, collections, sys

ROOT = pathlib.Path(".").resolve()
LANGS = ("en", "fr", "it")

# targets that map to one fixed destination regardless of the containing language
STATIC = {
    "/en#pricing": "/index.html#pricing",
    "/fr#pricing": "/index.html#pricing",
    "/it#pricing": "/index.html#pricing",
    "/contact": "/index.html#contact",
    "/ai-voice-agent.html": "/industries/",          # anchor text is "for different industries"
    "/roi-calculator.html": "/ai-voice-agents.html#roi",
    "/qualify.html": "/ai-voice-agents.html#roi",    # anchor text is "custom ROI estimate"
    "/case-studies/": "/demos.html",
}
RELABEL = {"Case studies": "Live agent demos"}

REPLACEMENT_TITLE = {
    "en": "How Premium Brands Like Le Marquier Can Automate Customer Support in 3 Languages",
    "fr": "Comment les marques premium comme Le Marquier peuvent automatiser le support client en 3 langues",
    "it": "Come i brand premium come Le Marquier possono automatizzare il supporto clienti in 3 lingue",
}

def blog_target(slug, lang):
    """A /blog/<slug> link resolved in the containing file's language, falling back to en."""
    for l in (lang, "en"):
        if (ROOT / "blog" / l / f"{slug}.html").exists() or (ROOT / "blog" / l / f"{slug}.md").exists():
            return f"/blog/{l}/{slug}.html"
    return None

def resolve(href, lang):
    # the map is keyed on some entries WITH their fragment (/en#pricing), so the
    # whole href has to be tried before the fragment is stripped off
    if href in STATIC:
        return STATIC[href]
    base = href.split("#")[0]
    frag = href[len(base):]
    if base in STATIC:
        return STATIC[base] + frag
    m = re.fullmatch(r"/blog/([a-z0-9-]+)(?:\.html)?", base)
    if m and m.group(1) not in LANGS:
        t = blog_target(m.group(1), lang)
        return (t + frag) if t else None
    return None

def exists(href):
    t = href.split("#")[0].split("?")[0]
    if not t:
        return True
    fs = ROOT / t.lstrip("/")
    if t.endswith("/"):
        fs = fs / "index.html"
    return fs.exists()

apply = "--apply" in sys.argv
fixed, unresolved, files_touched = collections.Counter(), collections.defaultdict(list), 0

for f in sorted(glob.glob("blog/*/*.md")):
    lang = pathlib.Path(f).parent.name
    p = pathlib.Path(f)
    s = orig = p.read_text(encoding="utf-8")

    # 1. the dead "related post" card — the article it points at was never written
    s = re.sub(r'\n?\s*<a href="/blog/ai-voice-agent-appointment-booking\.html"[^>]*>[^<]*</a>', "", s)

    # 2. the Le Marquier case-study card: no such page, and its "80% automation"
    #    claim is one of two contradictory figures the blog publishes. Point it at
    #    the post that carries the publishable profile instead.
    s = re.sub(r'<a href="/case-studies/le-marquier\.html"([^>]*)>[^<]*</a>',
               lambda m: f'<a href="/blog/{lang}/multilingual-support-specialty-brands.html"{m.group(1)}>{REPLACEMENT_TITLE[lang]}</a>',
               s)

    # 3. everything else, both link syntaxes
    def md(m):
        label, href = m.group(1), m.group(2)
        if exists(href):
            return m.group(0)
        new = resolve(href, lang)
        if not new:
            unresolved[href].append(f); return m.group(0)
        fixed[f"{href} -> {new}"] += 1
        return f"[{RELABEL.get(label, label)}]({new})"
    s = re.sub(r'\[([^\]]*)\]\((/[^)\s]+)\)', md, s)

    def html(m):
        href = m.group(1)
        if exists(href):
            return m.group(0)
        new = resolve(href, lang)
        if not new:
            unresolved[href].append(f); return m.group(0)
        fixed[f"{href} -> {new}"] += 1
        return f'href="{new}"'
    s = re.sub(r'href="(/[^"]+)"', html, s)

    if s != orig:
        files_touched += 1
        if apply:
            p.write_text(s, encoding="utf-8")

for k, n in sorted(fixed.items(), key=lambda kv: -kv[1]):
    print(f"{n:>3}  {k}")
print(f"\n{sum(fixed.values())} link(s) across {files_touched} file(s)" + ("" if apply else "  [dry run]"))
if unresolved:
    print("\nUNRESOLVED — need a decision:")
    for h, v in sorted(unresolved.items()):
        print(f"  {h}  ({len(v)} instance(s))")
