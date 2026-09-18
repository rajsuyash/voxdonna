#!/usr/bin/env python3
"""Give every Voxdonna Organization node one identity, edited as JSON.

The Organization block is copy-pasted into 60 pages in seven different shapes,
so there is no single template to edit. Every block is parsed with json.loads,
changed as data and re-serialised — a regex over JSON would depend on key order
and whitespace, neither of which is stable across those seven shapes.

A TOP-LEVEL Organization node carries the full identity. A NESTED one
(provider, publisher, author, parentOrganization) is a reference to the same
entity, so it gets the @id and nothing else: inlining the payload there repeats
the company's legal identity five times per page and says nothing new.

Blog pages are build output of blog-post.html; this touches the template and
`node scripts/build-blog-static.js` propagates it.
"""
import glob, json, pathlib, re, sys

ORG_ID = "https://voxdonna.com/#organization"
LEGAL = "Donna AI Labs Private Limited"
WIKIDATA = {"@type": "PropertyValue", "propertyID": "wikidata", "value": "Q139731514"}
CIN = {"@type": "PropertyValue", "propertyID": "CIN", "value": "U62013DL2026PTC464877"}
PERSON = {"@type": "Person", "@id": "https://rajsuyash.com/about.html#person",
          "name": "Suyash Raj", "url": "https://rajsuyash.com/about.html",
          "sameAs": ["https://www.linkedin.com/in/suyashraj/"]}
SUBORG = {"@type": "Organization", "@id": "https://aisewak.com/#organization",
          "name": "AiSewak", "url": "https://aisewak.com"}
ORDER = ["@context", "@type", "@id", "name", "legalName", "alternateName", "url",
         "logo", "description", "founder", "subOrganization", "contactPoint",
         "identifier", "sameAs"]
# keys that hold a reference to an organisation rather than a definition of one
REF_KEYS = {"provider", "publisher", "author", "parentOrganization", "worksFor",
            "brand", "seller", "sourceOrganization"}

BLOCK = re.compile(r'(<script[^>]*type="application/ld\+json"[^>]*>)(.*?)(</script>)', re.S | re.I)


def is_vox_org(n):
    return (isinstance(n, dict) and n.get("@type") == "Organization"
            and str(n.get("name", "")).startswith("Voxdonna"))


# Exactly three descriptions across the corpus name elections, and each drops
# a different shape of list item ("and elections", "elections India" mid-list).
# A generic comma-list rewriter got two of the three subtly wrong, so the
# rewrites are spelled out and an unknown shape is a hard failure rather than a
# silently mangled sentence.
REWRITE = {
    "Full-stack AI consulting company. We build custom AI agents across industries: voice, WhatsApp, sales, and elections.":
        "Full-stack AI consulting company. We build custom AI agents across industries: voice, WhatsApp and sales.",
    "Full-stack AI consulting. We work across industries and build custom AI agents across voice, WhatsApp, sales, and elections. Live in weeks.":
        "Full-stack AI consulting. We work across industries and build custom AI agents across voice, WhatsApp and sales. Live in weeks.",
    "40 live AI voice agents covering hospitality, healthcare, manufacturing, supply chain, B2B sales, elections India, and Bollywood voice marketing.":
        "40 live AI voice agents covering hospitality, healthcare, manufacturing, supply chain, B2B sales and Bollywood voice marketing.",
}
UNKNOWN = []


def strip_elections(t):
    if "election" not in t.lower():
        return t
    if t not in REWRITE:
        UNKNOWN.append(t)
        return t
    return REWRITE[t]


def define(n):
    """Fill in the full identity on a top-level Organization node."""
    n["@id"] = ORG_ID
    n["legalName"] = LEGAL
    ids = n.get("identifier")
    ids = list(ids) if isinstance(ids, list) else ([ids] if ids else [])
    if not any(isinstance(i, dict) and i.get("propertyID") == "wikidata" for i in ids):
        ids.insert(0, dict(WIKIDATA))
    if not any(isinstance(i, dict) and i.get("propertyID") == "CIN" for i in ids):
        ids.append(dict(CIN))
    n["identifier"] = ids
    n["founder"] = dict(PERSON)
    n["subOrganization"] = dict(SUBORG)
    if isinstance(n.get("description"), str):
        n["description"] = strip_elections(n["description"])
    ordered = {k: n[k] for k in ORDER if k in n}
    ordered.update({k: v for k, v in n.items() if k not in ordered})
    n.clear(); n.update(ordered)


def reference(n):
    """A nested mention: point at the entity, do not restate it."""
    keep = {k: n[k] for k in ("@type", "@id", "name", "url") if k in n}
    keep["@id"] = ORG_ID
    n.clear(); n.update({"@type": "Organization", "@id": ORG_ID,
                         **{k: v for k, v in keep.items() if k not in ("@type", "@id")}})


def walk(node, nested_key=None):
    changed = False
    if isinstance(node, dict):
        if is_vox_org(node):
            before = json.dumps(node, sort_keys=True)
            reference(node) if nested_key in REF_KEYS else define(node)
            changed |= json.dumps(node, sort_keys=True) != before
        for k, v in list(node.items()):
            if k == "description" and isinstance(v, str) and "election" in v.lower():
                new = strip_elections(v)
                if new != v:
                    node[k] = new; changed = True
            else:
                changed |= walk(v, k)
    elif isinstance(node, list):
        for v in node:
            changed |= walk(v, nested_key)
    return changed


def main(write):
    files = []
    for p in ("*.html", "demo/*.html", "demo/*/index.html", "industries/*.html", "jewellers/*.html"):
        files.extend(sorted(glob.glob(p)))
    touched = blocks = 0
    for f in files:
        path = pathlib.Path(f)
        raw = path.read_text(encoding="utf-8")
        if "application/ld+json" not in raw:
            continue
        local = 0

        def repl(m):
            nonlocal local
            try:
                data = json.loads(m.group(2))
            except json.JSONDecodeError:
                print(f"  SKIP {f}: a JSON-LD block does not parse", file=sys.stderr)
                return m.group(0)
            if not walk(data):
                return m.group(0)
            local += 1
            body = json.dumps(data, ensure_ascii=False, indent=2).replace("\n", "\n  ")
            return f"{m.group(1)}\n  {body}\n  {m.group(3)}"

        new = BLOCK.sub(repl, raw)
        if local:
            for m in BLOCK.finditer(new):   # re-parse what we wrote
                json.loads(m.group(2))
            if write:
                path.write_text(new, encoding="utf-8")
            touched += 1; blocks += local
    print(f"{'wrote' if write else 'would write'} {blocks} JSON-LD block(s) across {touched} page(s)")
    if UNKNOWN:
        for u in sorted(set(UNKNOWN)):
            print(f"  UNHANDLED description naming elections: {u}", file=sys.stderr)
        sys.exit(1)


main("--write" in sys.argv)
