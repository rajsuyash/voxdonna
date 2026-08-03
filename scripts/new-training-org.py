#!/usr/bin/env python3
"""Spin up a white-labelled training portal for one client company.

    python3 scripts/new-training-org.py "Acme Corp"
    python3 scripts/new-training-org.py "Acme Corp" --path developer --accent '#3b82f6'
    python3 scripts/new-training-org.py "Acme Corp" --modules part-04,part-12,part-13

Writes train/orgs/<slug>.json (plus an assets folder for the logo) and prints
the URL to hand over. Commit and push — the webhook does the rest.
"""

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ORGS = ROOT / "train" / "orgs"
MANIFEST = ROOT / "train" / "content" / "manifest.json"
BASE_URL = "https://train.voxdonna.com"


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]
    if not slug or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
        sys.exit(f"cannot derive a usable slug from {name!r}")
    return slug


def hex_colour(value: str) -> str:
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", value):
        raise argparse.ArgumentTypeError(f"{value!r} is not a #rrggbb colour")
    return value.lower()


def lighten(hex_colour_value: str, amount: float = 0.22) -> str:
    r, g, b = (int(hex_colour_value[i:i + 2], 16) for i in (1, 3, 5))
    mix = lambda c: round(c + (255 - c) * amount)
    return "#{:02x}{:02x}{:02x}".format(mix(r), mix(g), mix(b))


def main():
    if not MANIFEST.exists():
        sys.exit("run scripts/build-training-content.py first — manifest.json is missing")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    path_keys = sorted(manifest["paths"])
    module_ids = [m["id"] for m in manifest["modules"]]

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("company", help="company name as it should appear on screen")
    ap.add_argument("--slug", help="URL slug (default: derived from the company name)")
    ap.add_argument("--path", default="certification", choices=path_keys,
                    help="learning path to assign (default: certification)")
    ap.add_argument("--modules", help="comma-separated module ids; overrides --path entirely")
    ap.add_argument("--accent", type=hex_colour, default="#c17f59", help="brand accent, #rrggbb")
    ap.add_argument("--accent-light", type=hex_colour, help="lighter accent (default: derived)")
    ap.add_argument("--logo", help="logo path or URL (default: orgs/<slug>/logo.png if you add one)")
    ap.add_argument("--welcome-title", help="hero headline; {company} is substituted")
    ap.add_argument("--welcome-body", help="hero paragraph")
    ap.add_argument("--cert-statement", help="sentence after the trainee's name on the certificate")
    ap.add_argument("--signatory", default="Voxdonna", help="certificate signatory")
    ap.add_argument("--signatory-title", default="Training partner", help="signatory role")
    ap.add_argument("--force", action="store_true", help="overwrite an existing org config")
    args = ap.parse_args()

    slug = args.slug or slugify(args.company)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", slug):
        sys.exit(f"slug {slug!r} must be lowercase letters, digits, and hyphens")
    if slug == "_template":
        sys.exit("'_template' is reserved")

    modules = None
    if args.modules:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        unknown = [m for m in modules if m not in module_ids]
        if unknown:
            sys.exit(f"unknown module ids: {', '.join(unknown)}\nvalid ids: {', '.join(module_ids)}")

    target = ORGS / f"{slug}.json"
    if target.exists() and not args.force:
        sys.exit(f"{target.relative_to(ROOT)} already exists — pass --force to overwrite")

    template = json.loads((ORGS / "_template.json").read_text(encoding="utf-8"))
    assets = ORGS / slug
    assets.mkdir(parents=True, exist_ok=True)

    logo = args.logo
    if logo is None:
        logo = f"orgs/{slug}/logo.png" if (assets / "logo.png").exists() else ""

    config = {
        "slug": slug,
        "companyName": args.company,
        "logo": logo,
        "accent": args.accent,
        "accentLight": args.accent_light or lighten(args.accent),
        "learningPath": args.path,
        "modules": modules,
        "welcome": {
            "eyebrow": "Enterprise enablement",
            "title": args.welcome_title or "Claude for {company}",
            "body": args.welcome_body or template["welcome"]["body"],
        },
        "certificate": {
            "title": "Certificate of Completion",
            "statement": args.cert_statement or template["certificate"]["statement"],
            "signatory": args.signatory,
            "signatoryTitle": args.signatory_title,
        },
        "contact": template.get("contact", "hello@voxdonna.com"),
    }

    target.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    curriculum = modules or manifest["paths"][args.path]["modules"]
    minutes = sum(m["minutes"] for m in manifest["modules"] if m["id"] in curriculum)

    print(f"wrote {target.relative_to(ROOT)}")
    print(f"  company    {args.company}")
    print(f"  curriculum {len(curriculum)} modules · ~{minutes // 60}h {minutes % 60}m")
    print(f"  accent     {config['accent']} / {config['accentLight']}")
    if not logo:
        print(f"  logo       drop one at {(assets / 'logo.png').relative_to(ROOT)}, then re-run with --force")
    print(f"\n  {BASE_URL}/{slug}/\n")
    print("Commit and push to publish.")


if __name__ == "__main__":
    main()
