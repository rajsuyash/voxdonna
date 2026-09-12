#!/usr/bin/env python3
"""Search Console work for voxdonna.com: submit the sitemap, read the numbers,
check what Google has actually indexed. Optionally create a GA4 property.

Auth, once, interactive. Ask only for the scopes you need, because Google blocks
the shared gcloud client on some sensitive scopes ("This app is blocked"):

  # Search Console only, this one is known to work:
  gcloud auth application-default login \\
    --scopes=https://www.googleapis.com/auth/webmasters,https://www.googleapis.com/auth/cloud-platform

  # Adding Analytics may be refused by Google; try it only if you want --ga:
  #   ,https://www.googleapis.com/auth/analytics.edit

Application Default Credentials also need a quota project, which this script
takes from `gcloud config get-value project`.

Usage:
  python3 scripts/setup-google.py --report            # numbers and index status
  python3 scripts/setup-google.py --submit-sitemap    # (re)submit the sitemap
  python3 scripts/setup-google.py --ga                # create a GA4 property
"""
import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, timedelta

SITE = "sc-domain:voxdonna.com"
SITEMAP = "https://voxdonna.com/sitemap.xml"
SC = "https://searchconsole.googleapis.com"
KEY_PAGES = ["https://voxdonna.com/", "https://voxdonna.com/demos.html",
             "https://voxdonna.com/ai-for-sap.html", "https://voxdonna.com/ai-for-manufacturers.html",
             "https://voxdonna.com/jewellers.html",
             "https://voxdonna.com/blog/en/voice-ai-manufacturing-case-studies.html"]


def sh(*args):
    try:
        r = subprocess.run(args, capture_output=True, text=True, check=True)
        return r.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def auth():
    tok = sh("gcloud", "auth", "application-default", "print-access-token")
    if not tok:
        sys.exit("No application-default credentials. Run the gcloud command in this file's docstring.")
    proj = sh("gcloud", "config", "get-value", "project")
    if not proj or proj == "(unset)":
        sys.exit("No gcloud project set, and the API needs one for quota. Run: gcloud config set project <id>")
    return {"Authorization": f"Bearer {tok}", "x-goog-user-project": proj, "Content-Type": "application/json"}


def call(method, url, hdrs, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"raw": raw[:300]}


def msg(resp):
    return resp.get("error", {}).get("message", str(resp)[:160])


def q(path):
    return urllib.parse.quote(path, safe="")


def submit_sitemap(hdrs):
    code, resp = call("PUT", f"{SC}/webmasters/v3/sites/{q(SITE)}/sitemaps/{q(SITEMAP)}", hdrs)
    print(f"sitemap submit: HTTP {code}" + ("" if code < 300 else f" — {msg(resp)}"))
    code, resp = call("GET", f"{SC}/webmasters/v3/sites/{q(SITE)}/sitemaps", hdrs)
    for s in resp.get("sitemap", []):
        print(f"  {s.get('path')}  submitted {s.get('lastSubmitted','?')[:10]}  "
              f"downloaded {(s.get('lastDownloaded') or 'never')[:10]}  "
              f"errors {s.get('errors','?')}  warnings {s.get('warnings','?')}")


def report(hdrs):
    end = date.today() - timedelta(days=1)
    start = end - timedelta(days=27)
    base = f"{SC}/webmasters/v3/sites/{q(SITE)}/searchAnalytics/query"
    rng = {"startDate": start.isoformat(), "endDate": end.isoformat()}

    code, resp = call("POST", base, hdrs, rng)
    rows = resp.get("rows", [])
    print(f"28 days to {end}")
    if rows:
        r = rows[0]
        print(f"  clicks {r['clicks']:.0f} | impressions {r['impressions']:.0f} | "
              f"ctr {r['ctr']*100:.2f}% | average position {r['position']:.1f}")
    else:
        print(f"  no data ({msg(resp) if code != 200 else 'nothing recorded yet'})")

    for dim in ("query", "page"):
        code, resp = call("POST", base, hdrs, {**rng, "dimensions": [dim], "rowLimit": 10})
        print(f"\n  top {'queries' if dim == 'query' else 'pages'}")
        for r in resp.get("rows", []):
            label = r["keys"][0].replace("https://voxdonna.com", "")[:52]
            print(f"    {label:54}{r['clicks']:>5.0f} clicks {r['impressions']:>6.0f} impr  pos {r['position']:.1f}")
        if not resp.get("rows"):
            print("    none")

    print("\n  index status of key pages")
    for u in KEY_PAGES:
        code, resp = call("POST", f"{SC}/v1/urlInspection/index:inspect", hdrs,
                          {"inspectionUrl": u, "siteUrl": SITE})
        r = resp.get("inspectionResult", {}).get("indexStatusResult")
        label = u.replace("https://voxdonna.com", "") or "/"
        if r:
            print(f"    {label:54}{r.get('verdict','?'):8} {r.get('coverageState','?')[:38]}")
        else:
            print(f"    {label:54}{msg(resp)}")


def ga(hdrs):
    print("Google Analytics 4")
    code, resp = call("GET", "https://analyticsadmin.googleapis.com/v1beta/accounts", hdrs)
    if code != 200:
        print(f"  not available: {msg(resp)}")
        print("  Either re-run the login adding the analytics.edit scope, or create the property")
        print("  at analytics.google.com and install it with: python3 scripts/add-analytics.py G-XXXXXXXXXX")
        return
    accounts = resp.get("accounts", [])
    if not accounts:
        print("  no Analytics account on this login; create one at analytics.google.com first")
        return
    acct = accounts[0]
    print(f"  account: {acct.get('displayName')}")
    code, resp = call("GET", f"https://analyticsadmin.googleapis.com/v1beta/properties?filter=parent:{acct['name']}", hdrs)
    prop = next((p for p in resp.get("properties", []) if "voxdonna" in p.get("displayName", "").lower()), None)
    if not prop:
        code, prop = call("POST", "https://analyticsadmin.googleapis.com/v1beta/properties", hdrs,
                          {"parent": acct["name"], "displayName": "Voxdonna",
                           "timeZone": "Asia/Kolkata", "currencyCode": "INR"})
        if code != 200:
            print(f"  could not create the property: {msg(prop)}")
            return
        print(f"  created {prop['name']}")
    code, streams = call("GET", f"https://analyticsadmin.googleapis.com/v1beta/{prop['name']}/dataStreams", hdrs)
    web = next((s for s in streams.get("dataStreams", []) if s.get("type") == "WEB_DATA_STREAM"), None)
    if not web:
        code, web = call("POST", f"https://analyticsadmin.googleapis.com/v1beta/{prop['name']}/dataStreams", hdrs,
                         {"type": "WEB_DATA_STREAM", "displayName": "voxdonna.com",
                          "webStreamData": {"defaultUri": "https://voxdonna.com"}})
        if code != 200:
            print(f"  could not create the data stream: {msg(web)}")
            return
    mid = web.get("webStreamData", {}).get("measurementId")
    print(f"  measurement ID: {mid}")
    print(f"  install it:  python3 scripts/add-analytics.py {mid}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", action="store_true", help="28-day numbers and index status")
    ap.add_argument("--submit-sitemap", action="store_true", help="(re)submit the sitemap")
    ap.add_argument("--ga", action="store_true", help="create the GA4 property and data stream")
    a = ap.parse_args()
    if not any((a.report, a.submit_sitemap, a.ga)):
        ap.error("pick at least one of --report, --submit-sitemap, --ga")
    hdrs = auth()
    if a.submit_sitemap:
        submit_sitemap(hdrs)
    if a.report:
        report(hdrs)
    if a.ga:
        ga(hdrs)


if __name__ == "__main__":
    main()
