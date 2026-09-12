#!/usr/bin/env python3
"""Verify voxdonna.com in Search Console, submit the sitemap, and create a GA4 property.

Prerequisite, run once, interactive (opens a browser):

  gcloud auth application-default login \\
    --scopes=openid,https://www.googleapis.com/auth/cloud-platform,\\
https://www.googleapis.com/auth/webmasters,\\
https://www.googleapis.com/auth/siteverification,\\
https://www.googleapis.com/auth/analytics.edit

Then:

  python3 scripts/setup-google.py            # everything
  python3 scripts/setup-google.py --check    # report what it would do
  python3 scripts/setup-google.py --skip-ga  # Search Console only

Verification uses the file method: the script writes googleXXXX.html into the
repository, commits and pushes it (the site deploys on push), waits for it to
serve, and only then asks Google to verify. Nothing here prints a secret.
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

SITE = "https://voxdonna.com/"
SITEMAP = "https://voxdonna.com/sitemap.xml"
REPO = __file__.rsplit("/scripts/", 1)[0]


def token():
    try:
        out = subprocess.run(["gcloud", "auth", "application-default", "print-access-token"],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        sys.exit("No application-default credentials. Run the gcloud command in this file's docstring first.")


def call(method, url, tok, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"raw": raw[:400]}


def err(resp):
    return resp.get("error", {}).get("message", str(resp)[:200])


def scopes_ok(tok):
    code, resp = call("GET", "https://searchconsole.googleapis.com/webmasters/v3/sites", tok)
    if code == 403 and "scope" in err(resp).lower():
        sys.exit("The current credentials lack the Search Console scope.\n"
                 "Re-run the gcloud command in this file's docstring, then try again.")
    return code, resp


def sh(*args):
    return subprocess.run(args, cwd=REPO, capture_output=True, text=True)


def verify_site(tok, check):
    code, resp = call("POST",
                      "https://www.googleapis.com/siteVerification/v1/token",
                      tok, {"site": {"type": "SITE", "identifier": SITE}, "verificationMethod": "FILE"})
    if code != 200:
        print(f"  could not get a verification token: {err(resp)}")
        return False
    fname = resp["token"]
    print(f"  verification file: {fname}")
    if check:
        print("  --check: not writing or deploying the file")
        return False
    with open(f"{REPO}/{fname}", "w", encoding="utf-8") as f:
        f.write(f"google-site-verification: {fname}\n")
    sh("git", "add", fname)
    sh("git", "commit", "-q", "-m", "chore(seo): add the Search Console verification file")
    push = sh("git", "push", "-q", "origin", "main")
    if push.returncode != 0:
        print(f"  push failed: {push.stderr.strip()[:200]}")
        return False
    url = f"{SITE}{fname}"
    for _ in range(40):
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                if r.status == 200:
                    break
        except urllib.error.URLError:
            pass
        time.sleep(3)
    else:
        print("  verification file never went live; check the deploy")
        return False
    code, resp = call("POST",
                      "https://www.googleapis.com/siteVerification/v1/webResource?verificationMethod=FILE",
                      tok, {"site": {"type": "SITE", "identifier": SITE}})
    if code == 200:
        print("  ownership verified")
        return True
    print(f"  verification failed: {err(resp)}")
    return False


def search_console(tok, check):
    print("Search Console")
    code, resp = scopes_ok(tok)
    owned = [s["siteUrl"] for s in resp.get("siteEntry", [])] if code == 200 else []
    print(f"  properties on this account: {len(owned)}")
    if SITE not in owned:
        if check:
            print(f"  --check: would verify and add {SITE}")
            return
        if not verify_site(tok, check):
            return
        code, resp = call("PUT", f"https://searchconsole.googleapis.com/webmasters/v3/sites/{urlq(SITE)}", tok)
        print(f"  added the property: HTTP {code}")
    else:
        print("  property already present")
    if check:
        print("  --check: would submit the sitemap")
        return
    code, resp = call("PUT",
                      f"https://searchconsole.googleapis.com/webmasters/v3/sites/{urlq(SITE)}/sitemaps/{urlq(SITEMAP)}",
                      tok)
    print(f"  sitemap submitted: HTTP {code}" + ("" if code < 300 else f" — {err(resp)}"))


def urlq(s):
    return urllib.request.quote(s, safe="")


def analytics(tok, check):
    print("Google Analytics 4")
    code, resp = call("GET", "https://analyticsadmin.googleapis.com/v1beta/accounts", tok)
    if code != 200:
        print(f"  cannot list accounts: {err(resp)}")
        return
    accounts = resp.get("accounts", [])
    if not accounts:
        print("  no Analytics account on this login. Create one at analytics.google.com,")
        print("  then re-run. The API cannot create the account itself, only properties.")
        return
    acct = accounts[0]
    print(f"  account: {acct.get('displayName')}")
    code, resp = call("GET",
                      f"https://analyticsadmin.googleapis.com/v1beta/properties?filter=parent:{acct['name']}", tok)
    props = resp.get("properties", []) if code == 200 else []
    prop = next((p for p in props if "voxdonna" in p.get("displayName", "").lower()), None)
    if prop:
        print(f"  property exists: {prop['displayName']}")
    else:
        if check:
            print("  --check: would create a 'Voxdonna' property and a web data stream")
            return
        code, prop = call("POST", "https://analyticsadmin.googleapis.com/v1beta/properties", tok,
                          {"parent": acct["name"], "displayName": "Voxdonna", "timeZone": "Asia/Kolkata",
                           "currencyCode": "INR"})
        if code != 200:
            print(f"  could not create the property: {err(prop)}")
            return
        print(f"  created property {prop['name']}")
    code, streams = call("GET", f"https://analyticsadmin.googleapis.com/v1beta/{prop['name']}/dataStreams", tok)
    web = next((s for s in streams.get("dataStreams", []) if s.get("type") == "WEB_DATA_STREAM"), None)
    if not web:
        if check:
            print("  --check: would create the web data stream")
            return
        code, web = call("POST", f"https://analyticsadmin.googleapis.com/v1beta/{prop['name']}/dataStreams", tok,
                         {"type": "WEB_DATA_STREAM", "displayName": "voxdonna.com",
                          "webStreamData": {"defaultUri": "https://voxdonna.com"}})
        if code != 200:
            print(f"  could not create the data stream: {err(web)}")
            return
    mid = web.get("webStreamData", {}).get("measurementId")
    print(f"  measurement ID: {mid}")
    print(f"  install it with:  python3 scripts/add-analytics.py {mid}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="report only, change nothing")
    ap.add_argument("--skip-ga", action="store_true", help="Search Console only")
    a = ap.parse_args()
    tok = token()
    search_console(tok, a.check)
    if not a.skip_ga:
        analytics(tok, a.check)


if __name__ == "__main__":
    main()
