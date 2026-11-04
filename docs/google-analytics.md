# VoxDonna Google Analytics

Configured 2026-11-04.

- Account: VoxDonna, 414688740
- GA4 property: VoxDonna, 562310997
- Web stream: VoxDonna website, 16269818768, https://voxdonna.com
- Measurement ID: G-5TDZPZGLMX (public identifier, not a credential)
- Reporting: India time / INR
- Account optional sharing: disabled
- Enhanced measurement: page loads, scrolls, outbound clicks, YouTube engagement, downloads. Site search, automatic form events and history-based pageviews disabled.

## Site installation

`python3 scripts/add-analytics.py G-5TDZPZGLMX --check` audits the managed block.
Omit `--check` to install or update it. The sitemap defines the public page inventory;
`blog-post.html` is included so future static blog builds and BabyLoveGrowth posts inherit it.
Run the installer again when adding a new public page outside the blog generator.

`assets/analytics.js` loads Google only after analytics consent. Accept/reject choices
persist for 180 days; Analytics settings reopens the controls. Rejection disables
this measurement ID and clears its root-path Google Analytics cookies. Advertising
consent stays denied and Google signals/ad personalization are disabled.
Non-campaign query parameters and URL fragments are removed from configured page URLs.
No custom lead conversion is configured: an outbound click or a form interaction is
not evidence of a successfully received lead.

## Verification

- `node --test scripts/test-analytics.cjs scripts/test-babylovegrowth.cjs`
- `python3 scripts/test-analytics-installer.py`
- `node --check assets/analytics.js`
- `python3 -m py_compile scripts/add-analytics.py scripts/test-analytics-installer.py`
- `git diff --check`

This vanilla JS/Python subsystem has no configured type checker or linter.
Use a live accepted visit and the property's Realtime report to verify collection.
Before acceptance and after rejection, no Google tag script should load.
Consent blocking and ad blockers can prevent Google's installation checker detecting
the tag; inspect consented live collection instead of disabling consent controls.
