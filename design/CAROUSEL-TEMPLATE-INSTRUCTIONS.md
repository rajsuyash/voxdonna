# Social Media Carousel Template — MANDATORY for ALL Voxdonna posts

**Applies to:** Every agent that creates or posts carousels for Voxdonna on LinkedIn, Instagram, Twitter/X, or any other social channel.

**Status:** Authoritative as of 2026-05-27. Supersedes any prior carousel script or template.

---

## 🚨 IF YOU ARE CREATING A SOCIAL CAROUSEL — READ THIS FIRST

The user has provided a designed carousel template at:

```
~/clawd/voxdonna/design/carousel-template/
```

**You MUST use this template for all carousel output.** Do not invent layouts. Do not pick your own fonts or colors. Do not use `pdf-lib` `StandardFonts.Helvetica` or any generic styling.

The template encodes the Voxdonna brand: **Inter font, copper accent `#c17f59`, off-white text on near-black, restrained editorial aesthetic.**

---

## What's in the template bundle

```
~/clawd/voxdonna/design/carousel-template/
├── README.md                                  ← Anthropic Claude Design handoff notes
├── chats/chat1.md                             ← Original design conversation
└── project/
    ├── Carousel Template.html                 ← Master canvas (3 directions stacked)
    ├── assets/
    │   ├── voxdonna-tokens.css                ← DESIGN TOKENS (colors, fonts, spacing, glows)
    │   ├── voxdonna-logo.png                  ← Wordmark
    │   └── voxdonna-mark.png                  ← Mark
    ├── slide-data.js                          ← SLIDE CONTENT — edit this per carousel
    ├── direction-editorial.jsx                ← Direction A: restrained, big Inter type
    ├── direction-operator.jsx                 ← Direction B: mono-led spec sheet
    ├── direction-marquee.jsx                  ← Direction C: bold display, copper glows
    ├── design-canvas.jsx                      ← Side-by-side canvas of all 3 directions
    ├── app.jsx                                ← React mount
    ├── screenshots/                           ← Reference screenshots of each direction
    └── export/
        ├── voxdonna-carousel.html             ← STANDALONE single-file HTML (1.8 MB, self-contained)
        └── src/                               ← Source files (mirror of project/)
```

---

## How to create a new carousel

### Step 1 — Pick a direction

The template ships with 3 directions. **Default: `editorial`** (the user's intended primary). Use a different direction only if the user explicitly asks for `operator` or `marquee`.

| Direction | When to use |
|---|---|
| **`editorial`** (default) | How-to guides, POVs, frameworks, case studies — most posts |
| `operator` | Technical deep-dives, "spec sheet" style, code/numbers-heavy |
| `marquee` | Big announcements, hero moments, manifesto posts |

### Step 2 — Edit ONLY `slide-data.js`

Open `~/clawd/voxdonna/design/carousel-template/project/slide-data.js` and modify the `CAROUSEL.slides` array. Keep the existing `layout` keys (they map to the 9 supported layouts in each direction's JSX).

Supported `layout` values:
- `cover` — hook headline + eyebrow
- `step` — numbered process
- `section` — chapter break / divider
- `quote` — testimonial / pull quote
- `cta` — closing slide with call-to-action
- `stat` — one giant number
- `compare` — vs / before-after
- `feature` — icon + headline + body
- `bullets` — 3-5 numbered/dotted points

**DO NOT add new layouts.** If you need one that doesn't exist, escalate to the user.

### Step 3 — Render the carousel

The template uses the `?only=` URL query parameter to render a single direction full-size (1080×1080):

```bash
# Open in browser for visual check (one direction full-screen):
open "~/clawd/voxdonna/design/carousel-template/project/Carousel Template.html?only=editorial"

# Or use the self-contained export (no asset deps):
open "~/clawd/voxdonna/design/carousel-template/project/export/voxdonna-carousel.html?only=editorial"
```

### Step 4 — Generate PDF / JPGs for upload

**For LinkedIn document carousel (PDF, 1 page per slide):**

```bash
# Headless Chrome → PDF, 1080×1080 page
google-chrome --headless --no-sandbox \
  --print-to-pdf=/tmp/voxdonna-carousel.pdf \
  --print-to-pdf-no-header \
  --no-pdf-header-footer \
  --virtual-time-budget=10000 \
  "file://$HOME/clawd/voxdonna/design/carousel-template/project/Carousel Template.html?only=editorial"
```

Or with Puppeteer (Node):

```javascript
const puppeteer = require('puppeteer');
const browser = await puppeteer.launch();
const page = await browser.newPage();
await page.setViewport({ width: 1080, height: 1080 });
await page.goto('file:///home/suyashraj/clawd/voxdonna/design/carousel-template/project/Carousel Template.html?only=editorial', { waitUntil: 'networkidle0' });
await page.pdf({ path: '/tmp/carousel.pdf', width: '1080px', height: '1080px', printBackground: true });
```

**For Instagram (individual JPGs):**

Screenshot each `<section.export-slide>` element. Each slide is rendered as a separate full 1080×1080 section when you use the `?only=` filter.

```bash
# Per-slide screenshots (requires puppeteer + slide selector loop)
# See scripts/render-carousel-jpgs.sh (to be written if needed)
```

### Step 5 — Upload

- **LinkedIn:** Attach the multi-page PDF to a company-page post via Publer or Unipile. `linkedin-post.py` already does this if the queue.md entry has a `pdf_path:` field.
- **Instagram:** Upload JPGs as a carousel. (Manual via Instagram app or via Meta Graph API if wired.)
- **Twitter/X:** Upload first 4 JPGs as a tweet's image set.

---

## DO NOT do these things

| ❌ Don't | ✅ Do |
|---|---|
| Generate PDFs with `pdf-lib` `StandardFonts.Helvetica` | Use the HTML template + headless Chrome / Puppeteer |
| Use `rgb(1, 0.42, 0.42)` pink-red as accent | Use copper `#c17f59` (`var(--copper)` in template) |
| Pick your own font | Inter for body, JetBrains Mono for eyebrows + counters |
| Write inline CSS that overrides tokens | Edit `slide-data.js` only — leave template CSS alone |
| Invent a new layout | Use one of the 9 existing layouts; escalate if you need a new one |
| Render carousels from any other script | Use the template at `~/clawd/voxdonna/design/carousel-template/` |

The OLD `gen_carousel_pdf.js` at `~/clawd/social/linkedin-voxdonna/` is **DEPRECATED 2026-05-27** — do not use it. Its outputs violate every brand rule (Helvetica font + pink-red accent + flat gray text).

---

## Brand quick reference (don't memorize — read `voxdonna-tokens.css` instead)

| Token | Value | Use |
|---|---|---|
| `--bg` | `#000000` | Slide background |
| `--fg-1` | `#f5f5f7` | Primary text (off-white) |
| `--fg-3` | `rgba(245, 245, 247, 0.6)` | Secondary text |
| `--copper` | `#c17f59` | Brand accent — borders, eyebrows, CTAs |
| `--copper-light` | `#d4a574` | Hover, highlight in copy |
| `--font-sans` | `'Inter', system fallback` | All body + headlines |
| `--font-mono` | `'JetBrains Mono', system fallback` | Eyebrows, counters, code |

**Letter-spacing:** `-0.04em` on hero h1, `-0.03em` on h1, `-0.02em` on h2. Tight. Editorial.

**Layout:** 1080×1080 square. Wordmark in one corner. Mono slide counter (`01 / 10`) in opposite corner.

---

## Escalation

If the template doesn't fit what you need (new layout, new direction, new platform):

1. **Don't improvise.** Do not write a one-off PDF generator with hardcoded styling.
2. Create a Paperclip issue tagged `design-request` assigned to CEO with: what you need, why the existing 9 layouts don't fit, and a 1-slide mockup if possible.
3. The user will design the new layout via Claude Design + drop it into the template bundle.

---

## File ownership

- **The template itself** (`~/clawd/voxdonna/design/carousel-template/`) — owned by the user. Treat as read-only canon. Do not commit changes without escalation.
- **`slide-data.js`** — the only file agents edit per carousel. Treat each carousel as its own commit (`carousel: 2026-05-27 — <topic>`).
- **Generated PDFs/JPGs** — go to `~/clawd/social/linkedin-voxdonna/YYYY-MM-DD.pdf` etc. as before.

---

## TL;DR for impatient agents

1. Read `~/clawd/voxdonna/design/carousel-template/README.md`
2. Edit `~/clawd/voxdonna/design/carousel-template/project/slide-data.js` (only `CAROUSEL.slides`)
3. Headless-Chrome render `Carousel Template.html?only=editorial` to PDF or JPG sequence
4. Upload to social platform
5. DO NOT use `pdf-lib` / `StandardFonts.Helvetica` / hardcoded colors anywhere


---

## VERIFIED WORKING RENDER COMMAND (added 2026-05-27)

Tested inside paperclip-paperclip-1 container with chromium 148.0.7778.178 + fonts-inter + fonts-jetbrains-mono. Generates a 400KB+ 10-page PDF with full Voxdonna brand styling (Inter font, copper accent, off-white on true black).

```bash
docker exec paperclip-paperclip-1 sh -c '
mkdir -p /tmp/chrome-data
HOME=/tmp CHROME_DEVEL_SANDBOX= chromium \
  --headless=new \
  --no-sandbox \
  --disable-gpu \
  --disable-dev-shm-usage \
  --user-data-dir=/tmp/chrome-data \
  --disable-features=Crashpad \
  --disable-crash-reporter \
  --crash-dumps-dir=/tmp \
  --no-default-browser-check --no-first-run \
  --hide-scrollbars \
  --print-to-pdf=/tmp/voxdonna-carousel.pdf \
  --no-pdf-header-footer \
  --virtual-time-budget=30000 \
  "file:///home/suyashraj/clawd/voxdonna/design/carousel-template/project/export/voxdonna-carousel.html?only=editorial"
'
docker cp paperclip-paperclip-1:/tmp/voxdonna-carousel.pdf ~/clawd/social/linkedin-voxdonna/$(date +%Y-%m-%d).pdf
```

### Why the standalone export (not the source HTML)

The source at `project/Carousel Template.html` references external `assets/voxdonna-tokens.css`. Chromium does NOT load external CSS via `file://` URLs reliably. The source HTML renders as a 1KB blank page when rendered that way.

**Use the standalone export**: `project/export/voxdonna-carousel.html`. It is a single ~1.8MB self-contained HTML with all CSS + JS + fonts inlined. Renders cleanly to 400KB PDF.

### Why these chromium flags

- `HOME=/tmp` + `--user-data-dir=/tmp/chrome-data` — chromium needs a writable HOME for crashpad init.
- `--no-sandbox --disable-gpu --disable-dev-shm-usage` — standard container flags for Linux Docker.
- `--disable-features=Crashpad --disable-crash-reporter --crash-dumps-dir=/tmp` — Debian 13 chromium 148 has a crashpad packaging bug; the handler crashes with "--database is required" unless crashpad is fully disabled.
- `--virtual-time-budget=30000` — wait 30s for fonts + JS rendering. Less = partial render.
- `--no-pdf-header-footer` — strip page numbers / dates from PDF output.

DBus errors in stderr are non-fatal warnings (the container has no DBus socket). Look for the literal `N bytes written to file ...` line for success.

### Switching directions

The standalone export supports the same `?only=` URL parameter:
- `?only=editorial` (default — restrained, big Inter)
- `?only=operator` (mono-led, spec sheet)
- `?only=marquee` (bold display, copper glows)

### Known issue: source HTML vs export drift

The source files in `project/` and the standalone export `project/export/voxdonna-carousel.html` are independently maintained. If you edit slide-data.js in the source, the export is NOT automatically rebuilt. For a quick edit: modify `project/export/voxdonna-carousel.html` directly — its inlined `CAROUSEL.slides` array is at the top of the embedded script.

A future improvement would be a `rebuild-export.sh` that bundles the source into a new standalone export. Defer until needed.
