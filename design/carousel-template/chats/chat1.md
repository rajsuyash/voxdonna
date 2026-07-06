# Voxdonna Carousel Template

_Started 2026-05-27 06:43 UTC_

---

## User

Hi I want you to design a temaplte that can be used for creating carousal post on linkedin and Instagram feeed of Voxdonna, I plan to give this template to claue agent so they make ready use PDF / jpg that i can upload directly to my social media accounts

## Assistant

_[tool: questions_v2]_

## User

Questions answered:
- aspect: 1:1 square (1080×1080) — works everywhere
- slide_count: 10
- layouts_needed: Cover / hook (big headline + eyebrow), Step-by-step (numbered process), Section divider (chapter break), Quote / testimonial, CTA / closing slide, Stat hero (one giant number), Comparison (vs / before-after), Feature spotlight (icon + headline + body), Bullet list (3–5 points)
- topics: How to Guides, POV on latest developent in the field of AI 
- visual_density: Balanced — headline + supporting detail + one accent
- branding_per_slide: Small wordmark in corner of every slide
- slide_counter: Yes — small mono counter, bottom corner
- agent_handoff: Decide for me
- export_format: Both — needs to work for either
- variations: 3 directions — explore broadly

## Assistant

_[tool: update_todos]_

_[tool: list_files]_

_[tool: read_file]_

_[tool: list_files]_

_[tool: copy_files]_

_[tool: copy_starter_component]_

_[tool: image_metadata]_

_[tool: image_metadata]_

_[tool: view_image]_

_[tool: read_file]_

_[tool: write_file]_

I have enough context. Let me build the template.

_[tool: view_image]_

_[tool: write_file]_

_[tool: write_file]_

_[tool: write_file]_

_[tool: write_file]_

_[tool: grep]_

_[tool: str_replace_edit]_

_[tool: write_file]_

_[tool: show_html]_

_[tool: done]_

_[tool: fork_verifier_agent]_

Built a 3-direction carousel template at **Carousel Template.html**:

- **A · Editorial** — restrained, big Inter type, single copper hairline
- **B · Operator** — mono-led spec sheet, filename header, hairline grid
- **C · Marquee** — bold 800-weight display, copper glows, gradient accents

Each renders the same 10-slide demo carousel ("What Your AI Voice Agent Should Actually Sound Like") so you can compare aesthetics side-by-side. All 9 layouts you asked for are present (cover, section divider, stat, bullets, compare, steps, feature, quote, CTA), with the wordmark + mono counter chrome on every slide.

**For the next agent to ship a real carousel:**
1. Edit `slide-data.js` — just the `CAROUSEL.slides` array (keep `layout` keys)
2. Open `Carousel Template.html?only=editorial` (or `operator` / `marquee`) — slides stack at full 1080×1080
3. Screenshot each `<section.export-slide>` → Instagram JPGs
4. Print to PDF from the same view → LinkedIn document carousel (one slide per page)

A "How to use this template" card sits at the top of the canvas with the same instructions.

Verifier is doing a visual sweep now — I'll fix anything it flags. Once you pick a direction, I can prune the others and tighten the template for production.

## User

Verifier agent check completed

## Assistant

_[tool: show_html]_

Verifier hit an overload. Let me do a quick visual check myself.

_[tool: save_screenshot]_

_[tool: view_image]_

_[tool: multi_screenshot]_

_[tool: multi_screenshot]_

_[tool: show_html]_

Editorial looks crisp. Let me check Operator and Marquee.

_[tool: multi_screenshot]_

_[tool: show_html]_

Operator looks great. Now Marquee.

_[tool: multi_screenshot]_

_[tool: str_replace_edit]_

_[tool: show_html]_

One small fix needed — marquee cover headline wraps awkwardly. Also let me peek at the canvas view itself.

_[tool: save_screenshot]_

_[tool: view_image]_

Canvas overview reads well — the readme card sits up top, then 3 direction rows of 10 slides each. Each direction has a distinct visual identity that comes through at thumbnail scale (giant numbers in Editorial, bracket grids in Operator, copper-glow chips in Marquee).

I'll end here. Quick recap of what's shipped:

**`Carousel Template.html`** — the deliverable
- **A · Editorial** — restrained, big Inter type, single copper hairline
- **B · Operator** — mono-led spec sheet with filename header + hairline grid
- **C · Marquee** — bold display, copper glows, gradient accents

**For the next agent:**
- Edit `slide-data.js` (only the `CAROUSEL.slides` array — keep `layout` keys)
- Open `?only=editorial` / `?only=operator` / `?only=marquee` for full-size slides
- Screenshot each `<section.export-slide>` → JPGs for Instagram
- Print → PDF for LinkedIn document carousel (one 1080×1080 page per slide)

The handoff instructions are baked into the readme card at the top of the canvas, so when the agent opens the file it tells them what to do.

Once you pick a direction I can prune the other two, add the agent-facing CLAUDE.md, and add any layout variants you want (e.g. a TOC slide, a thread-style transcript slide). Let me know which direction lands.

## User

Send this design to Canva: Carousel Template.html

## Assistant

_[tool: snip]_

_[tool: tool_search_tool_bm25]_

_[tool: tool_search_tool_bm25]_

I don't see a Canva import tool wired up in this project. To send the design to Canva, please connect it from the **Connectors** panel — once connected, switching back to this tab picks it up automatically (no reload needed) and you can ask again.

**In the meantime**, do you want me to bundle the template into a single self-contained HTML file you can download? That same bundled file is what gets sent to Canva once it's connected, and it's also useful as a portable handoff to the next agent (no separate JSX/asset files to track).

## User

my canva is already connected

## Assistant

_[tool: copy_files]_

_[tool: tool_search_tool_bm25]_

Canva is connected. Let me bundle the template into a single self-contained HTML and send it.

_[tool: str_replace_edit]_

_[tool: str_replace_edit]_

_[tool: str_replace_edit]_

_[tool: str_replace_edit]_

_[tool: str_replace_edit]_

_[tool: super_inline_html]_

_[tool: show_html]_

_[tool: get_webview_logs]_

_[tool: get_public_file_url]_

Clean bundle. Now sending to Canva.

_[tool: canva__import-design-from-url]_

Sent. Open it in Canva here:

→ **[Edit in Canva](https://www.canva.com/d/gsOGRwz_91F1C0T)** (or [view-only link](https://www.canva.com/d/QI3AWAYQgBxMtqu))

One caveat — Canva imported the design as a single page (it captured the design canvas view, not the per-slide stack). If you want each of the 30 slides as a separate Canva page, the cleanest move is to pick one direction first (A · Editorial, B · Operator, or C · Marquee), then re-send `?only=<direction>` which renders the 10 slides as separate `<section>` blocks — much more likely to come in as a 10-page deck. Just say the word and I'll re-send.

