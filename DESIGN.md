# Design System — Voxdonna

## Product Context

- **What this is:** Enterprise B2B AI voice agent platform. Donna runs 24/7 conversational AI across phone, web, and messaging — answering inbound calls, qualifying outbound leads, taking warranty intakes, dispatching field techs.
- **Who it's for:** Revenue ops leaders, contact center directors, manufacturing aftermarket teams, B2B sales VPs. Decision-makers who buy + technical evaluators who pilot.
- **Space/industry:** Voice AI / Conversational AI. Adjacent: contact center as a service (CCaaS), CRM, ERP integrations, manufacturing aftermarket, B2B SaaS.
- **Project type:** Marketing site + live demo gallery (12 use cases) + multilingual blog (EN/FR/IT). Static HTML + GSAP for motion. Hosted on Hostinger with GitHub-driven deploys.

## Aesthetic Direction

- **Direction:** Industrial luxury. Dark, confident, technical. Apple meets foundry.
- **Decoration level:** Intentional — type and motion carry the work; decoration appears only when it adds meaning (subtle gradients, copper edge highlights, scroll-driven entrances).
- **Mood:** The product is enterprise-grade voice AI for serious revenue conversations. The site should feel like the most expensive version of itself — confident enough to use serif headlines, restrained enough to never look decorative. Premium, not playful. Editorial, not corporate.
- **Reference vibe:** Linear (restraint), Stripe (data clarity), Vercel (motion), with Apple's editorial pacing.

## Typography

- **Display/Hero + UI + Body:** `Inter` (300, 400, 500, 600, 700, 800) — does all the work. Hero h1 uses 700 weight + tight letter-spacing for confident impact. Body uses 300-400.
- **Data/tabular:** `Inter` with `font-variant-numeric: tabular-nums` for ROI calculator output, pricing numbers, stats.
- **Code/technical:** `JetBrains Mono` (400, 500, 700) — for the scramble-headline matrix effect, code samples, and the `data-i18n-scramble` typewriter sections.
- **Loading strategy:** Single Google Fonts `<link>` on every page with Inter + JetBrains Mono. Preconnect to `fonts.googleapis.com` and `fonts.gstatic.com`. `display=swap` to avoid invisible-text flash.
- **Scale (responsive via clamp):**
  - Hero h1: `clamp(42px, 7vw, 80px)` — Inter 700, letter-spacing -0.04em, line-height 1.05
  - Section hero h1: `clamp(32-40px, 5-6vw, 56-68px)` — Inter 700
  - Section scramble headline: `clamp(36px, 5vw, 64px)` — JetBrains Mono 700
  - Use-case scroll headline: `clamp(36px, 5vw, 64px)` — Inter 700
  - Body large: `clamp(16px, 2.2vw, 22px)` — Inter 300
  - Body: `15-18px` — Inter 400
  - UI/labels: `13-14px` — Inter 400 or 500
  - Tags/eyebrows: `11-12px`, letter-spacing `0.12em`, uppercase — Inter 600

**Note (2026-05-08):** Instrument Serif was tried and reverted — Inter alone holds the brand voice better for this product.

## Color

- **Approach:** Restrained. Copper is the only accent. Everything else is neutral or semantic. Color is rare and meaningful.
- **Background:**
  - Primary: `#0a0a0c` (true black with a hint of warmth — never `#000`)
  - Subtle surface: `rgba(255, 255, 255, 0.02)` (used for cards, demo blocks)
  - Raised surface: `rgba(255, 255, 255, 0.04)` (used for hover state, primary cards)
- **Text:**
  - Primary: `#f5f5f7` (off-white, never pure white — premium feel)
  - Secondary: `rgba(245, 245, 247, 0.6)` (60% opacity off-white)
  - Tertiary/muted: `rgba(245, 245, 247, 0.4)`
- **Accent (copper — the brand):**
  - Copper primary: `#c17f59` (use for borders, key CTAs, link hovers, statuses)
  - Copper light: `#d4a574` (use for hero italic words, gradient endpoints, tag text)
  - Copper soft (12% alpha): `rgba(193, 127, 89, 0.12)` (use for tag backgrounds, soft glow)
  - Copper border (25% alpha): `rgba(193, 127, 89, 0.25)`
- **Semantic colors (NEW — codified May 2026):**
  - Success: `#5cb85c` (slightly desaturated green to fit the dark palette — for "live", "delivered", "approved" states)
  - Warning: `#d4a574` (use copper-light, already on brand)
  - Error: `#e57373` (warm red, not surgical — for "ended" with error, validation failures)
  - Info: `#7da9c4` (muted blue, low saturation — for tooltips, info badges)
- **Reserved/unused:** `#2d5c4f` teal — exists in tokens but currently unused. Either remove or formalize as a secondary cool counterweight for technical diagrams.
- **Dark mode:** This site is dark-mode-only. Do not add a light-mode toggle without explicit redesign — every visual decision (text shadow, surface alpha, copper saturation) assumes a dark canvas.

## Spacing

- **Base unit:** 8px.
- **Density:** Comfortable. The product is enterprise B2B — spacing should feel confident, not cramped.
- **Scale:**
  - 2xs: 2px (1px borders, hairlines)
  - xs: 4px (icon padding, tight row gaps)
  - sm: 8px (button padding, small gaps)
  - md: 16px (component padding, list item gaps)
  - lg: 24px (card padding, section internal gaps)
  - xl: 32px (card-to-card gaps, dialog padding)
  - 2xl: 48px (page horizontal padding, section padding inner)
  - 3xl: 64px (between major content blocks)
  - 4xl: 120px (section padding top/bottom — `.pillars-section`, `.voice-caps-section`, etc.)

## Layout

- **Approach:** Hybrid. Grid-disciplined for app/data sections (pricing, features, blog grid, demo cards). Editorial / scroll-driven for hero, use-case showcase, scroll-pinned sequences.
- **Grid:**
  - Marketing sections: 12-column on desktop, 1-column mobile
  - Pricing: 3 columns on desktop, 1 column mobile
  - Demo cards: 3 columns (1200px) → 2 (≤1024px) → 1 (≤640px)
  - Pillars: 3 columns desktop, 1 mobile
- **Max content width:** 1200px (sections), 720px (text-heavy paragraphs).
- **Border radius:**
  - Hairline: `4px` (rare — debug states only)
  - Default: `12px` (cards, demo blocks, surfaces)
  - Hero/large: `20px` (use-case cards, blog featured card)
  - Pill: `999px` (tags, nav CTA, status pills, language toggle)

## Motion

- **Approach:** Intentional. Motion is purposeful — scroll-driven storytelling, hover state feedback, entrance animations. Never decorative.
- **Library:** GSAP 3.12.5 + ScrollTrigger. Already loaded on all pages.
- **Easing:**
  - Enter (fade-in, slide-up): `power3.out`
  - Exit/dismiss: `power2.in`
  - Cross-fade / position: `cubic-bezier(0.16, 1, 0.3, 1)` (Apple-style)
  - Scroll-pinned horizontal scroll: `none` (linear scrub for direct manipulation)
- **Duration:**
  - Micro (hover state, button press): 150-250ms
  - Short (entrance, card lift): 350-600ms
  - Medium (scroll-pinned sequence): 600-1200ms total via scrub
  - Long (hero text reveal, scramble effect): 800-1500ms
- **Established patterns:**
  - `fade-in` + `IntersectionObserver` for entrance reveals
  - `scrub: 0.6` on ScrollTrigger for smooth scroll-driven horizontal pin
  - `data-scramble` + `data-trigger="scroll"` for matrix-style headline reveals (uses JetBrains Mono)
  - Card hover: `transform: translateY(-6px)` + soft copper glow shadow

## Icons

- **Style:** SVG line icons, 2px stroke width, rounded line caps and joins, currentColor stroke. No filled icons. No icon system library — handwritten inline SVG so they color-match copper accents on hover.
- **Sizes:** 18px (in buttons), 24px (standalone CTAs), 32-40px (feature card emblems).

## Brand Voice (visual coherence with copy)

- Builder-tone, not corporate. No AI clichés. No "delve / robust / comprehensive" anywhere — code, copy, marketing, blog.
- Concrete examples over abstract claims. Real numbers (with sources). Real industry vocab (BOM, CMMS, IWRC, PIN, lockout-tagout) where natural.
- Short paragraphs. Builder energy.

## Patterns & Components

### Buttons

- **Primary:** copper `#c17f59` background, `#0a0a0c` text, 999px radius, 10-12px vertical padding × 20-24px horizontal. Hover: lighter copper, no transform.
- **Ghost:** transparent background, 1px border `rgba(193, 127, 89, 0.4)`, copper-light text. Hover: copper background fill.
- **Icon button (in cards):** transparent, copper-light text + icon, 14px font, becomes white text on hover.

### Cards

- **Base:** `rgba(255,255,255,0.04)` background gradient → `rgba(255,255,255,0.01)`, 1px border `rgba(255,255,255,0.08)`, 12-20px radius, 24-32px padding.
- **Hover:** `translateY(-6px)`, border `rgba(193, 127, 89, 0.45)`, shadow `0 20px 60px -10px rgba(193, 127, 89, 0.25)`, copper glow gradient overlay.
- **Featured (emphasis):** background gradient `rgba(193, 127, 89, 0.18) → rgba(193, 127, 89, 0.06)`, copper border.

### Tags / Eyebrows

- 11-12px, weight 600, letter-spacing 0.12em, uppercase.
- Background `rgba(193, 127, 89, 0.12)`, border `rgba(193, 127, 89, 0.25)`, color `#d4a574`, 999px radius, 6px × 12px padding.

### Status indicators (live calls)

- Dot + label: 8px circle in semantic color (success / error / warning / info), 13px label in same color.
- Animated pulse: scale 1 → 1.3, opacity 1 → 0, infinite, 1.5s cycle.

### Section structure

- Section label (eyebrow): 11px copper-light, uppercase, letter-spacing 0.16em, centered above headline
- Section headline: Instrument Serif (or scramble-headline mono) — clamp(36-64px) — center-aligned
- Section subtitle: `clamp(16-22px)` Inter 300, max-width 720px, line-height 1.6, color `--text-secondary`, centered
- Content (cards/grids): below subtitle with 64px gap

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-05-08 | Initial DESIGN.md created | First formal design system doc. Codifies what works. |
| 2026-05-08 | Tried Instrument Serif on display, reverted | User feedback: didn't fit the brand voice. Inter 700 stays the display font. |
| 2026-05-08 | Codify semantic color palette | success/warning/error/info now official. Previously inferred from context. |
| 2026-05-08 | Keep scramble-headline in JetBrains Mono | Deliberate techie effect. Mono is part of the visual texture for that pattern. |
| 2026-05-08 | Dark-mode-only confirmed | No light mode planned. All decisions assume dark canvas. |
| 2026-05-08 | Copper `#c17f59` is THE brand | No competitor uses this. Codified as the only accent. |

---

**Always read this file before making any visual or UI decisions. Do not deviate without explicit user approval.**
