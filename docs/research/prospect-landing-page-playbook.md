# Prospect Landing Page Playbook for B2B AI Voice Agents — Targeting Indian Conglomerates

*Generated 2026-05-18 · Sources: 30+ vendor pages, Indian B2B SaaS analyses, DPDP regulatory primers · Confidence: High*

## Executive Summary

For Voxdonna's bespoke prospect pages (the new `/for/<slug>/` pattern), the canonical structure is a **12-section enterprise long-form** — not the 4-section SMB hero — built in the **dark, copper, Inter + JetBrains Mono Voxdonna visual register**. The single biggest conviction lever in the entire B2B voice-AI cohort is a **live embedded agent in the hero**, paired with a **portfolio-recognition band** that proves the buyer's brands were read. For Indian conglomerate buyers (Tata / Reliance / Ambuja Neotia scale), the moat is **DPDP Act 2023 framing as the wedge, not the footnote**, plus a vernacular language band (Bengali / Hindi sample lines) that no US vendor will match credibly. Tech stack: ship now on the existing static Voxdonna pattern (Hostinger webhook, 25-second deploys); migrate to **Astro 6 + Vercel + Content Collections** when prospect-page volume exceeds ~10 per month and the JSON-driven workflow pays for itself.

---

## 1. Canonical Table of Contents — 12 Sections, ~1,800–2,200 Words

Order matters. The pattern is "convince first, structure second, commit last."

| # | Section | Purpose | Length | Key proof |
|---|---------|---------|--------|-----------|
| 01 | **Hero + Live Demo** | Land the outcome line, drop the live agent | 60–80 words + widget | Embedded embedded voice widget |
| 02 | **Built-for / Trust band** | Prospect logo + "Built privately for" tag | 30 words | Prospect's own mark |
| 03 | **Stat strip (their scale)** | 4 numbers from the prospect's own site | 4 stat cards | Verified citations |
| 04 | **Portfolio recognition** | Show you read every brand they own | Chip grid | Their brand list |
| 05 | **Before / After per vertical** | "Today 6:31 PM" vs "With Voxdonna, same minute" | 3-row table | Specific scenarios |
| 06 | **Research evidence** | 4 facts from their site → why this page exists | 4 quote-cards | Verbatim quotes + source URL |
| 07 | **Architecture (4 layers)** | How it plugs into their existing stack | 4 cards | Layer-by-layer detail |
| 08 | **Use cases (5 detailed)** | 4-step flow per use case | 5 large cards | Per-step routing logic |
| 09 | **ROI math in ₹** | Numbers in lakh / crore notation | Tabular block | Conservative assumptions |
| 10 | **Multilingual band** | Bengali + Hindi + English sample quotes | 3 cards | Native script + translation |
| 11 | **vs Alternatives** | IVR / in-house / BPO / "more advisors" | 3 + 1 wide card | Concrete cost comparison |
| 12 | **Compliance (DPDP-led)** | DPDP 2023 + TRAI + sector-specific | 2-col list + note | Penalty number ₹250 Cr |
| 13 | **14-day timeline** | Day 1–3, 4–7, 8–11, 12–14 | 4-card timeline | Concrete deliverables per phase |
| 14 | **Pricing** | Pilot in ₹ + enterprise "conversation" | 2 cards | INR pilot, no annual lock |
| 15 | **Founder note** | Signed paragraph, direct email | 1 quote block | Founder credibility |
| 16 | **CTA strip** | "30 minutes, then a pilot or a polite no" | Single block | Calendly + email |

*(The 12 was the canonical minimum from the vendor research — 16 here is the actual built version for Ambuja Neotia, with portfolio band + before/after + multilingual as Indian-conglomerate adaptations.)*

### Per-section content rules

- **Hero**: name the prospect in the H1. "A voice agent built for [Prospect], before you've signed anything." No abstract claims.
- **Live demo**: must be a real working agent with the prospect's KB attached. Not a video. Not a screenshot. The single highest-conviction artifact in the entire cohort — PolyAI, Bland, Vapi, Synthflow, [voice-AI vendors] all front-load this.
- **Portfolio recognition**: chip-grid of every named brand the prospect owns, grouped by vertical, flagship brands highlighted. Replaces the generic "trusted by" logo wall.
- **Before / After**: 3 rows, one per vertical. Left column "today at 6:31 PM Monday" — describe the loss in specifics. Right column "with Voxdonna, same minute" — describe the recovery.
- **Research evidence**: quote 4 verbatim lines from their own site with source URLs. Removes the "did they actually read our site?" doubt at the start.
- **Architecture**: 4 layers max. Each layer = 1 H3 + 1 paragraph + 4 bullet sub-features.
- **Use cases**: 5 cases. Each with 4 steps (STEP 01 · STEP 02 · STEP 03 · STEP 04). One callout per case naming the business win.
- **ROI**: in **₹ lakh / ₹ crore** notation. Always with assumption disclaimer. Always with a "we'll recalibrate to your real numbers" footnote.
- **Multilingual band**: side-by-side language sample lines (native script + Latin transliteration). For Bengali HQ prospects (Kolkata): lead with Bengali, then Hindi, then English. Make the live widget the audio sample — not a separate audio player.
- **Compliance**: lead with **DPDP Act 2023 + ₹250 Cr penalty exposure**. None of the dozen US/global vendors mentions DPDP — this is the wedge.
- **Timeline**: 14 days, four phases. Concrete deliverable per phase.
- **Pricing**: INR pilot (₹1–2 L setup + per-minute). Group rollout = "conversation."
- **Founder note**: signed, with direct email. Indian buyers explicitly check founder backgrounds during procurement (cited by Sachin Bhatia / Exotel and Blume Ventures).

---

## 2. Tech Stack — Two Phases

### Now (≤10 prospect pages per month)

**Stay on the current Voxdonna static HTML + Hostinger webhook stack.**

- **Pattern**: copy `election-campaign-manager.html` as the template, edit ~40 variables per prospect, write to `/for/<slug>/index.html`, push.
- **Deploy speed**: ~25 seconds from `git push` to live at `voxdonna.com/for/<slug>/` via the Hostinger PHP receiver.
- **Pros**: zero learning curve, matches voxdonna.com design exactly, no extra hosting bill, SEO-irrelevant pages can be `<meta name="robots" content="noindex">`.
- **Cons**: no type safety on inputs; copy-paste mistakes possible; doesn't scale past ~10–20 prospect pages comfortably.

### Phase 2 — Astro 6 + Vercel (when volume justifies it)

- **Why Astro over Next**: zero-JS by default → Lighthouse 100 on a 5,000-word page with one widget; LCP < 1.2 s with the voice SDK lazy-loaded; **52 s build for 1,000 pages vs ~3 min on Next** (`Cosmic CMS benchmark, Dec 2025`).
- **Content Collections**: drop `prospects/ambuja-neotia.json` into `src/content/prospects/`, define a Zod schema once, get type-safe data with autocomplete. The killer feature for "100 prospect pages from JSON."
- **`getStaticPaths`**: one `[slug].astro` file generates every prospect page at build time.
- **embedded voice widget is a web component**: zero framework friction, no `'use client'`, no SSR mismatch.
- **Vercel Preview + Password Protection**: every push gets a unique preview URL; gated access optional via Pro plan's Advanced Deployment Protection.
- **i18n**: built-in routing for Hindi / Bengali content blocks per prospect.

### Domain pattern

`voxdonna.com/for/<slug>` — not subdomain-per-prospect.
- Subdomains require Vercel domain config per prospect (wildcard breaks on some TLDs).
- `/for/` path is shareable, brandable, and `noindex` works with one robots.txt rule for the entire folder.

### Analytics — pick Plausible + signed-URL logging

- **Plausible** ($9/mo, cookieless, 1 KB script): default page analytics, supports custom events for "widget opened" and "ROI calculator used."
- **Signed URLs via Vercel Edge Middleware**: outreach link contains `?k=<hmac>`. Middleware verifies, logs `{slug, timestamp, ip, userAgent}` to Supabase. Per-link open tracking that survives email prefetchers if signed with a one-time nonce.
- **Do not use GA4** for prospect pages — aggregate tool, wrong audience.

### Sources

- [Astro vs Next.js, 2026 benchmarks](https://www.cosmicjs.com/blog/astro-vs-nextjs-2026)
- [Astro Content Collections docs](https://docs.astro.build/en/guides/content-collections/)
- [Vercel Deployment Protection](https://vercel.com/docs/deployment-protection)
- [Plausible Analytics review, 2026](https://www.traffic-masters.net/blog/plausible-analytics-review/)

---

## 3. Design Patterns for Indian Conglomerate Buyers

### The buying committee — three readers, one scroll

Indian enterprise deals are **committee deals**. The page must satisfy:

1. **Business head** (CXO of opco / vertical lead) — outcome and revenue
2. **CIO / CTO** — integration, security, scale
3. **Group / Chairman's Office** — vendor philosophy, durability, fit with legacy

Western SaaS pages optimize for one persona. That fails for Tata, Reliance, Adani, Ambuja Neotia scale.

### Seven principles

1. **Three-layer narrative**: outcome → credibility → philosophy (in that order down the scroll).
2. **Lead with peer Indian logos**, not US Fortune 500. Yellow.ai's "Built in Bharat" wedge is the right register.
3. **DPDP signals above the fold**. Penalties up to ₹250 Cr per breach. Procurement teams gate vendors on this *now*.
4. **Pricing in ₹, with crore / lakh notation, pilot-first**. USD per-seat pricing loses Indian deals.
5. **Founder visibility section** — institution, prior work, direct mobile/email. Table stakes in India, irrelevant in the US.
6. **Detailed case studies, not single-quote tiles**. Indian RFP culture expects multi-section depth.
7. **Visual register: "premium conservative"** — sit between TCS-corporate and Razorpay-startup. Voxdonna's dark + copper + serif-italics-on-headlines is exactly the right spot.

### Three patterns to ADOPT (Indian-specific)

- **"Group" framing** — talk about the prospect as "the Group", as Tata / Aditya Birla / Ambuja Neotia describe themselves.
- **Vertical-specific compliance call-outs** — Hospitality → Ministry of Tourism + DPDP. BFSI → RBI. Voice → TRAI. Healthcare → DGHS + DPDP.
- **Warm-intro signal** — "Introduced by [mutual]" / "Trusted by [peer Group CIO]" outperforms "Book a demo."

### Three Western patterns to AVOID

- Single-CTA hero with no depth ("The AI platform for X. Book a demo.").
- "Trusted by 10,000 companies" with anonymous logos — Indian buyers want **named peers with titles**.
- Per-seat USD pricing on the public page.

### Vernacular content blocks — recommendation

**Do not fully localize the page.** Senior Indian enterprise readers — Group CIOs, Chairman's Office staff — read business English natively. Localization belongs on the **product surface** (the voice agent itself), not on the B2B landing page.

Where vernacular **does** earn its place:

- A **multilingual demonstration band** with sample agent lines in Bengali + Hindi + English (the canonical 3-card layout shipped on the Ambuja Neotia page).
- 30-second embedded audio samples in each language (the live agent counts).
- Vernacular quotes from **frontline operational staff** in a case study (kept in script).

**Do not translate** the value-prop, pricing, or compliance copy — reads as gimmicky to senior buyers.

### Trust signal stack — ranked by weight

1. Named Group customer with executive sponsor *(highest weight — replaces everything else if present)*
2. Board / Chairman's Office endorsement quote
3. DPDP Act + ISO 27001 + India data-residency badges
4. Vertical-peer Indian logos
5. Founder credibility line (institution, prior work, direct contact)
6. Concrete metric with source ("220K calls audited by [name]")
7. Sectoral regulator alignment (TRAI / RBI / Ministry of Tourism)
8. MSME / Startup India / STPI badges — useful for tier-2; **skip for Tata/Ambuja Neotia scale** (reads small)
9. Generic SOC 2 — only if also selling US

### Phrasing — works vs flops

**Works**

- "Built for the Group — deployed across hospitality, healthcare, and real-estate verticals."
- "DPDP-compliant by default. Data residency in Mumbai. DPA available at procurement."
- "Pilot tier: ₹1.5 lakh, 60 days, one project."
- "Introduced by [Group CIO peer]. Reference call available."
- "Founded by [name], ex-[institution]. Direct line: +91-…"

**Flops**

- "Revolutionary AI that disrupts customer experience." (Indian buyers read "disrupt" as instability)
- "Starting at $99/seat/month."
- "Trusted by 10,000+ businesses worldwide."
- "Book a 15-minute demo." (Too transactional for a ₹2-Cr decision)
- "We're a YC-backed startup." (Helpful in SF, neutral-to-negative for a Group buyer who wants durability)

### Sources

- [EY India — DPDP Act 2023 guide](https://www.ey.com/en_in/insights/cybersecurity/decoding-the-digital-personal-data-protection-act-2023)
- [Levo.ai — DPDP CIO roadmap](https://www.levo.ai/resources/blogs/india-dpdp-act-cio-roadmap)
- [Blume Ventures — Scaling Enterprise SaaS in India (Sachin Bhatia)](https://blume.vc/commentaries/scaling-enterprise-saas-business-in-india-a-masterclass-by-sachin-bhatia-of-exotel)
- [Sajith Pai — The Indus Valley Playbook](https://sajithpai.medium.com/the-indus-valley-playbook-a66cfae8fc90)
- [Yahoo Finance — Yellow.ai "Built in Bharat" launch](https://finance.yahoo.com/sectors/technology/articles/built-bharat-yellow-ai-launches-043000082.html)
- [Tranquility Cybersecurity — SOC 2 vs ISO 27001 for Indian startups](https://www.tcsa.in/resources/soc-2-vs-iso-27001-indian-startups)
- [EximPe — INR pricing for global SaaS in India](https://eximpe-blog.ghost.io/inr-pricing-for-global-saas-should-you-charge-indian-customers-in-rupees/)

---

## 4. Five Direct References to Study

1. **[poly.ai](https://poly.ai)** — best live-demo placement + stat-grid pattern (PolyAI lands a live widget in the hero and four hard-number case studies under it).
2. **[decagon.ai](https://decagon.ai)** — best logo-wall density + per-quote ROI number pattern.
3. **[bland.ai](https://www.bland.ai)** — best recorded-call-with-transcript + vertical-rotating headline. The recorded-call section is the most underused proof type in the entire cohort.
4. **[vapi.ai/enterprise](https://vapi.ai/enterprise)** — best enterprise-readiness checklist + lifecycle diagram.
5. **[sierra.ai](https://sierra.ai)** — best compliance/trust panel + outcome-based pricing framing.

---

## 5. Key Takeaways

1. **The live embedded agent is the single highest-conviction lever** — front-load it. Bland, PolyAI, Vapi, Synthflow, [voice-AI vendors] all do.
2. **DPDP Act framing is the Indian wedge** — no global voice-AI vendor mentions it; treat it as the moat.
3. **Vernacular belongs on the product, not in the body copy** — but a 3-card Bengali / Hindi / English sample band proves the moat without translating the whole page.
4. **Portfolio recognition replaces the "trusted by" wall** — show you read every brand they own.
5. **ROI in ₹ crore / lakh, pilot-first** — never USD per-seat for an Indian conglomerate.
6. **Tech stack — ship now on static HTML; migrate to Astro 6 + Vercel when prospect-page volume > 10/month.**
7. **Page length — enterprise long-form (1,800–2,200 words, 10–12 scroll-screens)**, not SMB hero.

---

## 6. What Ships from This Research

- `/for/ambuja-neotia/index.html` — 1,695-line bespoke Voxdonna-style long-form page for the Ambuja Neotia Group, 16 sections, live Voxdonna voice agent embedded
- `kb/ambuja-neotia-property-enquiry.md` — 162-line knowledge base feeding the agent
- `scripts/create-ambuja-neotia-agent.sh` — agent provisioning script (KB upload + agent create + voice + scope)
- This document — playbook for the next 10 prospects
