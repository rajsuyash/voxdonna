# Voxdonna Carousel Generation — Canonical Reference

**For ANY agent writing/posting social carousels (LinkedIn, Instagram, Twitter, etc.):**

→ READ THIS FILE FIRST: `~/clawd/voxdonna/design/CAROUSEL-TEMPLATE-INSTRUCTIONS.md`

→ TEMPLATE LIVES AT: `~/clawd/voxdonna/design/carousel-template/`

The old `gen_carousel_pdf.js` at `~/clawd/social/linkedin-voxdonna/gen_carousel_pdf.js` is **DEPRECATED 2026-05-27** — its outputs violated every brand rule (Helvetica font + pink-red accent instead of copper + flat gray text). Do not invoke it.

The new template uses headless Chrome / Puppeteer to render the HTML template into PDF or per-slide JPGs at 1080×1080 with proper Voxdonna design tokens (Inter font, copper `#c17f59` accent, off-white on black).
