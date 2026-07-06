// ============================================================
// Voxdonna Carousel — sample content
// ------------------------------------------------------------
// This is the single source of truth for the demo carousel.
// The next agent edits THIS object to produce a new carousel,
// then re-renders the chosen direction to PDF or JPGs.
//
// Every slide has a `layout` matching one of these keys:
//   cover    — eyebrow + headline (multi-line) + subhead
//   section  — chapter divider (part label + title)
//   stat     — one giant number + caption + source line
//   bullets  — eyebrow + headline + 3–5 numbered items
//   compare  — before / after, two side-by-side panels
//   steps    — eyebrow + headline + 3–4 numbered process steps
//   feature  — eyebrow + headline + body + one supporting metric
//   quote    — pull-quote + attribution + role
//   cta      — eyebrow + headline + body + URL
// ============================================================

const CAROUSEL = {
  // Used only for the design-canvas header — not rendered on slides.
  title: 'What Your AI Voice Agent Should Actually Sound Like',
  slides: [
    {
      layout: 'cover',
      eyebrow: 'POV / VOICE AI 2026',
      // Each array entry is a line break in the headline.
      headline: ['The "AI Voice" Era', 'is Over.', 'Here\'s What\'s Next.'],
      subhead: 'A field note from the team building Donna.',
    },
    {
      layout: 'section',
      part: 'Part I',
      title: 'The Problem',
      kicker: 'Why most voice agents get hung up on.',
    },
    {
      layout: 'stat',
      value: '67',
      unit: '%',
      label: 'of callers hang up on an AI voice in under 8 seconds.',
      source: 'Voxdonna call analytics, 2025 — n = 10,420',
    },
    {
      layout: 'bullets',
      eyebrow: 'WHY THEY HANG UP',
      headline: 'Four tells that scream "robot."',
      items: [
        { n: '01', t: 'Dead air over 600ms', d: 'The pause between turns is the loudest signal of all.' },
        { n: '02', t: 'Flat prosody', d: 'No rise, no fall, no emphasis — just rendered text.' },
        { n: '03', t: 'Scripted recovery', d: '"I\'m sorry, I didn\'t catch that" on infinite loop.' },
        { n: '04', t: 'No working memory', d: 'Asking the customer\'s name three times in one call.' },
      ],
    },
    {
      layout: 'compare',
      eyebrow: 'BEFORE / AFTER',
      headline: 'Same caller. Two voice agents.',
      left: {
        label: 'Generic IVR-AI',
        body: '"Hello. Thank you for calling. Please state the reason for your call after the tone."',
        meta: 'Outcome — hangup at 6s',
      },
      right: {
        label: 'Donna',
        body: '"Hey — this is Donna at Pacific Plumbing. Sounds like the water heater again?"',
        meta: 'Outcome — booked, 94s',
      },
    },
    {
      layout: 'section',
      part: 'Part II',
      title: 'The Fix',
      kicker: 'A four-step deploy that actually holds up on real calls.',
    },
    {
      layout: 'steps',
      eyebrow: 'HOW TO DEPLOY',
      headline: 'A voice agent that doesn\'t get hung up on.',
      steps: [
        { n: '01', t: 'Train on your real calls', d: 'Not synthetic transcripts — 200 real recordings, minimum.' },
        { n: '02', t: 'Lock the brand voice', d: 'Cadence, vocabulary, what your agent will and won\'t say.' },
        { n: '03', t: 'Shrink the latency', d: 'Sub-200ms or callers feel the lag — and bail.' },
        { n: '04', t: 'Shadow for 14 days', d: 'Agent listens, drafts, humans approve. Then flip the switch.' },
      ],
    },
    {
      layout: 'feature',
      eyebrow: 'THE SPEED ENGINE™',
      headline: 'Sub-200ms response latency.',
      body: 'The gap between "Hi" and "Hello" is where trust lives or dies. We re-architected the stack to keep it under the threshold a human ear can detect.',
      metric: '180ms',
      metricLabel: 'P50 turn latency',
    },
    {
      layout: 'quote',
      quote: 'We replaced a $45,000-a-year receptionist with Donna in eleven days. The callers don\'t know. The bookings doubled.',
      attrib: 'Maya R.',
      role: 'Owner, Pacific Plumbing — Bellingham, WA',
    },
    {
      layout: 'cta',
      eyebrow: 'TRY IT',
      headline: 'Hear Donna handle a real call.',
      body: 'No demo gating. No sales call. Two minutes, three sample scenarios.',
      cta: 'voxdonna.com/demo',
    },
  ],
};

window.CAROUSEL = CAROUSEL;
