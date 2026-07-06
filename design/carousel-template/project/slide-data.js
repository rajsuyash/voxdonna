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
  title: 'Premium Furniture: The Unanswered Phone Problem',
  slides: [
    {
      layout: 'cover',
      eyebrow: 'PREMIUM RETAIL / REVENUE CRISIS',
      headline: ['$33.2 billion', 'market. 76% buy', 'in-store. Zero', 'answer the phone.'],
      subhead: 'The journey starts with a call that nobody picks up.',
    },
    {
      layout: 'stat',
      value: '81.2',
      unit: '%',
      label: 'of luxury furniture sales happen offline, not online. The phone bridges the gap.',
      source: 'Grand View Research, Luxury Furniture Market Report, 2026',
    },
    {
      layout: 'feature',
      eyebrow: 'THE BRIDGE',
      headline: 'Shoppers Start Online.',
      body: 'Half of all buyers research fabrics, finishes, and delivery online. Then they call: "Do you have cognac in stock? What's the lead time? Can I see it Saturday?" Nobody picks up.',
      metric: '50%',
      metricLabel: 'Start research online before visiting showroom',
    },
    {
      layout: 'stat',
      value: '30',
      unit: '%',
      label: 'sales lift during tax refund season. Call volume spikes. Staffing stays flat.',
      source: 'FusionCX, Seasonal Trends in Furniture Retail, 2026',
    },
    {
      layout: 'compare',
      eyebrow: 'THE MISMATCH',
      headline: 'Your busiest season. Your worst staffing.',
      left: {
        label: 'Peak Season',
        body: 'Tax refunds. Memorial Day. Black Friday. 30-50% promotions. Phones ring nonstop.',
        meta: 'Demand',
      },
      right: {
        label: 'Your Response',
        body: 'Hiring freeze. Skeleton crew. Voicemail queue grows. Callers hang up.',
        meta: 'Supply',
      },
    },
    {
      layout: 'stat',
      value: '62',
      unit: '%',
      label: 'of business calls go unanswered. 85% of those callers never try again.',
      source: 'Aira Data Study, 2026',
    },
    {
      layout: 'feature',
      eyebrow: 'THE COST',
      headline: 'One missed call. One lost sofa.',
      body: 'Average cost per missed call: $1,000. Premium sofa inquiry: $1,000-$2,500+. 82% of customers prefer voice calls before committing thousands of dollars. Less than 3% leave voicemail.',
      metric: '85%',
      metricLabel: 'Never call back after reaching voicemail',
    },
    {
      layout: 'feature',
      eyebrow: 'THE PHONE ADVANTAGE',
      headline: 'Voice Still Wins.',
      body: 'Phone customer satisfaction: 82%. Chat: 73%. Email: 61%. Premium buyers want instant answers about availability, custom options, and delivery. Not a chatbot. Not an email chain.',
      metric: '82%',
      metricLabel: 'CSAT on voice calls',
    },
    {
      layout: 'bullets',
      eyebrow: 'THE ALTERNATIVE',
      headline: 'AI Voice Agents Scale Instantly.',
      items: [
        'Answer in under 4 rings. No staffing surge.',
        'Know your catalog. Answer availability, custom options, delivery windows instantly.',
        'Qualify leads at 9pm Saturday. Book showroom visits at 6am Monday.',
        'Scale during peak season without hiring.',
      ],
    },
    {
      layout: 'cta',
      eyebrow: 'THE FIX',
      headline: 'Your showroom closes at 6pm.',
      body: 'Your buyer\'s intent doesn\'t. Premium furniture brands are capturing the calls they used to miss.',
      cta: 'voxdonna.com',
    },
  ],
};

window.CAROUSEL = CAROUSEL;
