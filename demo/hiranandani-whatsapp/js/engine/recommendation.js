/*
 * Recommendation engine (client-side demo version).
 * Scores the residence catalog against a structured "intent"
 * {budget, config, city, audience, style} using a transparent weighted model,
 * then returns ranked matches. The production architecture replaces this with a
 * hybrid rules + embedding-similarity service. The interface is identical.
 */
(function () {
  const within = (price, budget) => {
    if (!budget) return 1;
    // Reward fitting just under budget; penalise far-over and far-under.
    const r = price / budget;
    if (r <= 1.02) return 1 - Math.max(0, (0.85 - Math.min(r, 0.85))) * 0.4; // sweet spot 0.6–1.0 of budget
    if (r <= 1.25) return 0.45;        // slight stretch — still show as "upsell"
    return 0;                          // out of range
  };

  function score(p, q) {
    let s = 0;
    s += within(p.price, q.budget) * 5;
    if (q.config && p.config.toLowerCase().startsWith(q.config.toLowerCase())) s += 3;
    if (q.city && p.city.toLowerCase() === q.city.toLowerCase()) s += 2.5;
    if (q.audience) (Array.isArray(q.audience) ? q.audience : [q.audience]).forEach(a => {
      if (p.audience.includes(a)) s += 2.5;
    });
    if (q.style) (Array.isArray(q.style) ? q.style : [q.style]).forEach(st => {
      if (p.style.includes(st)) s += 1.5;
    });
    return s;
  }

  // Human-readable reason the AI can show ("why this fits").
  function reason(p, q) {
    const bits = [];
    if (q.budget) {
      if (p.price <= q.budget) bits.push(`fits your ₹${(q.budget/10000000).toFixed(1)}Cr budget`);
      else bits.push(`a small stretch above budget but worth a look`);
    }
    const aud = q.audience && (Array.isArray(q.audience) ? q.audience : [q.audience]).find(a => p.audience.includes(a));
    if (aud) bits.push(`great ${aud.replace('-', ' ')} pick`);
    if (p.style.includes('ready')) bits.push('ready to move, zero GST');
    else if (q.city && p.city.toLowerCase() === (q.city||'').toLowerCase()) bits.push(`right in ${p.city}`);
    return bits.slice(0, 2).join(', ');
  }

  function recommend(q, n = 3) {
    return window.UNITS
      .map(p => ({ p, s: score(p, q), why: reason(p, q) }))
      .filter(x => x.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, n);
  }

  // Construction-Linked Plan split for a given all-in price (illustrative).
  function bridalAllocation(total) {   // name kept — app.js calls this for the `alloc` renderer
    const plan = [
      { part: 'Booking + agreement (10%)',      pct: 0.10 },
      { part: 'Plinth & podium slabs',          pct: 0.20 },
      { part: 'Mid-rise slabs (up to 12th)',    pct: 0.30 },
      { part: 'Top-out + MEP & finishes',       pct: 0.25 },
      { part: 'On possession (incl. OC)',       pct: 0.15 },
    ];
    return plan.map(x => ({ ...x, amount: Math.round(total * x.pct) }));
  }

  window.RecoEngine = { recommend, bridalAllocation, score };
})();
