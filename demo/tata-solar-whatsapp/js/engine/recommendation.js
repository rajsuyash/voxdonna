/*
 * Recommendation engine (client-side demo version).
 * Sizes rooftop systems from a monthly electricity bill (₹8/unit avg tariff,
 * ~120 units/month generation per kW) and scores the catalog against a
 * structured "intent" {bill, kw, budget, audience, style}. The production
 * architecture replaces this with a rules + embedding-similarity service.
 */
(function () {
  const TARIFF = 8;           // ₹ per unit, average residential
  const GEN_PER_KW = 120;     // units per month per kW

  function kwFromBill(bill) {
    if (!bill) return null;
    return Math.max(1, Math.round((bill / TARIFF) / GEN_PER_KW * 2) / 2); // nearest 0.5 kW
  }

  function billFit(p, bill) {
    if (!bill) return 0.5;
    if (bill >= p.billMin && bill <= p.billMax) return 1;
    const mid = (p.billMin + p.billMax) / 2;
    const off = Math.abs(bill - mid) / mid;
    return off < 0.6 ? 0.4 : 0;
  }

  function score(p, q) {
    let s = 0;
    s += billFit(p, q.bill) * 5;
    if (q.kw && Math.abs(p.kw - q.kw) <= 0.5) s += 3;
    if (q.budget && p.price - (p.subsidy || 0) <= q.budget) s += 2;
    if (q.audience) (Array.isArray(q.audience) ? q.audience : [q.audience]).forEach(a => {
      if (p.audience.includes(a)) s += 2.5;
    });
    if (q.style) (Array.isArray(q.style) ? q.style : [q.style]).forEach(st => {
      if (p.style.includes(st)) s += 1.5;
    });
    // default to residential intent when no audience is stated
    if (!q.audience && !p.audience.includes('home') && !p.audience.includes('large-home')) s -= 3;
    return s;
  }

  // Human-readable reason the AI can show ("why this fits").
  function reason(p, q) {
    const bits = [];
    if (q.bill) {
      if (q.bill >= p.billMin && q.bill <= p.billMax) bits.push(`sized for your ₹${q.bill.toLocaleString('en-IN')}/mo bill`);
      else bits.push('worth comparing for your usage');
    }
    if (p.subsidy) bits.push(`₹${(p.subsidy/1000)}k PM Surya Ghar subsidy`);
    if (p.style.includes('battery')) bits.push('works through power cuts');
    if (p.style.includes('group-metering')) bits.push('group net metering for societies');
    return bits.slice(0, 2).join(', ');
  }

  function recommend(q, n = 3) {
    return window.SYSTEMS
      .map(p => ({ p, s: score(p, q), why: reason(p, q) }))
      .filter(x => x.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, n);
  }

  // Payment milestones for a given all-in system price (illustrative).
  function bridalAllocation(total) {   // name kept — app.js calls this for the `alloc` renderer
    const plan = [
      { part: 'Booking advance (5%)',                 pct: 0.05 },
      { part: 'Material dispatch — panels + inverter', pct: 0.60 },
      { part: 'Installation complete (roof + wiring)', pct: 0.25 },
      { part: 'Net-meter commissioning',               pct: 0.10 },
    ];
    return plan.map(x => ({ ...x, amount: Math.round(total * x.pct) }));
  }

  window.RecoEngine = { recommend, bridalAllocation, score, kwFromBill };
})();
