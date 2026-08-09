/*
 * Wholesale catalogue engine (client-side demo version).
 * Scores SKUs against a retailer intent {category, purity, ticket, tags, ready}
 * on the things a trade buyer actually optimises for: price point, margin,
 * how fast it moves, and whether it ships from ready stock.
 *
 * In production this is the ERP catalogue service plus the partner's own
 * sell-through history; the interface is identical.
 */
(function () {
  const margin = s => (s.mrp - s.wsp) / s.mrp;

  // Reward SKUs sitting at or just under the partner's target counter price point.
  function ticketFit(wsp, target) {
    if (!target) return 1;
    const r = wsp / target;
    if (r <= 1.05) return 1 - Math.max(0, 0.6 - Math.min(r, 0.6)) * 0.5;
    if (r <= 1.3) return 0.4;
    return 0;
  }

  function score(s, q) {
    let n = 0;
    n += ticketFit(s.wsp, q.ticket) * 5;
    if (q.category && s.cat === q.category) n += 3;
    if (q.line && s.line === q.line) n += 2;
    if (q.purity && s.purity === q.purity) n += 2;
    if (q.ready && s.stock === 'ready') n += 2;
    if (q.tags) (Array.isArray(q.tags) ? q.tags : [q.tags]).forEach(t => { if (s.tags.includes(t)) n += 1.8; });
    n += margin(s) * 3;              // always nudge the better-margin design up
    if (s.fast) n += 1.2;
    return n;
  }

  // The one-line justification the agent shows a retailer.
  function reason(s, q) {
    const bits = [`${Math.round(margin(s) * 100)}% margin`];
    if (s.fast) bits.push('fast mover');
    if (s.stock === 'ready') bits.push(`ready stock · ${s.lead}d`);
    else bits.push(`made to order · ${s.lead}d`);
    if (q.ticket && s.wsp <= q.ticket) bits.push('inside your price point');
    return bits.slice(0, 3).join(' · ');
  }

  function recommend(q, n = 3) {
    return window.SKUS
      .map(s => ({ p: s, s: score(s, q), why: reason(s, q) }))
      .filter(x => x.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, n);
  }

  // Sets that lift average ticket — the cross-sell a wholesaler actually pitches.
  const PAIRS = {
    pendant: ['earring'], earring: ['pendant'], ring: ['band', 'pendant'],
    mangalsutra: ['earring', 'ring'], pendantset: ['bangle'], bangle: ['pendantset'],
    bracelet: ['earring'], mensring: ['band'], nosepin: ['earring'], kids: ['pendant'],
  };
  function crossSell(sku, max = 2) {
    const wants = PAIRS[sku.cat] || [];
    return window.SKUS
      .filter(s => s.code !== sku.code && wants.includes(s.cat) && s.line === sku.line)
      .slice(0, max);
  }

  // Build an order line-set from {code, qty} pairs; totals include 3% GST on jewellery.
  const GST_RATE = 0.03;
  function buildOrder(lines) {
    const rows = lines.map(l => {
      const sku = window.SKU_BY_CODE[l.code];
      return { sku, qty: l.qty, amount: sku.wsp * l.qty };
    });
    const subtotal = rows.reduce((t, r) => t + r.amount, 0);
    const gst = Math.round(subtotal * GST_RATE);
    return { rows, subtotal, gst, total: subtotal + gst, pcs: rows.reduce((t, r) => t + r.qty, 0) };
  }

  // What the counter earns if the whole lot sells through at MRP.
  function sellThrough(order) {
    const retail = order.rows.reduce((t, r) => t + r.sku.mrp * r.qty, 0);
    return { retail, profit: retail - order.subtotal, pct: Math.round(((retail - order.subtotal) / retail) * 100) };
  }

  window.CatalogEngine = { recommend, crossSell, buildOrder, sellThrough, margin, score, GST_RATE };
})();
