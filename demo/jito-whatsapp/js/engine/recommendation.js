/*
 * Member-directory matching engine (client-side demo version).
 * Scores the directory against a structured "intent" {need, city, category, keywords}
 * using a transparent weighted model. Production replaces this with a hybrid
 * rules + embedding-similarity service. The interface is identical.
 */
(function () {
  function score(p, q) {
    let s = 0;
    if (q.need) (Array.isArray(q.need) ? q.need : [q.need]).forEach(n => {
      if (p.need.includes(n)) s += 5;
    });
    if (q.city && p.city.toLowerCase() === q.city.toLowerCase()) s += 3;
    if (q.category && p.config.toLowerCase().includes(q.category.toLowerCase())) s += 3;
    if (q.keywords) (Array.isArray(q.keywords) ? q.keywords : [q.keywords]).forEach(kw => {
      if (p.style.includes(kw) || p.desc.toLowerCase().includes(kw)) s += 1.5;
    });
    return s;
  }

  function reason(p, q) {
    const bits = [];
    if (q.city && p.city.toLowerCase() === q.city.toLowerCase()) bits.push(`based in ${p.city}`);
    const n = q.need && (Array.isArray(q.need) ? q.need : [q.need]).find(x => p.need.includes(x));
    if (n) bits.push(`verified JITO member for ${n}`);
    if (!bits.length) bits.push(`${p.township} member`);
    return bits.slice(0, 2).join(', ');
  }

  function recommend(q, n = 3) {
    return window.MEMBERS
      .map(p => ({ p, s: score(p, q), why: reason(p, q) }))
      .filter(x => x.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, n);
  }

  // Kept for the `alloc` renderer interface (unused by JITO scenarios).
  function bridalAllocation(total) {
    return [{ part: 'Allocation', pct: 1, amount: total }];
  }

  window.RecoEngine = { recommend, bridalAllocation, score };
})();
