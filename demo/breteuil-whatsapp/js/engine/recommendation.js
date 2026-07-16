/*
 * Moteur de recommandation (version démo côté client).
 * Note le catalogue face à une "intention" structurée
 * {budget, config, city, audience, style} via un modèle pondéré transparent,
 * puis renvoie les meilleurs biens. En production, ce moteur est remplacé par un
 * service hybride règles + similarité d'embeddings. L'interface est identique.
 */
(function () {
  const within = (price, budget) => {
    if (!budget) return 1;
    // Récompense un prix juste sous le budget ; pénalise trop au-dessus / trop en-dessous.
    const r = price / budget;
    if (r <= 1.02) return 1 - Math.max(0, (0.85 - Math.min(r, 0.85))) * 0.4; // sweet spot 0.6–1.0 du budget
    if (r <= 1.25) return 0.45;        // léger dépassement — montré en "montée en gamme"
    return 0;                          // hors budget
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

  // Raison lisible que l'IA peut afficher ("pourquoi ce bien").
  function reason(p, q) {
    const bits = [];
    if (q.budget) {
      if (p.price <= q.budget) bits.push(`dans votre budget de ${(q.budget/1000000).toFixed(1).replace('.', ',')} M€`);
      else bits.push(`légèrement au-dessus du budget, mais à voir`);
    }
    const audLabel = { 'residence-secondaire':'résidence secondaire', 'residence-principale':'résidence principale',
      'investissement':'investissement', 'pied-a-terre':'pied-à-terre', 'international':'acquéreur international',
      'prestige':'prestige', 'famille':'pour une famille' };
    const aud = q.audience && (Array.isArray(q.audience) ? q.audience : [q.audience]).find(a => p.audience.includes(a));
    if (aud) bits.push(`idéal ${audLabel[aud] || aud}`);
    if (p.style.includes('vue-mer')) bits.push('vue mer');
    else if (p.style.includes('ski')) bits.push('au pied des pistes');
    else if (p.style.includes('neuf')) bits.push('neuf, frais réduits');
    else if (q.city && p.city.toLowerCase() === (q.city||'').toLowerCase()) bits.push(`au cœur de ${p.city}`);
    return bits.slice(0, 2).join(', ');
  }

  function recommend(q, n = 3) {
    return window.UNITS
      .map(p => ({ p, s: score(p, q), why: reason(p, q) }))
      .filter(x => x.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, n);
  }

  // Échéancier VEFA (vente en état futur d'achèvement) pour un prix donné — illustratif.
  function bridalAllocation(total) {   // nom conservé — app.js appelle ceci pour le renderer `alloc`
    const plan = [
      { part: 'Réservation (contrat préliminaire)', pct: 0.05 },
      { part: 'Achèvement des fondations',           pct: 0.30 },
      { part: 'Mise hors d\'eau (toiture)',          pct: 0.35 },
      { part: 'Achèvement des travaux',              pct: 0.25 },
      { part: 'À la livraison (remise des clés)',    pct: 0.05 },
    ];
    return plan.map(x => ({ ...x, amount: Math.round(total * x.pct) }));
  }

  window.RecoEngine = { recommend, bridalAllocation, score };
})();
