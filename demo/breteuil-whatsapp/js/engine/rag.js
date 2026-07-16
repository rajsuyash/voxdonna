/*
 * Retrieval-Augmented Generation — base de connaissances + retriever (démo).
 * En production, c'est un pipeline embeddings + base vectorielle. Ici, une base
 * documentaire d'usages/FAQ de l'immobilier de prestige + un retriever par mots-clés,
 * pour des réponses ANCRÉES dans de vrais documents — jamais inventées.
 */
(function () {
  // Chaque entrée = un "chunk" que le retriever peut renvoyer. `cites` = le document source affiché.
  const KB = [
    { id:'notaire', tags:['frais de notaire','notaire','frais','droits de mutation','emoluments'], cites:'Note — Frais de notaire',
      text:"Dans l'ancien, les frais de notaire représentent environ 7 à 8 % du prix (droits de mutation + émoluments + débours). Dans le neuf/VEFA, ils tombent à 2 à 3 %. Le détail chiffré figure sur votre projet d'acte avant toute signature." },
    { id:'carrez', tags:['loi carrez','carrez','surface','m2','mètres carrés','surface habitable'], cites:'Explication — Loi Carrez',
      text:"La surface loi Carrez est la surface privative des lots en copropriété (hauteur sous plafond ≥ 1,80 m, hors murs et cloisons). Elle est certifiée par diagnostic et engage le vendeur : une erreur de plus de 5 % ouvre droit à une réduction de prix." },
    { id:'dpe', tags:['dpe','diagnostic','performance énergétique','énergie','classe','passoire'], cites:'Diagnostic — DPE',
      text:"Le DPE classe le bien de A à G sur sa performance énergétique et est obligatoire dès l'annonce. Il conditionne, pour le locatif, la possibilité de louer (les classes G sont progressivement interdites). Tous nos biens affichent leur DPE sur la fiche." },
    { id:'plusvalue', tags:['plus-value','plus value','fiscalité','impôt','revente','exonération'], cites:'Fiscalité — Plus-value immobilière',
      text:"La résidence principale est totalement exonérée de plus-value à la revente. Pour une résidence secondaire ou un investissement, la plus-value est imposée puis dégressive avec la durée de détention (exonération totale après 22 ans pour l'IR, 30 ans pour les prélèvements sociaux)." },
    { id:'credit', tags:['crédit','financement','prêt','banque','taux','emprunt','mensualité'], cites:'Bureau financement',
      text:"Notre bureau financement compare pour vous les offres des banques privées (LCL Banque Privée, BNP, Société Générale et partenaires) sans frais. Les taux se situent autour de 3,55 % sur 20–25 ans (indicatif). Les banques financent généralement 70 à 90 % du prix." },
    { id:'mensualite', tags:['mensualité','emi','calculette','simulation','remboursement'], cites:'Barème indicatif de mensualités',
      text:"Ordre de grandeur à 3,55 % sur 20 ans : chaque tranche de 100 000 € empruntés ≈ 580 €/mois. Ainsi un prêt de 2 M€ ≈ 11 600 €/mois ; sur 25 ans il descend autour de 10 100 €/mois. À affiner avec votre banque." },
    { id:'compromis', tags:['compromis','promesse de vente','séquestre','rétractation','sru','signature','acte'], cites:'Processus — Compromis de vente',
      text:"On signe d'abord un compromis (ou une promesse) de vente, généralement avec un séquestre de 5 à 10 % versé chez le notaire. L'acquéreur non-professionnel dispose ensuite d'un délai de rétractation de 10 jours (loi SRU). L'acte authentique est signé environ 2 à 3 mois plus tard." },
    { id:'ifi', tags:['ifi','fortune','patrimoine','impôt sur la fortune'], cites:'Fiscalité — IFI',
      text:"L'IFI (impôt sur la fortune immobilière) s'applique au patrimoine immobilier net supérieur à 1,3 M€, selon un barème progressif de 0,5 % à 1,5 %. Certains montages (démembrement, SCI, dette d'acquisition) en réduisent l'assiette — notre notaire partenaire vous conseille." },
    { id:'international', tags:['non-résident','étranger','international','change','devise','poa','procuration'], cites:'Guide acquéreur international',
      text:"Un non-résident peut acquérir librement en France. Le financement passe par un compte non-résident ou par apport ; une procuration permet à un mandataire de signer chez le notaire. Notre desk international gère visites en visioconférence, traduction des actes et mise en relation bancaire, quel que soit le fuseau horaire." },
    { id:'vefa', tags:['vefa','neuf','garantie','gfa','décennale','achèvement','livraison','échéancier'], cites:'Achat en VEFA',
      text:"En VEFA (vente en état futur d'achèvement), vous payez selon un échéancier légal aligné sur l'avancement (fondations, hors d'eau, achèvement, livraison), sécurisé par la Garantie Financière d'Achèvement. Vous bénéficiez des garanties de parfait achèvement (1 an), biennale (2 ans) et décennale (10 ans)." },
    { id:'sci', tags:['sci','société civile','indivision','transmission','montage'], cites:'Note — Détention en SCI',
      text:"La SCI (société civile immobilière) facilite la détention à plusieurs et la transmission progressive des parts, tout en organisant la gestion. Elle est fréquente pour un bien familial ou une résidence secondaire — à arbitrer avec votre notaire selon votre fiscalité." },
    { id:'charges', tags:['charges','copropriété','syndic','entretien','provisions'], cites:'Charges de copropriété',
      text:"Les charges de copropriété couvrent gardiennage, entretien des parties communes, services et provisions pour travaux. Pour un bien de prestige avec conciergerie, spa ou piscine, elles sont plus élevées — le montant annuel et les 3 derniers procès-verbaux d'AG vous sont communiqués avant l'offre." },
    { id:'gestion', tags:['gestion locative','location','rendement','conciergerie','saisonnier'], cites:'Gestion & conciergerie',
      text:"Breteuil propose la gestion locative et la conciergerie : mise en location saisonnière ou à l'année, entretien, accueil des occupants. Sur un appartement neuf en résidence gérée, la TVA (20 %) peut être récupérée et un rendement locatif visé — notre pôle patrimoine chiffre le projet." },
    { id:'visite', tags:['visite','visite privée','visite virtuelle','visioconférence','walkthrough','vidéo'], cites:'Visites & tours virtuels',
      text:"Nos conseillers organisent des visites privées tous les jours. Impossible de vous déplacer ? Réservez une visite en visioconférence : un conseiller parcourt le bien en direct sous votre conduite, 7j/7 de 8h à 22h — la plupart de nos acquéreurs internationaux réservent ainsi avant un unique déplacement." },
  ];

  // retriever par mots-clés très simple (à la place d'une similarité vectorielle)
  function retrieve(query, k = 1) {
    const q = (query || '').toLowerCase();
    const tokens = q.split(/[^a-zàâäéèêëïîôöùûüç0-9]+/).filter(Boolean);
    const scored = KB.map(doc => {
      let s = 0;
      doc.tags.forEach(t => { if (q.includes(t)) s += 3; });
      tokens.forEach(tok => { if (tok.length > 2 && (doc.tags.some(t => t.includes(tok)) || doc.text.toLowerCase().includes(tok))) s += 1; });
      return { doc, s };
    }).filter(x => x.s > 0).sort((a, b) => b.s - a.s);
    return scored.slice(0, k).map(x => x.doc);
  }

  // Renvoie une réponse ancrée {text, cites} ou null.
  function answer(query) {
    const hits = retrieve(query, 1);
    if (!hits.length) return null;
    return { text: hits[0].text, cites: hits[0].cites };
  }

  window.RAG = { retrieve, answer, KB };
})();
