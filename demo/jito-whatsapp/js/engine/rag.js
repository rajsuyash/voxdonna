/*
 * Retrieval-Augmented Generation — demo knowledge base + retriever.
 * Curated KB of JITO wings/policies (facts from public sources, terms marked SAMPLE
 * where unverified) + a lightweight keyword retriever, so answers are GROUNDED.
 */
(function () {
  const KB = [
    { id:'about', tags:['about','jito','what is','organisation','organization','mission'], cites:'About JITO',
      text:'JITO — the Jain International Trade Organisation — is a global not-for-profit uniting Jain businessmen, industrialists and professionals through city chapters and zones worldwide, working on economic empowerment, education and community service with an ethics-first charter.' },
    { id:'membership', tags:['membership','join','member','fees','eligibility','tier'], cites:'Membership Guide',
      text:'Membership is open to members of the Jain community in business or professional life, through your nearest city chapter. Tiers typically include Life and Patron categories (fees vary by chapter — SAMPLE; your chapter confirms the current schedule). One membership opens every wing: JBN, education programmes, JIIF, matrimony and events.' },
    { id:'jbn', tags:['jbn','business network','referral','networking','chapter meeting','guest'], cites:'JBN Handbook',
      text:'JBN — JITO Business Network — runs structured chapter meetings where members exchange business referrals, one member per business category. Guests may attend their first meeting by invitation to experience the format before applying. Referrals are tracked and celebrated chapter-wise.' },
    { id:'jatf', tags:['jatf','upsc','civil services','ias','cet','coaching','administrative'], cites:'JATF Prospectus',
      text:'JATF — the JITO Administrative Training Foundation — prepares Jain graduates for the UPSC Civil Services with subsidised coaching, lodging and boarding. Admission is via a two-stage process: the CET written exam, then an interview. CET-2026 applications are open. The community celebrated 35 Jain officers in the 2025 UPSC results.' },
    { id:'eduloan', tags:['education loan','interest subsidy','study abroad','student loan','bank loan'], cites:'Education Loan Scheme',
      text:'The JITO education-loan scheme provides an interest subsidy on loans students take from banks or NBFCs, including for studies abroad — you borrow from the bank at its rate (from around 9.1%, indicative) and JITO’s subsidy reduces the effective interest burden (SAMPLE terms; the education desk confirms current percentages and caps).' },
    { id:'connect', tags:['jito connect','trade fair','expo','stall','exhibition','visitor pass'], cites:'JITO Connect Brief',
      text:'JITO Connect is the flagship global trade fair — the recent Hyderabad edition ran 100+ stalls with startups, industry leaders and a deal arena. Members can book exhibition stalls or free visitor passes; stall categories and pricing come from the organising committee (SAMPLE until published).' },
    { id:'convention', tags:['convention','apex','summit','conclave','annual event'], cites:'Apex Convention Note',
      text:'The JITO Apex convention gathers the global JITO Pariwar — keynotes, trade exhibitions, wing showcases, and community programmes including matrimonial meets for young adults. Chapters coordinate delegate registration.' },
    { id:'matrimony', tags:['matrimony','matrimonial','match','marriage','rishta','profile'], cites:'JITO Matrimony Policy',
      text:'JITO Matrimony is completely free of cost — you can create a profile, explore and connect without any charges. Profiles are community-verified and contact details stay private until both families consent. Convention matrimonial meets offer in-person introductions.' },
    { id:'jan', tags:['angel network','jan','jiif','startup','funding','invest','pitch'], cites:'JAN / JIIF Overview',
      text:'JAN — the JITO Angel Network under JIIF — is a sector-agnostic angel network investing in early-stage startups from seed to Series A, with cheques up to $1.5 million, leading and co-investing in rounds. It has invested over ₹106 crore across 56+ startups, backed by 1,000+ Jain investor members. Founders pitch through the JIIF screening process.' },
    { id:'investor', tags:['become investor','angel investor','join jiif','invest in startups'], cites:'JIIF Investor Onboarding',
      text:'JITO members can join JIIF as angel investors to access screened dealflow, co-invest alongside experienced leads, and attend pitch days. Minimum ticket sizes and membership terms come from the JIIF desk (SAMPLE until confirmed).' },
    { id:'youth', tags:['youth wing','young','next gen','students wing'], cites:'JITO Youth Wing',
      text:'The JITO Youth wing runs leadership programmes, business plan competitions, mentorship circles with senior members, and career guidance for the community’s next generation.' },
    { id:'ladies', tags:['ladies wing','women','mahila','jlw'], cites:'JITO Ladies Wing',
      text:'The JITO Ladies wing drives women-entrepreneur programmes, skill development, exhibitions for women-led businesses and community-service initiatives across chapters.' },
    { id:'seva', tags:['medical','emergency','help','assistance','blood','hospital','seva','donation','csr','80g'], cites:'Community Seva & Assistance',
      text:'JITO chapters coordinate community assistance — medical-emergency support, blood-donor coordination and hospital tie-ups — via the chapter helpdesk. Donations to eligible JITO foundations carry 80G tax receipts, issued digitally (the chapter office confirms eligibility per programme).' },
    { id:'ethics', tags:['ethics','values','code of conduct','ahimsa','principles'], cites:'Code of Ethics',
      text:'JITO’s charter is ethics-first, rooted in Jain values — integrity in trade, non-violence, and giving back. Members commit to a code of conduct; disputes between members are encouraged to resolve through chapter-level mediation.' },
  ];

  function retrieve(query, k = 1) {
    const q = (query || '').toLowerCase();
    const tokens = q.split(/[^a-z0-9]+/).filter(Boolean);
    const scored = KB.map(doc => {
      let s = 0;
      doc.tags.forEach(t => { if (q.includes(t)) s += 3; });
      tokens.forEach(tok => { if (doc.tags.some(t => t.includes(tok)) || doc.text.toLowerCase().includes(tok)) s += 1; });
      return { doc, s };
    }).filter(x => x.s > 0).sort((a, b) => b.s - a.s);
    return scored.slice(0, k).map(x => x.doc);
  }

  function answer(query) {
    const hits = retrieve(query, 1);
    if (!hits.length) return null;
    return { text: hits[0].text, cites: hits[0].cites };
  }

  window.RAG = { retrieve, answer, KB };
})();
