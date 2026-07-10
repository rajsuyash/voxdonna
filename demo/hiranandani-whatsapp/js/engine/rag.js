/*
 * Retrieval-Augmented Generation — demo knowledge base + retriever.
 * In production this is an embeddings + vector-DB pipeline. Here we ship a curated
 * knowledge base of home-buying policies/FAQs and a lightweight keyword retriever,
 * so answers are GROUNDED in real documents — not invented.
 */
(function () {
  // Each entry = a "chunk" the retriever can return. `cites` = the source document label shown to the user.
  const KB = [
    { id:'rera', tags:['rera','registration','registered','maharera','legal','approved'], cites:'RERA Compliance Note',
      text:'Every Hiranandani project phase is MahaRERA registered — the registration number is printed on the project page, brochure and cost sheet. RERA protects you with a defined possession date, carpet-area-based pricing, and an escrow account for your payments.' },
    { id:'carpet', tags:['carpet','built up','builtup','super built','area','sqft','usable'], cites:'Carpet Area Explainer',
      text:'Carpet area is the usable floor area inside your walls — the number RERA requires us to quote. Built-up adds wall thickness; super built-up adds common areas. All our pricing is on RERA carpet area, so you compare apples to apples.' },
    { id:'stamp', tags:['stamp','duty','registration charge','registry','govt charge'], cites:'Stamp Duty & Registration',
      text:'In Maharashtra, stamp duty is typically 6% of agreement value in Mumbai/Thane/Navi Mumbai (5% + 1% metro cess) plus registration of ₹30,000 or 1% (whichever is lower). Women buyers get a 1% stamp-duty concession. Exact numbers appear on your cost sheet before you sign anything.' },
    { id:'gst', tags:['gst','tax','under construction','5%','1%'], cites:'GST on Homes',
      text:'Under-construction homes attract 5% GST (1% for affordable category) with no input credit. Ready-to-move homes with Occupancy Certificate attract NO GST — one reason our ready inventory is popular.' },
    { id:'clp', tags:['payment plan','clp','construction linked','plp','possession linked','schedule','instalment'], cites:'Payment Plans',
      text:'We offer a Construction-Linked Plan (CLP) — you pay in slabs as the tower rises (typically 10% booking, then milestone demands), so your money tracks real progress. Select inventory also has possession-linked and down-payment plans with a pricing benefit. Your RM shares the exact schedule on the cost sheet.' },
    { id:'booking', tags:['booking','token','eoi','advance','blocking','hold','cancellation'], cites:'Booking Process',
      text:'You can hold a unit with a fully-refundable Expression of Interest (typically ₹1–2 lakh, SAMPLE) valid 7 days while you decide. On booking, you pay 9.99% + sign the application; the agreement is registered after 10%. Cancellation and refund terms are printed on the application form.' },
    { id:'loan', tags:['home loan','loan','bank','approval','eligibility','sanction','apf'], cites:'Home Loan Desk',
      text:'All our projects are APF-approved with leading banks — SBI, HDFC, ICICI, Axis and more — so sanction is fast (often 3–5 working days with income documents). Our in-house loan desk gets you 2–3 competing offers at no charge; current rates start around 8.35% (indicative).' },
    { id:'emi', tags:['emi','instalment','monthly','interest','tenure','calculator'], cites:'EMI Ready Reckoner',
      text:'Rough reckoner at 8.35% for 20 years: every ₹10 lakh of loan ≈ ₹8,600/month EMI. So a ₹80 lakh loan ≈ ₹68,700/month; stretching to 25 years lowers it to roughly ₹63,500. Banks typically fund 80–90% of agreement value.' },
    { id:'nri', tags:['nri','abroad','overseas','oci','power of attorney','poa','repatriation','fema'], cites:'NRI Buyer Guide',
      text:'NRIs and OCIs can buy residential property in India under FEMA — payment via NRE/NRO accounts, and a registered Power of Attorney lets family complete signatures in India. Our NRI desk handles video walkthroughs, document couriering and loan tie-ups across time zones.' },
    { id:'possession', tags:['possession','oc','occupancy','handover','fit out','keys'], cites:'Possession & Handover',
      text:'Possession follows the Occupancy Certificate (OC). You get a snag-walkthrough with our team, a demand letter for the final instalment, and handover of keys + society documents. RERA timelines for your phase are on the registration page.' },
    { id:'maintenance', tags:['maintenance','society','cam','charges','monthly outgoing'], cites:'Township Maintenance',
      text:'Township common-area maintenance is billed per sqft monthly (SAMPLE range ₹4–6/sqft) and covers security, landscaping, clubhouse and services. The first 12–24 months are typically collected in advance at possession; thereafter the estate management bills quarterly.' },
    { id:'upgrade', tags:['upgrade','exchange','resale','sell current flat','bigger home'], cites:'Upgrade Programme',
      text:'Upgrading within a Hiranandani township is common — our resale desk can list your current home to verified buyers while you book the larger one, and align both timelines so you move once, not twice.' },
    { id:'visit', tags:['site visit','show flat','sample flat','virtual tour','video call','walkthrough'], cites:'Site Visit & Virtual Tours',
      text:'Show flats are open every day at all three townships (10:00–19:30). Can’t travel? Book a live video walkthrough — a relationship manager walks the actual show flat and township on camera, any day 9am–9pm IST.' },
    { id:'amenities', tags:['amenities','school','hospital','club','pool','sports','township','walk to work'], cites:'Township Living',
      text:'Hiranandani townships are self-contained: schools, hospitals, high-street retail, clubhouses, sports facilities and offices inside the gates. Powai spans 250 acres; Fortune City Panvel is Navi Mumbai’s largest integrated township with school, hospital and sports complex already operational.' },
    { id:'appreciation', tags:['appreciation','investment','rental','yield','airport','infrastructure','resale value','atal setu'], cites:'Location & Infrastructure Note',
      text:'Panvel sits on the Navi Mumbai International Airport corridor with the Atal Setu cutting travel time to South Mumbai; Thane’s Ghodbunder Road connects both expressways; Powai remains one of Mumbai’s strongest rental markets thanks to walk-to-work offices. (Illustrative; past performance ≠ guarantee.)' },
  ];

  // very small keyword retriever (stand-in for vector similarity)
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

  // Returns a grounded answer object {text, cites} or null.
  function answer(query) {
    const hits = retrieve(query, 1);
    if (!hits.length) return null;
    return { text: hits[0].text, cites: hits[0].cites };
  }

  window.RAG = { retrieve, answer, KB };
})();
