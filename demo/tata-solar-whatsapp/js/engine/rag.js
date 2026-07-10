/*
 * Retrieval-Augmented Generation — demo knowledge base + retriever.
 * In production this is an embeddings + vector-DB pipeline. Here we ship a curated
 * knowledge base of rooftop-solar policies/FAQs and a lightweight keyword retriever,
 * so answers are GROUNDED in real documents — not invented.
 * Figures reflect public 2025-26 norms (PM Surya Ghar guidelines, discom timelines).
 */
(function () {
  const KB = [
    { id:'subsidy', tags:['subsidy','surya ghar','pm surya','muft bijli','78000','30000','60000','government','scheme'], cites:'PM Surya Ghar Guidelines',
      text:'PM Surya Ghar Muft Bijli Yojana subsidy: ₹30,000 for 1 kW, ₹60,000 for 2 kW, and ₹78,000 for 3 kW or larger (that is the cap — a 5 kW system still gets ₹78,000). It is credited directly to your bank account, typically 4–8 weeks after net-meter commissioning. Not taxable.' },
    { id:'eligibility', tags:['eligible','eligibility','who can apply','dcr','domestic content','apply','portal','registration'], cites:'Subsidy Eligibility Checklist',
      text:'To claim the subsidy you need: a residential connection in your name, an own roof (tenants need a notarized NOC from the owner), DCR (made-in-India) panels, and registration on the national portal — pmsuryaghar.gov.in. We handle the portal application, discom feasibility and paperwork for you.' },
    { id:'netmeter', tags:['net meter','net metering','discom','approval','export','grid','bidirectional','timeline'], cites:'Net Metering Process Note',
      text:'Net metering lets your meter run both ways — you are billed only on net units (import minus export). Process: discom application → feasibility approval (15–30 days) → installation → meter inspection and swap (~30 days). Realistically allow 1–3 months end to end; we track and chase every stage for you. Meter fee is typically ₹1,000–3,000.' },
    { id:'docs', tags:['documents','paperwork','aadhaar','bill copy','noc','property','proof','checklist'], cites:'Documents Checklist',
      text:'Documents needed: photo ID (Aadhaar/PAN/voter ID), your latest electricity bill, property ownership proof, a passport photo, and your bank details for the subsidy credit. Tenants add a notarized NOC. That is the whole list — most rejections come from mismatched names between the bill and the application, which we pre-check.' },
    { id:'payback', tags:['payback','roi','return','savings','worth it','profit','investment'], cites:'Savings & Payback Reckoner',
      text:'A 3 kW system generates ~360 units/month. At ₹8/unit that is ~₹2,900/month saved, ~₹34,500/year. Net cost after the ₹78,000 subsidy is ~₹1.2 lakh → payback in 3–4 years, then 20+ years of near-free power. Rooftop solar returns 18–25% a year — a fixed deposit pays 6–7%.' },
    { id:'powercut', tags:['power cut','outage','blackout','grid down','night','backup','load shedding'], cites:'On-Grid Behaviour Note',
      text:'Honest answer: a standard on-grid system shuts off during a power cut — a safety requirement (anti-islanding) so linemen are not electrocuted by your export. If outages are common in your area, choose the hybrid system: its battery keeps essential loads running through cuts and evenings.' },
    { id:'hybrid', tags:['hybrid','battery','storage','kwh','backup system','inverter battery'], cites:'Hybrid Systems Explainer',
      text:'A hybrid system adds a battery: solar powers the home and charges the battery by day; the battery takes over during cuts and evenings. It costs more upfront (a 3 kW hybrid with 5 kWh battery runs ~₹3.4 lakh before subsidy) but removes dependence on grid reliability. Subsidy applies on the solar portion.' },
    { id:'maintenance', tags:['maintenance','cleaning','amc','service','dust','upkeep','wash'], cites:'Maintenance & AMC Note',
      text:'Panels mainly need cleaning — dust can cost you 10–15% generation. We recommend cleaning every 2–4 weeks (more in dusty areas). Our AMC covers scheduled cleaning, electrical inspection and priority service at ₹2,500–4,000 per kW per year for homes. Your app flags generation drops automatically.' },
    { id:'warranty', tags:['warranty','guarantee','panel life','inverter life','25 years','replace'], cites:'Warranty Card',
      text:'Panels carry a 25-year performance warranty (at least 80% output in year 25) and inverters 5–10 years depending on model. Tata Power Solar has made panels since 1989 — the company will be around for year 25 of your warranty. Registration is automatic at commissioning.' },
    { id:'monsoon', tags:['monsoon','rain','cloud','winter','generation drop','season'], cites:'Seasonal Generation Note',
      text:'Cloudy and monsoon months generate 40–60% of peak — the annual average already accounts for this, which is why we quote ~120 units/kW/month as a yearly figure. Rain actually helps by washing the panels. Your monitoring app shows the seasonal curve, so a July dip is expected, not a fault.' },
    { id:'society', tags:['society','rwa','apartment','flat','housing society','common area','group net metering'], cites:'Housing Society Guide',
      text:'Housing societies install solar on the common-area meter (lifts, pumps, lobby lighting) using group net metering. We need: an RWA/managing-committee resolution, the last 6 months of common-area bills, and the society registration/OC. Typical result: 60–90% off the common-area bill, which directly cuts every member’s maintenance.' },
    { id:'finance', tags:['emi','loan','finance','instalment','down payment','tenure','collateral'], cites:'Solar Financing Desk',
      text:'Residential financing runs up to 10 years through partner institutions — entry offers start around ₹7,499 upfront with ~₹2,499/month EMIs for a 2 kW system. For MSMEs, the SunSmart Flexi EMI plan lets the system pay for itself from the electricity savings, no collateral. Loan + subsidy can be combined.' },
    { id:'ci', tags:['capex','opex','ppa','resco','commercial','industrial','factory','warehouse','depreciation','business'], cites:'C&I Models Note',
      text:'Businesses choose between CAPEX — you own the asset, 3–5 year payback, accelerated depreciation benefit, best lifetime value — and OPEX/RESCO: zero investment, the developer builds and owns the plant on your roof and you simply pay per unit at a tariff below the grid. OPEX is common above 100 kW. We run both models on your last 12 months of bills.' },
    { id:'bill', tags:['bill','import','export','credit','units','adjustment','higher bill','wrong bill'], cites:'Bill Reading Guide',
      text:'Your post-solar bill has three numbers: import (grid units you used), export (solar units you sent to the grid), and net (import minus export — what you pay for). Surplus export becomes a credit for later months. If a bill looks inflated, the usual cause is the discom reading only import — send me a photo of the bill and I will check it line by line.' },
    { id:'install', tags:['install','installation','days','time','how long','structure','roof','shadow'], cites:'Installation Note',
      text:'Residential installation takes 2–5 days on the roof (structure, panels, inverter, wiring) after a site survey confirms shadow-free area — you need roughly 80–100 sq ft per kW. The longer wait is the net-meter step (1–3 months, discom-dependent), which we chase for you and track right here on WhatsApp.' },
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
