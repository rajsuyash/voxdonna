/*
 * Retrieval-Augmented Generation — trade-policy knowledge base + retriever.
 * In production this is an embeddings + vector-DB pipeline over the partner handbook,
 * circulars and GST/BIS notifications. Here it is a curated KB plus a lightweight
 * keyword retriever, so every answer is GROUNDED in a named document — never invented.
 * Content is ILLUSTRATIVE and written for the demo.
 */
(function () {
  const KB = [
    { id:'huid', tags:['huid','hallmark','hallmarking','bis','6 digit','unique id','marking'], cites:'BIS Hallmarking & HUID — Partner Handbook §4',
      text:'Every gold item we dispatch carries a 6-digit alphanumeric HUID, laser-marked with the BIS logo, purity and the assaying centre mark. The HUID is printed on your invoice line and is traceable on the BIS Care app. Hallmarking happens after QC and before dispatch — that is the stage you see as *Hallmarking · HUID* in order tracking.' },
    { id:'purity', tags:['purity','karat','14k','18k','585','750','carat','quality'], cites:'Purity & Quality Standards §2',
      text:'We supply 14K (585) and 18K (750) diamond-studded gold. Every lot is assayed before hallmarking and the certificate travels with the invoice. Diamond grades are stated per SKU (VS/SI clarity, GH/IJ colour); mixed-grade lots are never shipped against a single-grade order.' },
    { id:'cert', tags:['certificate','igi','certification','grading','solitaire certificate','authenticity'], cites:'Certification Policy §3',
      text:'Diamonds above 0.30 ct ship with an individual IGI certificate. Below 0.30 ct, the lot carries an in-house grading card stating clarity, colour and total carat weight. Certificates are re-issued free within 12 months if lost — raise it here with the invoice number.' },
    { id:'gst', tags:['gst','tax','hsn','invoice tax','3%','5%','e-way','eway','einvoice'], cites:'GST & Invoicing — Circular 2026-04',
      text:'Jewellery is billed at 3% GST on the total value; job-work and making, where billed separately, attract 5%. HSN 7113 applies. E-invoice and e-way bill are generated automatically at dispatch and pushed to you on WhatsApp — no separate request needed. Any GSTIN correction must be raised within 7 days of invoice date.' },
    { id:'credit', tags:['credit','limit','terms','days','payment terms','enhance','increase limit'], cites:'Trade Credit Policy §6',
      text:'Standard partner terms are 45 days from invoice date against the sanctioned limit. Limits are reviewed every quarter on payment behaviour, sell-through and ageing. A limit enhancement can be requested here — it needs the last two years of financials and current ageing under 60 days.' },
    { id:'collections', tags:['payment','pay','upi','neft','rtgs','link','settle','outstanding','due'], cites:'Payments & Settlement §7',
      text:'You can settle by UPI, NEFT/RTGS or a payment link raised right here in chat. Payments reflect against your ledger within 30 minutes on UPI and same working day on NEFT. Part-payments are applied oldest-invoice-first unless you tag a specific invoice number.' },
    { id:'returns', tags:['return','exchange','unsold','buyback','stock rotation','swap'], cites:'Returns & Stock Rotation §8',
      text:'Unsold stock can be exchanged design-for-design within the agreed rotation window at invoice value, provided tags, certificate and packaging are intact. Festive-scheme stock carries its own extended window. Melting-value buyback applies only to damaged or discontinued pieces and is settled at the prevailing gold rate less the diamond assessment.' },
    { id:'dispute', tags:['dispute','short','shortage','damage','claim','missing','wrong item','discrepancy'], cites:'Claims & Disputes §9',
      text:'Raise shortage or damage within 24 hours of delivery, with the unopened-seal video and the packing list photo. Short shipment is resolved in 24 hours from the dispatch audit; transit damage runs through the insurer at 48 hours. Every claim opens a ticket you can track here by number.' },
    { id:'repair', tags:['repair','rework','karigar','polish','resize','finish','service'], cites:'Rework & Karigar Service §10',
      text:'Finish and setting issues go back to the karigar under our rework service — no charge inside 6 months of invoice. Turnaround is 10–14 working days including re-hallmarking. Customer-damage repairs are quoted before work starts.' },
    { id:'dispatch', tags:['dispatch','shipping','courier','awb','transit','insurance','delivery','freight'], cites:'Logistics & Transit Cover §11',
      text:'All consignments move fully insured through our contracted carriers with door-delivery against firm stamp and photo ID. Ready-stock designs dispatch in 5–7 working days; made-to-order runs by the lead time on the SKU. AWB and live tracking are pushed here the moment the box leaves the vault.' },
    { id:'moq', tags:['moq','minimum','quantity','order size','minimum order','size run'], cites:'Ordering & MOQ §5',
      text:'Each design carries its own MOQ, shown on the SKU card. Ring MOQs are counted across a size run, not per size. Mixed orders across designs are allowed as long as each line meets its own MOQ, and there is no minimum invoice value for active partners.' },
    { id:'scheme', tags:['scheme','offer','festive','diwali','emi','subvention','programme','campaign'], cites:'Partner Schemes — Festive 2026',
      text:'Festive schemes are segmented by partner profile and turnover band, so the offer you see here is the one your account is eligible for. Scheme credit terms and return windows override standard terms for scheme SKUs only, and both are stated on the scheme card before you opt in.' },
    { id:'kyc', tags:['kyc','onboard','onboarding','new partner','documents','register','sign up','account opening'], cites:'Partner Onboarding §1',
      text:'Onboarding needs six things: firm details, GSTIN, PAN with proprietor/director KYC, a cancelled cheque for penny-drop verification, two trade references, and shop photographs including signage. Everything can be uploaded right here in chat. Verification is usually complete within two working days, after which opening credit terms are proposed.' },
    { id:'catalogue', tags:['catalogue','catalog','new design','drop','collection','lookbook','launch'], cites:'Design Launch Calendar 2026',
      text:'New design lines drop four times a year, with the catalogue PDF, shoot videos and counter-display artwork released together. Interest registered in chat is what decides the first production run, so an early signal usually means an earlier delivery slot.' },
  ];

  function retrieve(query, k = 1) {
    const q = (query || '').toLowerCase();
    const tokens = q.split(/[^a-z0-9]+/).filter(Boolean);
    return KB
      .map(doc => {
        let s = 0;
        doc.tags.forEach(t => { if (q.includes(t)) s += 3; });
        tokens.forEach(tok => {
          if (tok.length < 3) return;
          if (doc.tags.some(t => t.includes(tok)) || doc.text.toLowerCase().includes(tok)) s += 1;
        });
        return { doc, s };
      })
      .filter(x => x.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, k)
      .map(x => x.doc);
  }

  function answer(query) {
    const hits = retrieve(query, 1);
    if (!hits.length) return null;
    return { text: hits[0].text, cites: hits[0].cites };
  }

  window.RAG = { retrieve, answer, KB };
})();
