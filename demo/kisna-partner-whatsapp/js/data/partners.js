/*
 * Kisna Partner Desk — retail-partner account state for the demo.
 * Stands in for the ERP (ledger, orders, invoices), the logistics feed (AWB) and the
 * onboarding pipeline. All figures ILLUSTRATIVE.
 *
 * Invariants the self-check asserts (test/selfcheck.mjs):
 *   ageing buckets sum to outstanding, and available = creditLimit - outstanding.
 */
window.PARTNER = {
  code: 'KP-4417',
  firm: 'Shree Balaji Jewellers',
  city: 'Nagpur',
  state: 'Maharashtra',
  since: '2021',
  counters: 2,
  kam: 'Ankit Deshmukh',
  kamPhone: '+91 98xxx 41120',
  gst: '27AAJCS4417K1ZP',
  creditLimit: 2500000,
  creditDays: 45,
  outstanding: 1842000,
  available: 658000,
  ageing: [
    { bucket: '0–30 days', amount: 1120000, state: 'current' },
    { bucket: '31–45 days', amount: 512000, state: 'current' },
    { bucket: '46–60 days', amount: 210000, state: 'overdue' },
    { bucket: '60+ days', amount: 0, state: 'clear' },
  ],
  dso: 47,
  riskScore: 62,
  riskBand: 'Watch',
  ytdPurchase: 18600000,
  topLine: 'Everyday',
};

// Order pipeline stages, in order. `stage` on an order is an index into this list.
window.ORDER_STAGES = ['Order confirmed', 'Manufacturing', 'QC', 'Hallmarking · HUID', 'Dispatch', 'Delivered'];

window.ORDERS = [
  { id:'KO-24881', placed:'28 Jul', pcs:42, items:'Everyday studs & pendants', value:812000, stage:4,
    eta:'09 Aug', awb:'BLDT 7741 9930', courier:'Bluedart · fully insured', flag:null,
    note:'Insured transit. ID + firm stamp needed at delivery.' },
  { id:'KO-24902', placed:'02 Aug', pcs:18, items:'Bridal mangalsutra run', value:1466000, stage:2,
    eta:'14 Aug', awb:null, courier:null, flag:'QC hold',
    note:'2 of 18 pieces held at QC for re-polish. Rest of the lot moves on schedule.' },
  { id:'KO-24915', placed:'05 Aug', pcs:60, items:'Festive gifting edit', value:540000, stage:1,
    eta:'22 Aug', awb:null, courier:null, flag:null,
    note:'Karigar allocation done. On track for the Diwali window.' },
];
window.ORDER_BY_ID = Object.fromEntries(window.ORDERS.map(o => [o.id, o]));

window.INVOICES = [
  { no:'KIS/26-27/3391', date:'12 Jul', amount:512000, due:'26 Aug', status:'current' },
  { no:'KIS/26-27/3268', date:'24 Jun', amount:210000, due:'08 Aug', status:'due in 1 day' },
  { no:'KIS/26-27/3402', date:'28 Jul', amount:812000, due:'11 Sep', status:'current' },
];

// Live scheme + new-design broadcasts, segmented by partner profile.
window.SCHEMES = [
  { id:'FEST-26', title:'Diwali Stock-Up · 2026', segment:'Partners with ₹1Cr+ YTD',
    body:'Book the festive edit before 25 Aug: 60-day credit instead of 45, free insured freight, and full return-or-exchange on unsold festive stock till 15 Jan.',
    terms:['60-day credit on festive SKUs only','Minimum booking ₹5,00,000','Unsold-stock exchange window closes 15 Jan 2027'] },
  { id:'EMI-26', title:'Gold-on-EMI · Counter Programme', segment:'All active partners',
    body:'Offer your customer 6/9/12-month EMI at the counter. Kisna funds the subvention on 9-month tenures during the festive window; you are paid upfront in full.',
    terms:['Partner is paid in full at invoice','Subvention funded by Kisna on 9-month tenure','Requires the counter app for eligibility checks'] },
];

window.DESIGN_DROPS = [
  { id:'DROP-AW26', title:'Autumn/Winter 26 — Everyday Diamonds', pieces:24,
    hero:['KSN-ER-1042','KSN-PD-1088','KSN-RG-1121'],
    body:'24 new designs under ₹25,000 MRP, built for the gifting counter. Catalogue PDF and 4 shoot videos are attached below.',
    assets:['AW26-catalogue.pdf · 6.2 MB','AW26-reel-01.mp4 · 0:18','AW26-reel-02.mp4 · 0:22'] },
];

// Onboarding pipeline for a prospective partner (KYC scenario).
window.KYC_APPLICANT = {
  firm: 'Ratnadeep Jewellers',
  contact: 'Mehul Soni',
  city: 'Indore',
  state: 'Madhya Pradesh',
  gst: '23AABCR5521M1Z4',
  pan: 'AABCR5521M',
  counters: 1,
  annualTurnover: 42000000,
  steps: [
    { key:'firm',    label:'Firm details & contact',      done:true,  detail:'Ratnadeep Jewellers · Indore · proprietorship' },
    { key:'gst',     label:'GSTIN',                       done:true,  detail:'23AABCR5521M1Z4 · active, filings current' },
    { key:'pan',     label:'PAN & proprietor KYC',        done:true,  detail:'AABCR5521M · Aadhaar e-KYC matched' },
    { key:'bank',    label:'Cancelled cheque / bank',     done:true,  detail:'HDFC · Indore MG Road · penny-drop verified' },
    { key:'refs',    label:'Two trade references',        done:false, detail:'1 of 2 received — second reference pending' },
    { key:'shop',    label:'Shop photos & signage',       done:false, detail:'Awaiting 3 photos incl. board and counter' },
  ],
  // What the orchestrator proposes once validation clears.
  proposedTerms: { limit: 800000, days: 30, security:'PDC + personal guarantee', review:'at 90 days on payment behaviour' },
};

window.DISPUTE_TYPES = [
  { key:'short',   label:'Short shipment',      sla:'24 hrs', route:'Dispatch audit' },
  { key:'damage',  label:'Damage in transit',   sla:'48 hrs', route:'Insurance claim' },
  { key:'quality', label:'Finish / QC issue',   sla:'72 hrs', route:'Karigar rework' },
  { key:'invoice', label:'Invoice / GST error', sla:'24 hrs', route:'Accounts' },
];
