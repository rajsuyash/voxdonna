/*
 * JITO — Demo member business directory.
 * All member names/businesses are ILLUSTRATIVE placeholders for demonstration only.
 * Imagery is rendered as inline SVG so the demo works fully offline.
 */
window.EDU_RATES = {
  subsidy: 'Interest subsidy on bank/NBFC education loans (SAMPLE terms)',
  bankFrom: '9.1%', cetWindow: 'CET-2026 · applications open',
  asOf: '10 Jul 2026',
};

// ---- Inline-SVG emblems for member categories --------------------------------
function memberSVG(kind) {
  const g = `<defs>
    <linearGradient id="mrn" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#b0433d"/><stop offset=".5" stop-color="#8a2f2b"/><stop offset="1" stop-color="#5f1f1c"/>
    </linearGradient>
    <linearGradient id="gld" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#f3dfae"/><stop offset="1" stop-color="#d9b96a"/>
    </linearGradient>
    <radialGradient id="bgm" cx=".5" cy=".35" r=".9">
      <stop offset="0" stop-color="#fdf7ee"/><stop offset="1" stop-color="#f0e3cd"/>
    </radialGradient></defs>
    <rect width="200" height="200" rx="10" fill="url(#bgm)"/>`;
  const M = {
    ca: `<rect x="52" y="48" width="96" height="116" rx="8" fill="#fff" stroke="#8a2f2b" stroke-width="2"/>
      ${[72,92,112].map(y=>`<line x1="66" y1="${y}" x2="134" y2="${y}" stroke="#c9a961" stroke-width="4" stroke-linecap="round"/>`).join('')}
      <circle cx="128" cy="140" r="20" fill="url(#mrn)"/><text x="128" y="147" text-anchor="middle" font-size="18" fill="#f3dfae" font-family="serif">₹</text>`,
    textile: `<path d="M40 70 Q70 50 100 70 T160 70 V150 Q130 170 100 150 T40 150 Z" fill="url(#mrn)"/>
      <path d="M40 95 Q70 75 100 95 T160 95" stroke="url(#gld)" stroke-width="5" fill="none"/>
      <path d="M40 120 Q70 100 100 120 T160 120" stroke="url(#gld)" stroke-width="5" fill="none"/>`,
    pharma: `<rect x="62" y="56" width="42" height="98" rx="21" fill="url(#mrn)" transform="rotate(-35 100 100)"/>
      <rect x="96" y="56" width="42" height="49" rx="21" fill="url(#gld)" transform="rotate(-35 100 100)"/>
      <circle cx="138" cy="138" r="24" fill="none" stroke="#8a2f2b" stroke-width="6"/><line x1="138" y1="122" x2="138" y2="154" stroke="#8a2f2b" stroke-width="6"/><line x1="122" y1="138" x2="154" y2="138" stroke="#8a2f2b" stroke-width="6"/>`,
    diamond: `<path d="M60 78 L100 50 L140 78 L100 160 Z" fill="url(#gld)" stroke="#b8963f" stroke-width="3"/>
      <path d="M60 78 L140 78 M100 50 L100 160 M76 78 L100 50 L124 78" stroke="#b8963f" stroke-width="2" fill="none"/>`,
    it: `<rect x="42" y="60" width="116" height="72" rx="8" fill="url(#mrn)"/>
      <rect x="52" y="70" width="96" height="52" rx="4" fill="#dcecf7"/>
      <text x="100" y="103" text-anchor="middle" font-size="26" fill="#8a2f2b" font-family="monospace">&lt;/&gt;</text>
      <rect x="82" y="136" width="36" height="10" fill="url(#gld)"/><rect x="62" y="148" width="76" height="8" rx="4" fill="url(#mrn)"/>`,
    realestate: `<rect x="56" y="72" width="50" height="112" rx="4" fill="url(#mrn)"/>
      <rect x="112" y="96" width="38" height="88" rx="4" fill="url(#gld)"/>
      ${[86,106,126,146].map(y=>`<rect x="66" y="${y}" width="10" height="12" fill="#f3dfae"/><rect x="84" y="${y}" width="10" height="12" fill="#f3dfae"/>`).join('')}`,
    food: `<circle cx="100" cy="112" r="52" fill="url(#gld)"/><circle cx="100" cy="112" r="40" fill="#fdf7ee"/>
      ${[[-16,-6],[0,-14],[16,-6]].map(([dx,dy])=>`<circle cx="${100+dx}" cy="${106+dy}" r="7" fill="url(#mrn)"/>`).join('')}
      <path d="M78 126 Q100 142 122 126" stroke="#8a2f2b" stroke-width="5" fill="none" stroke-linecap="round"/>`,
    logistics: `<rect x="38" y="86" width="76" height="52" rx="6" fill="url(#mrn)"/>
      <path d="M114 98 H150 L162 118 V138 H114 Z" fill="url(#gld)"/>
      <circle cx="66" cy="146" r="13" fill="#3a3a3a"/><circle cx="138" cy="146" r="13" fill="#3a3a3a"/>
      <circle cx="66" cy="146" r="6" fill="#c9c9c9"/><circle cx="138" cy="146" r="6" fill="#c9c9c9"/>`,
    education: `<path d="M100 58 L170 88 L100 118 L30 88 Z" fill="url(#mrn)"/>
      <path d="M62 104 V138 Q100 158 138 138 V104" fill="none" stroke="url(#gld)" stroke-width="8"/>
      <line x1="164" y1="92" x2="164" y2="130" stroke="#8a2f2b" stroke-width="4"/><circle cx="164" cy="136" r="6" fill="url(#gld)"/>`,
    startup: `<path d="M100 40 Q130 70 122 120 L78 120 Q70 70 100 40 Z" fill="url(#mrn)"/>
      <circle cx="100" cy="86" r="12" fill="#dcecf7" stroke="#8a2f2b" stroke-width="3"/>
      <path d="M78 120 L60 150 L84 142 Z" fill="url(#gld)"/><path d="M122 120 L140 150 L116 142 Z" fill="url(#gld)"/>
      <path d="M92 128 Q100 156 108 128" fill="#e8863a"/>`,
    chapter: `<rect x="44" y="88" width="112" height="82" rx="4" fill="url(#gld)"/>
      <path d="M36 92 L100 52 L164 92 Z" fill="url(#mrn)"/>
      ${[58,88,118].map(x=>`<rect x="${x}" y="106" width="18" height="30" rx="2" fill="#8a2f2b"/>`).join('')}
      <rect x="88" y="142" width="24" height="28" fill="#5f1f1c"/>`,
    event: `<rect x="52" y="52" width="96" height="108" rx="8" fill="#fff" stroke="#8a2f2b" stroke-width="3"/>
      <rect x="52" y="52" width="96" height="26" rx="8" fill="url(#mrn)"/>
      ${[0,1,2].map(r=>[0,1,2].map(c=>`<rect x="${66+c*26}" y="${90+r*22}" width="16" height="14" rx="2" fill="${(r+c)%2?'url(#gld)':'#eee1c8'}"/>`).join('')).join('')}`,
  }[kind] || `<circle cx="100" cy="100" r="46" fill="url(#mrn)"/>`;
  return `<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">${g}${M}</svg>`;
}
window.jewelSVG = memberSVG; // app.js hook — same name, new art

/*
 * Directory fields the engine uses:
 *   config = business category label, city, chapter (shown as tag),
 *   need[] = what a searcher might need them for, style[] = keywords, since.
 */
window.MEMBERS = [
  { id:'M-CA-01', name:'Sanghvi & Associates', township:'JBN Pune', city:'Pune', config:'Chartered Accountancy',
    since:'Member since 2014', icon:'ca', style:['audit','tax','gst','compliance'], need:['ca','finance','tax'],
    desc:'CA firm — audit, GST, cross-border structuring for SME exporters. 40-person practice.' },
  { id:'M-CA-02', name:'Jain Mehta & Co.', township:'JBN Mumbai', city:'Mumbai', config:'Chartered Accountancy',
    since:'Member since 2011', icon:'ca', style:['tax','valuation','startup'], need:['ca','finance','tax'],
    desc:'Boutique CA practice — startup valuations, ESOP structuring, JIIF deal diligence partner.' },
  { id:'M-TX-03', name:'Shree Parshwa Textiles', township:'JBN Surat', city:'Surat', config:'Textiles & Fabrics',
    since:'Member since 2009', icon:'textile', style:['fabric','saree','export'], need:['textile','manufacturing','export'],
    desc:'Viscose and jacquard fabrics — 200-loom unit, exports to UAE and East Africa.' },
  { id:'M-PH-04', name:'Arihant Lifesciences', township:'JBN Ahmedabad', city:'Ahmedabad', config:'Pharmaceuticals',
    since:'Member since 2016', icon:'pharma', style:['generics','formulations','who-gmp'], need:['pharma','healthcare','manufacturing'],
    desc:'WHO-GMP formulations plant — generics and nutraceuticals, 14 export registrations.' },
  { id:'M-DM-05', name:'Vardhman Gems', township:'JBN Mumbai', city:'Mumbai', config:'Diamonds & Jewellery',
    since:'Member since 2008', icon:'diamond', style:['polished','certified','b2b'], need:['diamond','jewellery','export'],
    desc:'BKC-based polished diamond house — certified stones, B2B supply to 60+ retail brands.' },
  { id:'M-IT-06', name:'Kalpataru InfoTech', township:'JBN Pune', city:'Pune', config:'IT Services',
    since:'Member since 2018', icon:'it', style:['erp','saas','cloud'], need:['it','software','technology'],
    desc:'ERP implementations and custom SaaS for mid-market manufacturers — 120 engineers.' },
  { id:'M-RE-07', name:'Labdhi Developers', township:'JBN Mumbai', city:'Mumbai', config:'Real Estate',
    since:'Member since 2012', icon:'realestate', style:['redevelopment','commercial'], need:['realestate','construction','property'],
    desc:'Society redevelopment specialist — 22 completed projects across the western suburbs.' },
  { id:'M-FD-08', name:'Rasna Foods (Shah family)', township:'JBN Ahmedabad', city:'Ahmedabad', config:'Food & FMCG',
    since:'Member since 2015', icon:'food', style:['snacks','jain-certified','distribution'], need:['food','fmcg','distribution'],
    desc:'Jain-certified snacks brand — 4,000 retail touchpoints across Gujarat and Maharashtra.' },
  { id:'M-LG-09', name:'Mahavir Logistics', township:'JBN Hyderabad', city:'Hyderabad', config:'Logistics & Warehousing',
    since:'Member since 2017', icon:'logistics', style:['3pl','cold-chain','pan-india'], need:['logistics','transport','warehouse'],
    desc:'3PL + cold-chain — 11 warehouses, pharma and FMCG lanes across South India.' },
  { id:'M-ED-10', name:'Gyanoday Coaching', township:'JBN Pune', city:'Pune', config:'Education Services',
    since:'Member since 2019', icon:'education', style:['test-prep','careers'], need:['education','coaching','training'],
    desc:'Test-prep academy — JEE/NEET + civil-services foundation batches, 2,000 students/yr.' },
  { id:'M-ST-11', name:'GreenKart (JAN portfolio)', township:'JIIF · Mumbai', city:'Mumbai', config:'Startup — Agritech',
    since:'JAN portfolio 2024', icon:'startup', style:['agritech','d2c','seed'], need:['startup','investment','agritech'],
    desc:'Farm-to-kirana supply platform — JAN-funded seed round, now raising Series A (SAMPLE).' },
  { id:'M-EV-12', name:'Utsav Events & Expos', township:'JBN Hyderabad', city:'Hyderabad', config:'Events & Exhibitions',
    since:'Member since 2013', icon:'event', style:['exhibitions','weddings','corporate'], need:['events','exhibition','wedding'],
    desc:'Exhibition and stall-fabrication house — official partner at two JITO Connect editions.' },
];

window.MEMBER_BY_ID = {};
window.MEMBERS.forEach(p => { window.MEMBER_BY_ID[p.id] = p; });
// app.js engine reads window.PRODUCTS / PRODUCT_BY_ID — alias.
window.PRODUCTS = window.MEMBERS;
window.PRODUCT_BY_ID = window.MEMBER_BY_ID;
