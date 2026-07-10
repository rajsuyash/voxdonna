/*
 * Tata Power Solar — Demo rooftop system catalog.
 * Prices/figures are ILLUSTRATIVE, grounded in public 2025-26 market ranges
 * (PM Surya Ghar subsidy slabs: ₹30k/1kW, ₹60k/2kW, ₹78k cap at 3kW+).
 * Imagery is inline SVG so the demo works fully offline.
 */
window.SOLAR_RATES = {
  tariff: '₹8/unit (avg residential)',
  genPerKw: '~120 units/month per kW',
  subsidy: { '1 kW': 30000, '2 kW': 60000, '3 kW+': 78000 },
  emiFrom: '₹2,499/month · up to 10-yr tenure',
  payback: '3–4 years (residential, post-subsidy)',
  asOf: '10 Jul 2026',
};

// ---- Inline-SVG "photography" for each system type ------------------------
function solarSVG(kind) {
  const g = `<defs>
    <linearGradient id="pnl" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#2c66b8"/><stop offset=".55" stop-color="#174a92"/><stop offset="1" stop-color="#0f3a7a"/>
    </linearGradient>
    <linearGradient id="wall" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#fdf8ec"/><stop offset="1" stop-color="#e9dcc0"/>
    </linearGradient>
    <linearGradient id="sky2" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#dff0fb"/><stop offset="1" stop-color="#f6f0de"/>
    </linearGradient></defs>
    <rect width="200" height="200" rx="10" fill="url(#sky2)"/>
    <circle cx="164" cy="34" r="16" fill="#f6c344"/>
    <ellipse cx="100" cy="188" rx="92" ry="12" fill="#cfe0cf"/>`;
  // a tilted solar panel array: x,y anchor, cols x rows
  const arr = (x, y, cols, rows, cw = 16, ch = 11) => {
    let cells = '';
    for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++)
      cells += `<rect x="${x + c * cw}" y="${y + r * ch}" width="${cw - 2}" height="${ch - 2}" rx="1.5" fill="url(#pnl)" stroke="#9fc0e8" stroke-width=".6"/>`;
    return cells;
  };
  const M = {
    home: `<rect x="52" y="106" width="96" height="80" rx="5" fill="url(#wall)" stroke="#c9b98d"/>
      <path d="M40 110 L100 62 L160 110 Z" fill="#8a6b4a"/>
      ${arr(66, 74, 4, 3)}
      <rect x="88" y="146" width="24" height="40" rx="3" fill="#7a5a3a"/>`,
    home_big: `<rect x="38" y="100" width="124" height="86" rx="5" fill="url(#wall)" stroke="#c9b98d"/>
      <path d="M28 104 L100 54 L172 104 Z" fill="#8a6b4a"/>
      ${arr(52, 66, 6, 3)}
      <rect x="90" y="146" width="24" height="40" rx="3" fill="#7a5a3a"/>`,
    hybrid: `<rect x="52" y="106" width="96" height="80" rx="5" fill="url(#wall)" stroke="#c9b98d"/>
      <path d="M40 110 L100 62 L160 110 Z" fill="#8a6b4a"/>
      ${arr(66, 74, 4, 3)}
      <rect x="152" y="128" width="30" height="46" rx="4" fill="#1f9d55" stroke="#137a3f"/>
      <path d="M167 136 l-7 14 h6 l-4 12 10 -15 h-6 l5 -11 z" fill="#eafff2"/>`,
    society: `<rect x="44" y="60" width="52" height="126" rx="4" fill="url(#wall)" stroke="#c9b98d"/>
      <rect x="104" y="76" width="52" height="110" rx="4" fill="url(#wall)" stroke="#c9b98d"/>
      ${arr(44, 44, 3, 1)}${arr(104, 60, 3, 1)}
      <rect x="52" y="80" width="9" height="11" fill="#bcd6ee"/><rect x="70" y="80" width="9" height="11" fill="#bcd6ee"/>
      <rect x="52" y="100" width="9" height="11" fill="#bcd6ee"/><rect x="70" y="100" width="9" height="11" fill="#bcd6ee"/>
      <rect x="112" y="96" width="9" height="11" fill="#bcd6ee"/><rect x="130" y="96" width="9" height="11" fill="#bcd6ee"/>
      <rect x="112" y="116" width="9" height="11" fill="#bcd6ee"/><rect x="130" y="116" width="9" height="11" fill="#bcd6ee"/>`,
    factory: `<path d="M32 186 V110 l30 -18 v18 l30 -18 v18 l30 -18 v18 h46 v76 Z" fill="url(#wall)" stroke="#c9b98d"/>
      ${arr(36, 70, 8, 2)}
      <rect x="130" y="140" width="16" height="46" fill="#7a5a3a"/>
      <rect x="46" y="140" width="14" height="14" fill="#bcd6ee"/><rect x="70" y="140" width="14" height="14" fill="#bcd6ee"/>`,
    ground: `<rect x="20" y="150" width="160" height="6" rx="3" fill="#8fa48f"/>
      ${arr(28, 96, 4, 3)}${arr(112, 96, 4, 3)}
      <rect x="52" y="132" width="4" height="22" fill="#5a6b5a"/><rect x="136" y="132" width="4" height="22" fill="#5a6b5a"/>`,
    meter: `<rect x="60" y="52" width="80" height="104" rx="8" fill="#ffffff" stroke="#0f3a7a" stroke-width="2"/>
      <rect x="72" y="66" width="56" height="26" rx="4" fill="#dff0fb" stroke="#9fc0e8"/>
      <text x="100" y="84" font-size="13" fill="#0f3a7a" text-anchor="middle" font-family="monospace">EXPORT</text>
      <circle cx="100" cy="120" r="16" fill="none" stroke="#0f3a7a" stroke-width="2"/>
      <path d="M100 120 L110 110" stroke="#f6a821" stroke-width="3" stroke-linecap="round"/>`,
  }[kind] || `<rect x="52" y="106" width="96" height="80" rx="5" fill="url(#wall)" stroke="#c9b98d"/>${arr(66, 74, 4, 3)}`;
  return `<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">${g}${M}</svg>`;
}
window.jewelSVG = solarSVG; // app.js calls window.jewelSVG — same hook, new art

/*
 * System fields the engine uses:
 *   price (number, pre-subsidy), subsidy (number), kw (number),
 *   config / carpet / possession (display strings shown on the card),
 *   billMin–billMax (monthly bill band this system suits),
 *   audience[] (home | large-home | backup | society | sme | industry),
 *   style[] (on-grid | hybrid | subsidy | battery | commercial | group-metering).
 */
window.SYSTEMS = [
  { id:'TS-2K', name:'Solaroof 2 kW Starter', township:'Solaroof · Home', city:'Mumbai',
    config:'2 kW · On-Grid', carpet:'≈240 units/mo', possession:'Installed in 2–3 days', icon:'home',
    price:145000, subsidy:60000, kw:2, billMin:1200, billMax:2400,
    style:['on-grid','subsidy'], audience:['home'],
    desc:'The entry point for small homes — covers bills up to ~₹2,000/month. ₹60,000 PM Surya Ghar subsidy brings net cost to ₹85,000.' },
  { id:'TS-3K', name:'Solaroof 3 kW Family Home', township:'Solaroof · Home', city:'Mumbai',
    config:'3 kW · On-Grid', carpet:'≈360 units/mo', possession:'Installed in 3–5 days', icon:'home',
    price:195000, subsidy:78000, kw:3, billMin:2400, billMax:3800,
    style:['on-grid','subsidy'], audience:['home'],
    desc:'India’s most-installed size — full ₹78,000 subsidy, covers a ₹2,500–3,800 monthly bill, payback in 3–4 years.' },
  { id:'TS-5K', name:'Solaroof 5 kW Large Home', township:'Solaroof · Home', city:'Pune',
    config:'5 kW · On-Grid', carpet:'≈600 units/mo', possession:'Installed in 3–5 days', icon:'home_big',
    price:310000, subsidy:78000, kw:5, billMin:3800, billMax:6500,
    style:['on-grid','subsidy'], audience:['home','large-home'],
    desc:'For ACs-running-all-summer homes — covers bills up to ~₹6,500/month. Subsidy capped at ₹78,000; still a 4-year payback.' },
  { id:'TS-3H', name:'Solaroof 3 kW Hybrid + Battery', township:'Solaroof · Hybrid', city:'Jaipur',
    config:'3 kW Hybrid · 5 kWh battery', carpet:'≈360 units/mo + backup', possession:'Installed in 4–6 days', icon:'hybrid',
    price:340000, subsidy:78000, kw:3, billMin:2400, billMax:4200,
    style:['hybrid','battery','subsidy'], audience:['home','backup'],
    desc:'Solar by day, battery through power cuts — the answer to “on-grid shuts down when the grid does.” Subsidy applies on the solar portion.' },
  { id:'TS-8K', name:'Solaroof 8 kW Villa', township:'Solaroof · Villa', city:'Pune',
    config:'8 kW · On-Grid', carpet:'≈960 units/mo', possession:'Installed in 5–7 days', icon:'home_big',
    price:480000, subsidy:78000, kw:8, billMin:6500, billMax:11000,
    style:['on-grid','subsidy'], audience:['large-home'],
    desc:'Villa-scale system for ₹7,000+ bills — EV charger ready, 25-year panel warranty, remote monitoring included.' },
  { id:'TS-10S', name:'Society Common-Area 10 kW', township:'Solaroof · Society', city:'Mumbai',
    config:'10 kW · Group Net Metering', carpet:'≈1,200 units/mo', possession:'Installed in 2–3 weeks', icon:'society',
    price:550000, subsidy:0, kw:10, billMin:8000, billMax:18000,
    style:['on-grid','commercial','group-metering'], audience:['society'],
    desc:'Cuts the society’s common-area bill (lifts, pumps, lobby lighting) 60–90%. RWA resolution + 6 months of bills is all we need to start.' },
  { id:'TS-25C', name:'MSME 25 kW Commercial', township:'Solaroof · Business', city:'Pune',
    config:'25 kW · Commercial CAPEX', carpet:'≈3,000 units/mo', possession:'Commissioned in 3–4 weeks', icon:'factory',
    price:1150000, subsidy:0, kw:25, billMin:20000, billMax:45000,
    style:['on-grid','commercial'], audience:['sme'],
    desc:'For workshops, showrooms, cold storage — 3–5 year payback with accelerated depreciation. SunSmart Flexi EMI: pay from savings, no collateral.' },
  { id:'TS-100C', name:'C&I 100 kW · CAPEX or OPEX', township:'Solaroof · C&I', city:'Mumbai',
    config:'100 kW · CAPEX / OPEX-PPA', carpet:'≈12,000 units/mo', possession:'Commissioned in 6–8 weeks', icon:'ground',
    price:5200000, subsidy:0, kw:100, billMin:80000, billMax:250000,
    style:['on-grid','commercial'], audience:['industry'],
    desc:'Factory/warehouse scale. Own it (CAPEX, 3–5 yr payback, depreciation benefit) or zero-investment OPEX: pay per unit under a PPA.' },
];

window.SYSTEM_BY_ID = {};
window.SYSTEMS.forEach(p => { window.SYSTEM_BY_ID[p.id] = p; });
// app.js references window.PRODUCTS / PRODUCT_BY_ID / UNITS — alias to the same objects.
window.UNITS = window.SYSTEMS;
window.PRODUCTS = window.SYSTEMS;
window.PRODUCT_BY_ID = window.SYSTEM_BY_ID;
window.UNIT_BY_ID = window.SYSTEM_BY_ID;
