/*
 * Hiranandani Group — Demo residence catalog.
 * Prices/possession dates are ILLUSTRATIVE placeholders for demonstration only.
 * Imagery is rendered as inline SVG so the demo works fully offline.
 */
window.LOAN_RATES = {
  homeLoan: '8.35%', maxTenure: '30 yrs',
  sqft: { 'Powai': 32000, 'Thane': 18500, 'Panvel': 12500 },
  asOf: '9 Jul 2026',
};

// ---- Elegant inline-SVG "photography" for each residence type --------------
function buildingSVG(kind) {
  const g = `<defs>
    <linearGradient id="nvy" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#4a6da8"/><stop offset=".5" stop-color="#2c4a7c"/><stop offset="1" stop-color="#1b3a6b"/>
    </linearGradient>
    <linearGradient id="crm" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#fdf8ec"/><stop offset="1" stop-color="#e9dcc0"/>
    </linearGradient>
    <linearGradient id="sky" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#dcecf7"/><stop offset="1" stop-color="#f4efe2"/>
    </linearGradient></defs>
    <rect width="200" height="200" rx="10" fill="url(#sky)"/>
    <ellipse cx="100" cy="188" rx="92" ry="12" fill="#cfe0cf"/>`;
  const win = (x, y, w = 8, h = 10) => `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="1.5" fill="#bcd6ee"/>`;
  const winCol = (x, y0, n) => Array.from({length: n}, (_, i) => win(x, y0 + i * 18)).join('');
  const M = {
    tower: `<rect x="70" y="34" width="60" height="152" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="70" y="34" width="60" height="14" rx="4" fill="url(#nvy)"/>
      ${winCol(80, 58, 7)}${winCol(96, 58, 7)}${winCol(112, 58, 7)}`,
    twin_tower: `<rect x="38" y="52" width="52" height="134" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="110" y="36" width="52" height="150" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="38" y="52" width="52" height="11" fill="url(#nvy)"/><rect x="110" y="36" width="52" height="11" fill="url(#nvy)"/>
      ${winCol(47, 72, 6)}${winCol(64, 72, 6)}${winCol(119, 56, 7)}${winCol(136, 56, 7)}`,
    lake_tower: `<rect x="84" y="30" width="58" height="156" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="84" y="30" width="58" height="12" fill="url(#nvy)"/>
      ${winCol(93, 52, 7)}${winCol(110, 52, 7)}
      <ellipse cx="42" cy="172" rx="34" ry="12" fill="#9ec4e8"/><path d="M18 170 Q42 162 66 170" stroke="#7ba9d4" fill="none"/>`,
    garden_tower: `<rect x="72" y="44" width="56" height="142" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="72" y="44" width="56" height="12" fill="url(#nvy)"/>
      ${winCol(81, 66, 6)}${winCol(98, 66, 6)}
      <circle cx="44" cy="164" r="16" fill="#8fbf8f"/><rect x="41" y="164" width="6" height="22" fill="#8a6b4a"/>
      <circle cx="160" cy="170" r="12" fill="#8fbf8f"/><rect x="158" y="170" width="5" height="16" fill="#8a6b4a"/>`,
    penthouse: `<rect x="52" y="70" width="96" height="116" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="66" y="42" width="68" height="30" rx="4" fill="url(#nvy)"/>
      <rect x="74" y="50" width="52" height="14" rx="2" fill="#bcd6ee"/>
      ${winCol(62, 88, 5)}${winCol(82, 88, 5)}${winCol(102, 88, 5)}${winCol(122, 88, 5)}`,
    villa: `<rect x="46" y="96" width="108" height="90" rx="5" fill="url(#crm)" stroke="#c9b98d"/>
      <path d="M36 100 L100 52 L164 100 Z" fill="url(#nvy)"/>
      <rect x="88" y="136" width="26" height="50" rx="3" fill="#7a5a3a"/>
      ${win(56, 116, 18, 16)}${win(126, 116, 18, 16)}`,
    studio: `<rect x="60" y="60" width="80" height="126" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="60" y="60" width="80" height="12" fill="url(#nvy)"/>
      ${winCol(71, 82, 5)}${winCol(93, 82, 5)}${winCol(115, 82, 5)}`,
    skyline: `<rect x="26" y="86" width="34" height="100" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="68" y="48" width="42" height="138" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="118" y="70" width="34" height="116" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="158" y="102" width="24" height="84" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="68" y="48" width="42" height="10" fill="url(#nvy)"/>${winCol(76, 66, 7)}${winCol(94, 66, 7)}`,
    floorplan: `<rect x="40" y="46" width="120" height="108" rx="4" fill="#ffffff" stroke="#1b3a6b" stroke-width="2"/>
      <line x1="100" y1="46" x2="100" y2="118" stroke="#1b3a6b" stroke-width="1.5"/>
      <line x1="40" y1="118" x2="160" y2="118" stroke="#1b3a6b" stroke-width="1.5"/>
      <line x1="128" y1="118" x2="128" y2="154" stroke="#1b3a6b" stroke-width="1.5"/>
      <text x="66" y="86" font-size="11" fill="#1b3a6b" text-anchor="middle" font-family="sans-serif">BED</text>
      <text x="130" y="86" font-size="11" fill="#1b3a6b" text-anchor="middle" font-family="sans-serif">LIVING</text>
      <text x="82" y="140" font-size="10" fill="#1b3a6b" text-anchor="middle" font-family="sans-serif">KITCHEN</text>`,
  }[kind] || `<rect x="70" y="60" width="60" height="126" rx="4" fill="url(#crm)" stroke="#c9b98d"/>`;
  return `<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">${g}${M}</svg>`;
}
window.jewelSVG = buildingSVG; // app.js calls window.jewelSVG — same hook, new art

/*
 * Unit fields the engine uses:
 *   price (number), config ('1 BHK'...), township (shown as brand tag), city,
 *   audience[] (first-home | upgrade | investment | nri | family | retirement),
 *   style[] (ready | under-construction | lake-view | township | garden | high-rise |
 *   villa | penthouse), possession, carpet (display string).
 */
window.UNITS = [
  // ---- Hiranandani Gardens, Powai (Mumbai) ----
  { id:'HG-1B-01', name:'Regent Hill — 1 BHK Residence', township:'Gardens · Powai', city:'Mumbai', cat:'powai',
    config:'1 BHK', carpet:'403 sqft carpet', price:13500000, possession:'Ready to move', icon:'tower',
    style:['ready','high-rise','township'], audience:['first-home','investment'],
    desc:'Compact 1 BHK in the iconic 250-acre Powai township — neo-classical towers, landscaped boulevards, walk-to-work offices.' },
  { id:'HG-2B-02', name:'Eden Court — 2 BHK Residence', township:'Gardens · Powai', city:'Mumbai', cat:'powai',
    config:'2 BHK', carpet:'778 sqft carpet', price:26500000, possession:'Ready to move', icon:'garden_tower',
    style:['ready','garden','township'], audience:['family','upgrade'],
    desc:'Garden-facing 2 BHK near Heritage Gardens — schools, hospital and the Galleria high street inside the township.' },
  { id:'HG-3B-03', name:'Lake Verandah — 3 BHK Lake View', township:'Gardens · Powai', city:'Mumbai', cat:'powai',
    config:'3 BHK', carpet:'1,180 sqft carpet', price:44500000, possession:'Ready to move', icon:'lake_tower',
    style:['ready','lake-view','high-rise'], audience:['upgrade','family','nri'],
    desc:'Powai Lake views from a high floor — the flagship Hiranandani address, minutes from Hiranandani Business Park.' },
  { id:'HG-4B-04', name:'Rockside Crown — 4 BHK Penthouse', township:'Gardens · Powai', city:'Mumbai', cat:'powai',
    config:'4 BHK', carpet:'1,729 sqft carpet', price:78000000, possession:'Ready to move', icon:'penthouse',
    style:['ready','lake-view','penthouse'], audience:['upgrade','nri'],
    desc:'Top-floor penthouse living in Powai — double-height deck, panoramic lake and hill views.' },

  // ---- Hiranandani Estate, Thane (Ghodbunder Road) ----
  { id:'HE-1B-05', name:'Estate Serene — 1 BHK Residence', township:'Estate · Thane', city:'Thane', cat:'thane',
    config:'1 BHK', carpet:'428 sqft carpet', price:8500000, possession:'Ready to move', icon:'studio',
    style:['ready','township','garden'], audience:['first-home','investment'],
    desc:'Smart first home inside the Estate township — tree-lined avenues, tennis courts, walking tracks.' },
  { id:'HE-2B-06', name:'Estate Bella Vista — 2 BHK', township:'Estate · Thane', city:'Thane', cat:'thane',
    config:'2 BHK', carpet:'720 sqft carpet', price:14200000, possession:'Dec 2026', icon:'twin_tower',
    style:['under-construction','township','high-rise'], audience:['family','first-home'],
    desc:'New-phase 2 BHK on Ghodbunder Road — clubhouse, pool and the Estate high street at your doorstep.' },
  { id:'HE-3B-07', name:'Estate Regina — 3 BHK Grande', township:'Estate · Thane', city:'Thane', cat:'thane',
    config:'3 BHK', carpet:'1,050 sqft carpet', price:21500000, possession:'Jun 2027', icon:'tower',
    style:['under-construction','township','high-rise'], audience:['upgrade','family'],
    desc:'Spacious 3 BHK with hill views — the Thane township that set the benchmark for integrated living.' },
  { id:'HE-VL-08', name:'Estate Villa Row — 4 BHK Villa', township:'Estate · Thane', city:'Thane', cat:'thane',
    config:'4 BHK Villa', carpet:'2,400 sqft', price:52000000, possession:'Ready to move', icon:'villa',
    style:['ready','villa','garden'], audience:['upgrade','retirement'],
    desc:'Limited-edition villa living inside the township — private garden, double-car deck.' },

  // ---- Hiranandani Fortune City, Panvel (Navi Mumbai) ----
  { id:'FC-1B-09', name:'Fortune Greens — 1 BHK', township:'Fortune City · Panvel', city:'Panvel', cat:'panvel',
    config:'1 BHK', carpet:'480 sqft carpet', price:6200000, possession:'Ready to move', icon:'garden_tower',
    style:['ready','township','garden'], audience:['first-home','investment'],
    desc:'Entry into Fortune City — school, hospital and sports complex already live; on the upcoming Navi Mumbai airport corridor.' },
  { id:'FC-2B-10', name:'Fortune Crest — 2 BHK', township:'Fortune City · Panvel', city:'Panvel', cat:'panvel',
    config:'2 BHK', carpet:'723 sqft carpet', price:11000000, possession:'Mar 2027', icon:'tower',
    style:['under-construction','township','high-rise'], audience:['first-home','family','investment'],
    desc:'Best-selling 2 BHK in Navi Mumbai’s largest integrated township — cricket ground, football turf, clubhouse.' },
  { id:'FC-3B-11', name:'Fortune Skyline — 3 BHK', township:'Fortune City · Panvel', city:'Panvel', cat:'panvel',
    config:'3 BHK', carpet:'1,040 sqft carpet', price:16800000, possession:'Dec 2027', icon:'skyline',
    style:['under-construction','township','high-rise'], audience:['family','upgrade','nri'],
    desc:'High-floor 3 BHK with hill-line views — the airport-corridor appreciation story for end-users and investors alike.' },
  { id:'FC-ST-12', name:'Fortune Business Studio', township:'Fortune City · Panvel', city:'Panvel', cat:'panvel',
    config:'Studio / Office', carpet:'350 sqft', price:4500000, possession:'Ready to move', icon:'studio',
    style:['ready','township'], audience:['investment'],
    desc:'Compact studio-office on the township retail spine — a rental-yield play on the airport corridor.' },
];

window.UNIT_BY_ID = {};
window.UNITS.forEach(p => { window.UNIT_BY_ID[p.id] = p; });
// app.js references window.PRODUCTS / PRODUCT_BY_ID — alias to the same objects.
window.PRODUCTS = window.UNITS;
window.PRODUCT_BY_ID = window.UNIT_BY_ID;
