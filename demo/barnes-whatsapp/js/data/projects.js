/*
 * BARNES — Catalogue de biens de prestige (démo).
 * Prix / disponibilités ILLUSTRATIFS, à des fins de démonstration uniquement.
 * Les visuels sont rendus en SVG inline pour que la démo fonctionne hors-ligne.
 */
window.LOAN_RATES = {
  credit: '3,55%', maxTenure: '25 ans',
  m2: { 'Paris': 15200, "Côte d'Azur": 12500, 'Alpes': 28000, 'Provence': 8500 },
  asOf: '14 juil. 2026',
};

// ---- "Photographie" SVG élégante pour chaque type de bien ------------------
function buildingSVG(kind) {
  const g = `<defs>
    <linearGradient id="nvy" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#e0c48b"/><stop offset=".5" stop-color="#c9a86a"/><stop offset="1" stop-color="#8a6d3b"/>
    </linearGradient>
    <linearGradient id="crm" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#fdf8ec"/><stop offset="1" stop-color="#ece0c8"/>
    </linearGradient>
    <linearGradient id="sky" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#e7eef4"/><stop offset="1" stop-color="#f6f0e4"/>
    </linearGradient>
    <linearGradient id="mansard" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#5b636b"/><stop offset="1" stop-color="#3a4046"/>
    </linearGradient></defs>
    <rect width="200" height="200" rx="10" fill="url(#sky)"/>
    <ellipse cx="100" cy="188" rx="92" ry="12" fill="#d8d0be"/>`;
  const win = (x, y, w = 8, h = 10) => `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="1.5" fill="#cbd8e6"/>`;
  const winCol = (x, y0, n) => Array.from({length: n}, (_, i) => win(x, y0 + i * 18)).join('');
  const M = {
    // Immeuble haussmannien avec toit mansardé en zinc
    haussmann: `<rect x="58" y="60" width="84" height="126" fill="url(#crm)" stroke="#c9b98d"/>
      <path d="M54 60 L100 30 L146 60 Z" fill="url(#mansard)"/>
      <rect x="52" y="58" width="96" height="6" fill="#8a6d3b"/>
      ${winCol(66, 74, 6)}${winCol(84, 74, 6)}${winCol(102, 74, 6)}${winCol(120, 74, 6)}
      <rect x="58" y="96" width="84" height="4" fill="#d6c9a4"/>`,
    // Hôtel particulier — corps central + ailes, cour
    hotel_particulier: `<rect x="70" y="70" width="60" height="116" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="42" y="96" width="34" height="90" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="124" y="96" width="34" height="90" fill="url(#crm)" stroke="#c9b98d"/>
      <path d="M66 70 L100 44 L134 70 Z" fill="url(#mansard)"/>
      ${winCol(80, 86, 5)}${winCol(102, 86, 5)}${win(50,110,16,14)}${win(132,110,16,14)}
      <rect x="92" y="150" width="18" height="36" rx="2" fill="#7a5a3a"/>`,
    // Appartement / tour contemporaine
    tower: `<rect x="70" y="34" width="60" height="152" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="70" y="34" width="60" height="14" rx="4" fill="url(#nvy)"/>
      ${winCol(80, 58, 7)}${winCol(96, 58, 7)}${winCol(112, 58, 7)}`,
    // Villa méditerranéenne, piscine
    villa: `<rect x="46" y="104" width="120" height="82" rx="5" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="46" y="98" width="120" height="10" fill="url(#nvy)"/>
      ${win(60, 120, 20, 16)}${win(140, 120, 20, 16)}
      <rect x="98" y="140" width="24" height="46" rx="2" fill="#7a5a3a"/>
      <ellipse cx="30" cy="176" rx="24" ry="9" fill="#9ec9e8"/><path d="M10 174 Q30 168 50 174" stroke="#7ba9d4" fill="none"/>
      <circle cx="182" cy="150" r="10" fill="#8fbf8f"/>`,
    // Villa pieds dans l'eau
    waterfront: `<rect x="60" y="96" width="90" height="70" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="60" y="90" width="90" height="10" fill="url(#nvy)"/>
      ${win(72, 112, 18, 14)}${win(120, 112, 18, 14)}
      <rect x="0" y="166" width="200" height="34" fill="#9ec9e8"/>
      <path d="M0 172 Q40 166 80 172 T160 172 T240 172" stroke="#7ba9d4" fill="none"/>
      <path d="M0 184 Q50 178 100 184 T200 184" stroke="#7ba9d4" fill="none"/>`,
    // Chalet alpin, toit en A, bardage bois
    chalet: `<rect x="52" y="104" width="96" height="82" fill="#a9814f"/>
      <path d="M44 108 L100 52 L156 108 Z" fill="#6f5432"/>
      <path d="M44 108 L100 52 L156 108 Z" fill="none" stroke="#4a3820" stroke-width="2"/>
      <rect x="52" y="120" width="96" height="3" fill="#8a6a40"/><rect x="52" y="140" width="96" height="3" fill="#8a6a40"/>
      <rect x="70" y="86" width="26" height="20" fill="#f4e6c4"/><rect x="104" y="86" width="26" height="20" fill="#f4e6c4"/>
      ${win(64, 128, 16, 14)}${win(120, 128, 16, 14)}
      <rect x="92" y="150" width="18" height="36" rx="2" fill="#5a4228"/>
      <path d="M40 118 L60 118 L52 108 Z" fill="#ffffff" opacity=".85"/>`,
    // Penthouse avec terrasse
    penthouse: `<rect x="52" y="86" width="96" height="100" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="66" y="52" width="68" height="34" rx="3" fill="url(#nvy)"/>
      <rect x="74" y="60" width="52" height="16" rx="2" fill="#cbd8e6"/>
      <rect x="52" y="86" width="96" height="12" fill="#e3d6b6"/>
      <circle cx="64" cy="80" r="6" fill="#8fbf8f"/><circle cx="136" cy="80" r="6" fill="#8fbf8f"/>
      ${winCol(64, 104, 4)}${winCol(84, 104, 4)}${winCol(104, 104, 4)}${winCol(124, 104, 4)}`,
    // Studio / pied-à-terre
    studio: `<rect x="60" y="60" width="80" height="126" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <path d="M56 60 L100 38 L144 60 Z" fill="url(#mansard)"/>
      ${winCol(71, 76, 5)}${winCol(93, 76, 5)}${winCol(115, 76, 5)}`,
    // Domaine viticole / mas provençal
    vineyard: `<rect x="58" y="112" width="84" height="74" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <path d="M54 112 L100 84 L146 112 Z" fill="#b25c3a"/>
      ${win(70, 128, 18, 14)}${win(112, 128, 18, 14)}
      <rect x="92" y="150" width="16" height="36" rx="2" fill="#7a5a3a"/>
      <g stroke="#6f8f5a" stroke-width="2">
        <path d="M12 176 L28 158"/><path d="M28 176 L44 158"/><path d="M44 176 L60 158"/>
        <path d="M156 176 L172 158"/><path d="M172 176 L188 158"/></g>`,
    // Plan
    floorplan: `<rect x="40" y="46" width="120" height="108" rx="4" fill="#ffffff" stroke="#8a6d3b" stroke-width="2"/>
      <line x1="100" y1="46" x2="100" y2="118" stroke="#8a6d3b" stroke-width="1.5"/>
      <line x1="40" y1="118" x2="160" y2="118" stroke="#8a6d3b" stroke-width="1.5"/>
      <line x1="128" y1="118" x2="128" y2="154" stroke="#8a6d3b" stroke-width="1.5"/>
      <text x="66" y="86" font-size="10" fill="#8a6d3b" text-anchor="middle" font-family="serif">CHAMBRE</text>
      <text x="130" y="86" font-size="10" fill="#8a6d3b" text-anchor="middle" font-family="serif">SALON</text>
      <text x="82" y="140" font-size="9" fill="#8a6d3b" text-anchor="middle" font-family="serif">CUISINE</text>`,
  }[kind] || `<rect x="58" y="60" width="84" height="126" fill="url(#crm)" stroke="#c9b98d"/>`;
  return `<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">${g}${M}</svg>`;
}
window.jewelSVG = buildingSVG; // app.js appelle window.jewelSVG — même point d'accroche, art nouveau

/*
 * Champs utilisés par le moteur :
 *   price (nombre €), config ('3 pièces' | 'Villa' | 'Chalet' ...), township (tag marque),
 *   city ('Paris' | "Côte d'Azur" | 'Alpes' | 'Provence'),
 *   audience[] (residence-principale | residence-secondaire | investissement | pied-a-terre | international | prestige),
 *   style[] (ancien | neuf | vue-mer | ski | haussmannien | hotel-particulier | terrasse | domaine | penthouse | pieds-dans-l-eau),
 *   possession, carpet (surface affichée).
 */
window.UNITS = [
  // ---- PARIS ----
  { id:'PA-2P-01', name:'Le Marais — Pied-à-terre 2 pièces', township:'Paris 4ᵉ · Le Marais', city:'Paris', cat:'paris',
    config:'2 pièces', carpet:'54 m² · loi Carrez', price:1150000, possession:'Disponible', icon:'studio',
    style:['ancien','haussmannien'], audience:['pied-a-terre','investissement'],
    desc:"Pied-à-terre de charme au cœur du Marais — pierres apparentes, poutres, à deux pas de la place des Vosges." },
  { id:'PA-4P-02', name:'Rive Gauche — Haussmannien 4 pièces', township:'Paris 7ᵉ · Rive Gauche', city:'Paris', cat:'paris',
    config:'4 pièces', carpet:'128 m² · loi Carrez', price:2900000, possession:'Disponible', icon:'haussmann',
    style:['ancien','haussmannien'], audience:['residence-principale','famille'],
    desc:"Étage noble haussmannien : moulures, parquet Versailles, cheminées en marbre, double exposition sur cour et rue." },
  { id:'PA-PH-03', name:'Triangle d\'Or — Penthouse terrasse', township:'Paris 8ᵉ · Triangle d\'Or', city:'Paris', cat:'paris',
    config:'Penthouse', carpet:'210 m² + 90 m² terrasse', price:6500000, possession:'Disponible', icon:'penthouse',
    style:['ancien','terrasse','penthouse'], audience:['prestige','residence-principale'],
    desc:"Dernier étage avec terrasse panoramique sur les toits de Paris et la tour Eiffel — rénovation d'architecte." },
  { id:'PA-HP-04', name:'Hôtel particulier — Muette', township:'Paris 16ᵉ · La Muette', city:'Paris', cat:'paris',
    config:'Hôtel particulier', carpet:'540 m² · jardin 300 m²', price:12000000, possession:'Disponible', icon:'hotel_particulier',
    style:['ancien','hotel-particulier'], audience:['prestige','international'],
    desc:"Hôtel particulier sur jardin, réception en enfilade, ascenseur, cave et parkings — rareté absolue dans le 16ᵉ." },

  // ---- CÔTE D'AZUR ----
  { id:'CA-VL-05', name:'Saint-Tropez — Villa vue mer', township:'Côte d\'Azur · Saint-Tropez', city:"Côte d'Azur", cat:'riviera',
    config:'Villa', carpet:'320 m² · terrain 2 500 m²', price:8500000, possession:'Disponible', icon:'villa',
    style:['ancien','vue-mer'], audience:['residence-secondaire','prestige'],
    desc:"Villa contemporaine sur les hauteurs de Ramatuelle — vue mer imprenable, piscine à débordement, pool-house." },
  { id:'CA-WF-06', name:'Cap-Ferrat — Pieds dans l\'eau', township:'Côte d\'Azur · Cap-Ferrat', city:"Côte d'Azur", cat:'riviera',
    config:'Villa', carpet:'450 m² · accès mer privé', price:18000000, possession:'Disponible', icon:'waterfront',
    style:['ancien','vue-mer','pieds-dans-l-eau'], audience:['prestige','international'],
    desc:"Propriété pieds dans l'eau au Cap-Ferrat — ponton privé, une des adresses les plus prisées de la Riviera." },
  { id:'CA-NF-07', name:'Cannes Croisette — 3 pièces neuf', township:'Côte d\'Azur · Cannes', city:"Côte d'Azur", cat:'riviera',
    config:'3 pièces', carpet:'96 m² + terrasse vue mer', price:2400000, possession:'Livraison T2 2027', icon:'tower',
    style:['neuf','vue-mer'], audience:['investissement','residence-secondaire'],
    desc:"Programme neuf d'exception à deux pas de la Croisette — prestations haut de gamme, TVA récupérable en résidence gérée." },

  // ---- ALPES ----
  { id:'AL-CH-08', name:'Courchevel 1850 — Chalet', township:'Alpes · Courchevel 1850', city:'Alpes', cat:'alpes',
    config:'Chalet', carpet:'480 m² · ski-in ski-out', price:14500000, possession:'Disponible', icon:'chalet',
    style:['ancien','ski'], audience:['prestige','residence-secondaire','international'],
    desc:"Chalet ski-in ski-out à Courchevel 1850 — spa, piscine intérieure, cinéma, la station la plus recherchée des Alpes." },
  { id:'AL-CH-09', name:'Megève — Chalet Mont d\'Arbois', township:'Alpes · Megève', city:'Alpes', cat:'alpes',
    config:'Chalet', carpet:'260 m² · terrain 900 m²', price:6200000, possession:'Disponible', icon:'chalet',
    style:['ancien','ski'], audience:['residence-secondaire','famille'],
    desc:"Chalet au Mont d'Arbois — vieux bois et pierre, vue sur le massif, à proximité immédiate des pistes et du village." },
  { id:'AL-NF-10', name:'Megève — Appartement neuf 3 pièces', township:'Alpes · Megève', city:'Alpes', cat:'alpes',
    config:'3 pièces', carpet:'78 m² · ski-room, casier', price:1350000, possession:'Livraison T4 2027', icon:'tower',
    style:['neuf','ski'], audience:['investissement','residence-secondaire'],
    desc:"Résidence neuve au cœur de Megève — livraison T4 2027, prestations montagne haut de gamme, forte demande locative saisonnière." },

  // ---- PROVENCE / VIGNOBLE ----
  { id:'PR-MS-11', name:'Luberon — Mas provençal', township:'Provence · Luberon', city:'Provence', cat:'provence',
    config:'Mas', carpet:'380 m² · terrain 1,5 ha', price:4300000, possession:'Disponible', icon:'vineyard',
    style:['ancien','domaine'], audience:['residence-secondaire','prestige'],
    desc:"Mas en pierre restauré au cœur du Luberon — oliviers, piscine, vue sur les collines, calme absolu." },
  { id:'PR-DV-12', name:'Bordeaux — Domaine viticole', township:'Nouvelle-Aquitaine · Saint-Émilion', city:'Provence', cat:'provence',
    config:'Domaine', carpet:'Château + 12 ha AOC', price:7800000, possession:'Disponible', icon:'vineyard',
    style:['ancien','domaine'], audience:['investissement','prestige','international'],
    desc:"Propriété viticole en appellation Saint-Émilion — château, chais, vignoble en production, activité clé en main." },
];

window.UNIT_BY_ID = {};
window.UNITS.forEach(p => { window.UNIT_BY_ID[p.id] = p; });
// app.js référence window.PRODUCTS / PRODUCT_BY_ID — alias vers les mêmes objets.
window.PRODUCTS = window.UNITS;
window.PRODUCT_BY_ID = window.UNIT_BY_ID;
