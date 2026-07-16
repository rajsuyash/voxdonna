/*
 * Breteuil Immobilier — Catalogue de biens (démo).
 * Prix / disponibilités ILLUSTRATIFS, à des fins de démonstration uniquement.
 * Les visuels sont rendus en SVG inline pour que la démo fonctionne hors-ligne.
 */
window.LOAN_RATES = {
  credit: '3,55%', maxTenure: '25 ans',
  m2: { 'Paris': 13800, 'Neuilly': 12200, "Côte d'Azur": 9500 },
  asOf: '16 juil. 2026',
};

// ---- "Photographie" SVG élégante pour chaque type de bien ------------------
function buildingSVG(kind) {
  const g = `<defs>
    <linearGradient id="nvy" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#4a6da8"/><stop offset=".5" stop-color="#2c4a7c"/><stop offset="1" stop-color="#152744"/>
    </linearGradient>
    <linearGradient id="crm" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#fdf8ec"/><stop offset="1" stop-color="#e6ddcb"/>
    </linearGradient>
    <linearGradient id="sky" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#dfe8f1"/><stop offset="1" stop-color="#f2f0e6"/>
    </linearGradient>
    <linearGradient id="mansard" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#5b636b"/><stop offset="1" stop-color="#3a4046"/>
    </linearGradient></defs>
    <rect width="200" height="200" rx="10" fill="url(#sky)"/>
    <ellipse cx="100" cy="188" rx="92" ry="12" fill="#d5d3c4"/>`;
  const win = (x, y, w = 8, h = 10) => `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="1.5" fill="#cbd8e6"/>`;
  const winCol = (x, y0, n) => Array.from({length: n}, (_, i) => win(x, y0 + i * 18)).join('');
  const M = {
    // Immeuble haussmannien avec toit mansardé en zinc + balcon filant
    haussmann: `<rect x="58" y="60" width="84" height="126" fill="url(#crm)" stroke="#c9b98d"/>
      <path d="M54 60 L100 30 L146 60 Z" fill="url(#mansard)"/>
      <rect x="52" y="58" width="96" height="6" fill="#26406b"/>
      ${winCol(66, 74, 6)}${winCol(84, 74, 6)}${winCol(102, 74, 6)}${winCol(120, 74, 6)}
      <rect x="58" y="96" width="84" height="3" fill="#7d8ba0"/>`,
    // Maison de ville / hôtel particulier — corps central + ailes, jardin
    hotel_particulier: `<rect x="70" y="70" width="60" height="116" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="42" y="96" width="34" height="90" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="124" y="96" width="34" height="90" fill="url(#crm)" stroke="#c9b98d"/>
      <path d="M66 70 L100 44 L134 70 Z" fill="url(#mansard)"/>
      ${winCol(80, 86, 5)}${winCol(102, 86, 5)}${win(50,110,16,14)}${win(132,110,16,14)}
      <rect x="92" y="150" width="18" height="36" rx="2" fill="#7a5a3a"/>`,
    // Programme neuf contemporain
    tower: `<rect x="70" y="34" width="60" height="152" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="70" y="34" width="60" height="14" rx="4" fill="url(#nvy)"/>
      ${winCol(80, 58, 7)}${winCol(96, 58, 7)}${winCol(112, 58, 7)}`,
    // Villa Côte d'Azur, piscine
    villa: `<rect x="46" y="104" width="120" height="82" rx="5" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="46" y="98" width="120" height="10" fill="url(#nvy)"/>
      ${win(60, 120, 20, 16)}${win(140, 120, 20, 16)}
      <rect x="98" y="140" width="24" height="46" rx="2" fill="#7a5a3a"/>
      <ellipse cx="30" cy="176" rx="24" ry="9" fill="#9ec9e8"/><path d="M10 174 Q30 168 50 174" stroke="#7ba9d4" fill="none"/>
      <circle cx="182" cy="150" r="10" fill="#8fbf8f"/>`,
    // Appartement vue mer
    waterfront: `<rect x="60" y="96" width="90" height="70" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="60" y="90" width="90" height="10" fill="url(#nvy)"/>
      ${win(72, 112, 18, 14)}${win(120, 112, 18, 14)}
      <rect x="0" y="166" width="200" height="34" fill="#9ec9e8"/>
      <path d="M0 172 Q40 166 80 172 T160 172 T240 172" stroke="#7ba9d4" fill="none"/>
      <path d="M0 184 Q50 178 100 184 T200 184" stroke="#7ba9d4" fill="none"/>`,
    // Penthouse avec terrasse
    penthouse: `<rect x="52" y="86" width="96" height="100" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <rect x="66" y="52" width="68" height="34" rx="3" fill="url(#nvy)"/>
      <rect x="74" y="60" width="52" height="16" rx="2" fill="#cbd8e6"/>
      <rect x="52" y="86" width="96" height="12" fill="#dfd6bf"/>
      <circle cx="64" cy="80" r="6" fill="#8fbf8f"/><circle cx="136" cy="80" r="6" fill="#8fbf8f"/>
      ${winCol(64, 104, 4)}${winCol(84, 104, 4)}${winCol(104, 104, 4)}${winCol(124, 104, 4)}`,
    // Studio / atelier / pied-à-terre
    studio: `<rect x="60" y="60" width="80" height="126" rx="4" fill="url(#crm)" stroke="#c9b98d"/>
      <path d="M56 60 L100 38 L144 60 Z" fill="url(#mansard)"/>
      ${winCol(71, 76, 5)}${winCol(93, 76, 5)}${winCol(115, 76, 5)}`,
    // Plan
    floorplan: `<rect x="40" y="46" width="120" height="108" rx="4" fill="#ffffff" stroke="#26406b" stroke-width="2"/>
      <line x1="100" y1="46" x2="100" y2="118" stroke="#26406b" stroke-width="1.5"/>
      <line x1="40" y1="118" x2="160" y2="118" stroke="#26406b" stroke-width="1.5"/>
      <line x1="128" y1="118" x2="128" y2="154" stroke="#26406b" stroke-width="1.5"/>
      <text x="66" y="86" font-size="10" fill="#26406b" text-anchor="middle" font-family="serif">CHAMBRE</text>
      <text x="130" y="86" font-size="10" fill="#26406b" text-anchor="middle" font-family="serif">SALON</text>
      <text x="82" y="140" font-size="9" fill="#26406b" text-anchor="middle" font-family="serif">CUISINE</text>`,
  }[kind] || `<rect x="58" y="60" width="84" height="126" fill="url(#crm)" stroke="#c9b98d"/>`;
  return `<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">${g}${M}</svg>`;
}
window.jewelSVG = buildingSVG; // app.js appelle window.jewelSVG — même point d'accroche, art nouveau

/*
 * Champs utilisés par le moteur :
 *   price (nombre €), config ('3 pièces' | 'Villa' | 'Maison' ...), township (tag marque),
 *   city ('Paris' | 'Neuilly' | "Côte d'Azur"),
 *   audience[] (residence-principale | residence-secondaire | investissement | pied-a-terre | international | prestige | famille),
 *   style[] (ancien | neuf | vue-mer | haussmannien | terrasse | penthouse | hotel-particulier | atypique),
 *   possession, carpet (surface affichée).
 */
window.UNITS = [
  // ---- PARIS ----
  { id:'PA-1P-01', name:'Saint-Germain — Studio', township:'Paris 6ᵉ · Saint-Germain', city:'Paris', cat:'paris',
    config:'Studio', carpet:'32 m² · loi Carrez', price:680000, possession:'Disponible', icon:'studio',
    style:['ancien','haussmannien'], audience:['pied-a-terre','investissement'],
    desc:"Studio de charme au cœur de Saint-Germain-des-Prés — parquet, moulures, immeuble en pierre de taille, forte demande locative." },
  { id:'PA-2P-02', name:'Champ-de-Mars — 2 pièces', township:'Paris 7ᵉ · Champ-de-Mars', city:'Paris', cat:'paris',
    config:'2 pièces', carpet:'48 m² · loi Carrez', price:1150000, possession:'Disponible', icon:'haussmann',
    style:['ancien','haussmannien'], audience:['pied-a-terre','residence-principale'],
    desc:"2 pièces lumineux à deux pas du Champ-de-Mars — vue dégagée, étage élevé, cave, gardien." },
  { id:'PA-3P-03', name:'Passy — 3 pièces familial', township:'Paris 16ᵉ · Passy', city:'Paris', cat:'paris',
    config:'3 pièces', carpet:'82 m² · loi Carrez', price:1650000, possession:'Disponible', icon:'haussmann',
    style:['ancien','haussmannien'], audience:['residence-principale','famille'],
    desc:"3 pièces au calme dans le quartier de Passy — double séjour, cuisine séparée, proche écoles et commerces." },
  { id:'PA-4P-04', name:'Monceau — 4 pièces haussmannien', township:'Paris 17ᵉ · Monceau', city:'Paris', cat:'paris',
    config:'4 pièces', carpet:'118 m² · loi Carrez', price:2300000, possession:'Disponible', icon:'haussmann',
    style:['ancien','haussmannien'], audience:['famille','residence-principale'],
    desc:"Étage noble face au parc Monceau — moulures, parquet Versailles, cheminées, double exposition." },
  { id:'PA-5P-05', name:'Trocadéro — Appartement de réception', township:'Paris 16ᵉ · Trocadéro', city:'Paris', cat:'paris',
    config:'5 pièces', carpet:'176 m² · loi Carrez', price:3800000, possession:'Disponible', icon:'tower',
    style:['ancien','haussmannien'], audience:['prestige','famille'],
    desc:"Grand appartement de réception près du Trocadéro — enfilade classique, hauteur sous plafond, vue sur monument." },
  { id:'PA-PH-06', name:'Madeleine — Penthouse terrasse', township:'Paris 8ᵉ · Madeleine', city:'Paris', cat:'paris',
    config:'Penthouse', carpet:'165 m² + 55 m² terrasse', price:5900000, possession:'Disponible', icon:'penthouse',
    style:['ancien','terrasse','penthouse'], audience:['prestige','residence-principale'],
    desc:"Dernier étage avec vaste terrasse sur les toits de Paris — rénovation d'architecte, ascenseur privatif." },
  { id:'PA-AT-07', name:'Odéon — Atelier d\'artiste', township:'Paris 6ᵉ · Odéon', city:'Paris', cat:'paris',
    config:'Atelier', carpet:'92 m² · verrière plein sud', price:2100000, possession:'Disponible', icon:'studio',
    style:['ancien','atypique'], audience:['pied-a-terre','prestige'],
    desc:"Atelier d'artiste avec verrière et volumes atypiques — pièce de réception à double hauteur, mezzanine, calme absolu sur cour." },

  // ---- NEUILLY-SUR-SEINE ----
  { id:'NE-MV-08', name:'Neuilly — Maison de ville', township:'Neuilly · Saint-James', city:'Neuilly', cat:'neuilly',
    config:'Maison', carpet:'240 m² · jardin 180 m²', price:4200000, possession:'Disponible', icon:'hotel_particulier',
    style:['ancien','hotel-particulier'], audience:['famille','prestige'],
    desc:"Maison de ville sur jardin dans le quartier Saint-James — 5 chambres, garage, calme résidentiel, écoles à proximité." },
  { id:'NE-4P-09', name:'Neuilly — 4 pièces les Sablons', township:'Neuilly · Les Sablons', city:'Neuilly', cat:'neuilly',
    config:'4 pièces', carpet:'106 m² · loi Carrez', price:1850000, possession:'Disponible', icon:'haussmann',
    style:['ancien','haussmannien'], audience:['famille','residence-principale'],
    desc:"4 pièces familial près du métro Les Sablons — balcon, étage élevé, proche du bois de Boulogne." },

  // ---- CÔTE D'AZUR ----
  { id:'CA-3P-10', name:'Nice — 3 pièces vue mer, Carré d\'Or', township:"Côte d'Azur · Nice", city:"Côte d'Azur", cat:'riviera',
    config:'3 pièces', carpet:'88 m² + balcon vue mer', price:1450000, possession:'Disponible', icon:'waterfront',
    style:['ancien','vue-mer'], audience:['residence-secondaire','investissement'],
    desc:"3 pièces vue mer dans le Carré d'Or de Nice — Belle Époque rénovée, balcon plein sud sur la Promenade." },
  { id:'CA-VL-11', name:"Cap d'Antibes — Villa", township:"Côte d'Azur · Cap d'Antibes", city:"Côte d'Azur", cat:'riviera',
    config:'Villa', carpet:'280 m² · terrain 1 800 m²', price:6500000, possession:'Disponible', icon:'villa',
    style:['ancien','vue-mer'], audience:['residence-secondaire','prestige'],
    desc:"Villa au Cap d'Antibes — vue mer, piscine, pool-house, jardin méditerranéen, à quelques minutes des plages." },

  // ---- PROGRAMME NEUF (VEFA) ----
  { id:'BB-NF-12', name:'Boulogne — 3 pièces neuf', township:'Boulogne-Billancourt · Rives de Seine', city:'Paris', cat:'neuf',
    config:'3 pièces', carpet:'72 m² + balcon', price:980000, possession:'Livraison T4 2027', icon:'tower',
    style:['neuf'], audience:['investissement','residence-principale'],
    desc:"Programme neuf sur les Rives de Seine à Boulogne — frais de notaire réduits, prestations haut de gamme, forte demande locative." },
];

window.UNIT_BY_ID = {};
window.UNITS.forEach(p => { window.UNIT_BY_ID[p.id] = p; });
// app.js référence window.PRODUCTS / PRODUCT_BY_ID — alias vers les mêmes objets.
window.PRODUCTS = window.UNITS;
window.PRODUCT_BY_ID = window.UNIT_BY_ID;
