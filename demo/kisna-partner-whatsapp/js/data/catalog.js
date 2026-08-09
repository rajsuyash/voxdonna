/*
 * Kisna Partner Desk — wholesale catalogue for the demo.
 * B2B, so every SKU carries the numbers a retailer actually decides on:
 * wholesale price per piece, MRP, margin, MOQ and lead time — not a retail price tag.
 * All figures are ILLUSTRATIVE. Imagery is inline SVG so the demo runs fully offline.
 */
window.KISNA_RATE = {
  gold22: 7150, gold18: 5860, gold14: 4570,
  diamondIndex: '+1.8% MoM', making: '₹520–₹760 / g (design-dependent)',
  asOf: '07 Aug 2026, 09:30 IST',
};

// ---- Inline-SVG "photography" per design type ---------------------------
function kisnaSVG(kind) {
  const defs = `<defs>
    <linearGradient id="k-gold" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#f9e7b0"/><stop offset=".5" stop-color="#dfb457"/><stop offset="1" stop-color="#a97c12"/>
    </linearGradient>
    <linearGradient id="k-dia" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#ffffff"/><stop offset=".55" stop-color="#dceeff"/><stop offset="1" stop-color="#8fbde8"/>
    </linearGradient>
    <radialGradient id="k-bg" cx=".5" cy=".32" r=".92">
      <stop offset="0" stop-color="#fdfbf6"/><stop offset="1" stop-color="#ece3d3"/>
    </radialGradient></defs>
    <rect width="200" height="200" rx="10" fill="url(#k-bg)"/>`;

  const stone = (x, y, r) => `<path d="M${x - r} ${y} L${x} ${y - r} L${x + r} ${y} L${x} ${y + r} Z" fill="url(#k-dia)" stroke="#7fa8d0" stroke-width=".8"/>`;

  const art = {
    ring: `<ellipse cx="100" cy="126" rx="38" ry="44" fill="none" stroke="url(#k-gold)" stroke-width="12"/>
      ${stone(100, 66, 20)}${stone(72, 82, 8)}${stone(128, 82, 8)}`,
    solitaire: `<ellipse cx="100" cy="130" rx="36" ry="42" fill="none" stroke="url(#k-gold)" stroke-width="11"/>
      ${stone(100, 64, 26)}`,
    band: `<ellipse cx="100" cy="100" rx="46" ry="54" fill="none" stroke="url(#k-gold)" stroke-width="15"/>
      ${[70, 100, 130].map(x => stone(x, 52, 7)).join('')}`,
    studs: `${[70, 130].map(x => `<circle cx="${x}" cy="100" r="19" fill="url(#k-gold)"/>${stone(x, 100, 12)}`).join('')}`,
    drops: `${[70, 130].map(x => `${stone(x, 74, 10)}<path d="M${x} 84 L${x} 104" stroke="url(#k-gold)" stroke-width="3"/>${stone(x, 120, 15)}`).join('')}`,
    pendant: `<path d="M50 58 Q100 96 150 58" stroke="url(#k-gold)" stroke-width="4.5" fill="none"/>
      ${stone(100, 118, 30)}${stone(100, 118, 14)}`,
    pendantset: `<path d="M50 52 Q100 88 150 52" stroke="url(#k-gold)" stroke-width="4" fill="none"/>
      ${stone(100, 106, 24)}${[62, 138].map(x => stone(x, 150, 11)).join('')}`,
    mangalsutra: `<path d="M34 62 Q100 118 166 62" stroke="#1d2733" stroke-width="5" fill="none"/>
      ${[52, 66, 80, 120, 134, 148].map((x, i) => `<circle cx="${x}" cy="${80 + (i < 3 ? (2 - i) * 6 : (i - 3) * 6)}" r="4" fill="#1d2733"/>`).join('')}
      ${stone(100, 122, 26)}${stone(100, 122, 12)}`,
    bracelet: `<path d="M40 100 Q100 134 160 100" stroke="url(#k-gold)" stroke-width="5" fill="none"/>
      ${[58, 79, 100, 121, 142].map((x, i) => stone(x, 108 + (i === 2 ? 8 : i === 1 || i === 3 ? 5 : 0), 9)).join('')}`,
    bangle: `<ellipse cx="100" cy="100" rx="50" ry="58" fill="none" stroke="url(#k-gold)" stroke-width="13"/>
      ${[100, 62, 138].map((x, i) => stone(x, i === 0 ? 44 : 100, 8)).join('')}`,
    nosepin: `<circle cx="100" cy="112" r="34" fill="none" stroke="url(#k-gold)" stroke-width="4"/>
      ${stone(100, 78, 16)}`,
    mensring: `<ellipse cx="100" cy="106" rx="44" ry="50" fill="none" stroke="url(#k-gold)" stroke-width="18"/>
      <rect x="80" y="42" width="40" height="30" rx="4" fill="#1d2733" stroke="url(#k-gold)" stroke-width="2"/>${stone(100, 57, 9)}`,
    kids: `<ellipse cx="74" cy="100" rx="24" ry="30" fill="none" stroke="url(#k-gold)" stroke-width="8"/>
      <ellipse cx="126" cy="100" rx="24" ry="30" fill="none" stroke="url(#k-gold)" stroke-width="8"/>${stone(74, 70, 7)}${stone(126, 70, 7)}`,
  }[kind] || `${stone(100, 100, 34)}`;

  return `<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${kind} design">${defs}${art}</svg>`;
}

/*
 * wsp  = wholesale price to the retail partner, per piece (ex-GST)
 * mrp  = printed retail price the partner sells at
 * moq  = minimum order quantity for that design
 * lead = working days to dispatch when made to order
 */
window.SKUS = [
  // ---- Everyday · fast-moving, low ticket -------------------------------
  { code:'KSN-ER-1042', name:'Everyday Diamond Studs', line:'Everyday', cat:'earring', icon:'studs',
    purity:'14K', dia:'0.12 ct · SI/IJ', gross:'1.9 g', wsp:14200, mrp:21500, moq:12, lead:7, stock:'ready', fast:true,
    tags:['everyday','gifting','fast-moving','entry'], desc:'The counter workhorse — lowest ticket in the range, highest repeat.' },
  { code:'KSN-PD-1088', name:'Halo Diamond Pendant', line:'Everyday', cat:'pendant', icon:'pendant',
    purity:'14K', dia:'0.18 ct · SI/GH', gross:'2.4 g', wsp:19800, mrp:29900, moq:10, lead:7, stock:'ready', fast:true,
    tags:['everyday','gifting','fast-moving'], desc:'Halo setting reads a full carat bigger than it is — easy first-diamond sale.' },
  { code:'KSN-RG-1121', name:'Slim Stackable Band', line:'Everyday', cat:'ring', icon:'band',
    purity:'14K', dia:'0.10 ct · SI/IJ', gross:'1.6 g', wsp:11600, mrp:17900, moq:15, lead:5, stock:'ready', fast:true,
    tags:['everyday','stackable','entry','gifting'], desc:'Sells in threes. Stock the 12–16 size run, not singles.' },
  { code:'KSN-NP-1150', name:'Diamond Nose Pin', line:'Everyday', cat:'nosepin', icon:'nosepin',
    purity:'18K', dia:'0.06 ct · VS/GH', gross:'0.7 g', wsp:7400, mrp:11900, moq:20, lead:5, stock:'ready', fast:true,
    tags:['everyday','entry','impulse'], desc:'Impulse buy at the counter. Highest units-per-invoice in the catalogue.' },

  // ---- Solitaire look · mid ticket --------------------------------------
  { code:'KSN-RG-2210', name:'Solitaire-look Ring', line:'Solitaire Look', cat:'ring', icon:'solitaire',
    purity:'18K', dia:'0.45 ct · VS/GH', gross:'3.2 g', wsp:78500, mrp:112000, moq:4, lead:12, stock:'make-to-order', fast:false,
    tags:['engagement','proposal','premium'], desc:'Cluster set that wears like a solitaire at a third of the diamond cost.' },
  { code:'KSN-PD-2244', name:'Solitaire-look Pendant', line:'Solitaire Look', cat:'pendant', icon:'pendant',
    purity:'18K', dia:'0.38 ct · VS/GH', gross:'2.8 g', wsp:62000, mrp:89500, moq:4, lead:12, stock:'make-to-order', fast:false,
    tags:['anniversary','premium','gifting'], desc:'Anniversary staple. Pairs into a set with KSN-ER-2251.' },
  { code:'KSN-ER-2251', name:'Solitaire-look Drops', line:'Solitaire Look', cat:'earring', icon:'drops',
    purity:'18K', dia:'0.52 ct · VS/GH', gross:'4.1 g', wsp:84000, mrp:124000, moq:4, lead:14, stock:'make-to-order', fast:false,
    tags:['anniversary','premium','occasion'], desc:'Sell as a set with the pendant — average ticket jumps 2.3×.' },
  { code:'KSN-BR-2280', name:'Tennis Bracelet', line:'Solitaire Look', cat:'bracelet', icon:'bracelet',
    purity:'18K', dia:'1.05 ct · SI/GH', gross:'6.8 g', wsp:168000, mrp:239000, moq:2, lead:18, stock:'make-to-order', fast:false,
    tags:['milestone','premium','anniversary'], desc:'Milestone-gift piece. Slow mover, but it anchors your window display.' },

  // ---- Bridal · high ticket ---------------------------------------------
  { code:'KSN-MS-3310', name:'Diamond Mangalsutra', line:'Bridal', cat:'mangalsutra', icon:'mangalsutra',
    purity:'18K', dia:'0.62 ct · VS/GH', gross:'8.4 g', wsp:96500, mrp:142000, moq:3, lead:15, stock:'make-to-order', fast:true,
    tags:['bridal','wedding','fast-moving','premium'], desc:'The one bridal piece that never sits. Keep 3 on the counter year-round.' },
  { code:'KSN-MS-3318', name:'Short Daily Mangalsutra', line:'Bridal', cat:'mangalsutra', icon:'mangalsutra',
    purity:'14K', dia:'0.24 ct · SI/GH', gross:'4.2 g', wsp:38900, mrp:57500, moq:6, lead:10, stock:'ready', fast:true,
    tags:['bridal','everyday','fast-moving'], desc:'Post-wedding daily wear — the repeat purchase after the heavy set.' },
  { code:'KSN-PS-3342', name:'Bridal Pendant Set', line:'Bridal', cat:'pendantset', icon:'pendantset',
    purity:'18K', dia:'0.88 ct · VS/GH', gross:'9.6 g', wsp:148000, mrp:214000, moq:2, lead:20, stock:'make-to-order', fast:false,
    tags:['bridal','wedding','premium','set'], desc:'Pendant + matching drops. Reception-look piece for the ₹2L bridal budget.' },
  { code:'KSN-BG-3370', name:'Diamond Bangle (pair)', line:'Bridal', cat:'bangle', icon:'bangle',
    purity:'18K', dia:'1.42 ct · SI/GH', gross:'18.2 g', wsp:246000, mrp:352000, moq:1, lead:22, stock:'make-to-order', fast:false,
    tags:['bridal','wedding','premium','statement'], desc:'Trousseau statement pair. Order against a confirmed bridal booking.' },

  // ---- Men & Kids --------------------------------------------------------
  { code:'KSN-MR-4410', name:"Men's Signet Ring", line:'Men', cat:'mensring', icon:'mensring',
    purity:'18K', dia:'0.28 ct · SI/GH', gross:'7.8 g', wsp:64500, mrp:94000, moq:3, lead:14, stock:'make-to-order', fast:false,
    tags:['men','gifting','occasion'], desc:'Under-served category. Almost no local competition on the shelf.' },
  { code:'KSN-MR-4428', name:"Men's Diamond Band", line:'Men', cat:'mensring', icon:'mensring',
    purity:'14K', dia:'0.15 ct · SI/IJ', gross:'5.2 g', wsp:31500, mrp:47500, moq:5, lead:10, stock:'ready', fast:false,
    tags:['men','wedding','gifting'], desc:'Groom-band for the wedding season. Stock sizes 18–22.' },
  { code:'KSN-KD-4460', name:'Kids Diamond Bangles (pair)', line:'Kids', cat:'kids', icon:'kids',
    purity:'14K', dia:'0.08 ct · SI/IJ', gross:'3.4 g', wsp:18900, mrp:28500, moq:8, lead:8, stock:'ready', fast:false,
    tags:['kids','gifting','newborn'], desc:'Naming-ceremony and first-birthday gifting. Steady, unseasonal demand.' },

  // ---- Festive / temple fusion ------------------------------------------
  { code:'KSN-PD-5510', name:'Temple-Fusion Pendant', line:'Temple Fusion', cat:'pendant', icon:'pendant',
    purity:'18K', dia:'0.34 ct · SI/GH', gross:'5.6 g', wsp:58000, mrp:86000, moq:4, lead:14, stock:'make-to-order', fast:false,
    tags:['festive','south','traditional','occasion'], desc:'Diamond piece for the customer who only buys traditional gold.' },
  { code:'KSN-ER-5522', name:'Festive Jhumka Drops', line:'Temple Fusion', cat:'earring', icon:'drops',
    purity:'18K', dia:'0.46 ct · SI/GH', gross:'7.1 g', wsp:79500, mrp:116000, moq:3, lead:16, stock:'make-to-order', fast:true,
    tags:['festive','wedding','traditional','fast-moving'], desc:'Diwali-to-wedding-season mover. Order by mid-August to land in time.' },
  { code:'KSN-RG-5540', name:'Festive Cocktail Ring', line:'Temple Fusion', cat:'ring', icon:'ring',
    purity:'18K', dia:'0.55 ct · SI/GH', gross:'5.9 g', wsp:88000, mrp:128000, moq:3, lead:16, stock:'make-to-order', fast:false,
    tags:['festive','occasion','statement'], desc:'Festive self-purchase. Strong in metro and tier-1 counters.' },
];

window.SKU_BY_CODE = Object.fromEntries(window.SKUS.map(s => [s.code, s]));
window.kisnaSVG = kisnaSVG;
