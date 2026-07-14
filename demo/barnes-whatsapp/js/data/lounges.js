/* Annuaire illustratif des boutiques / bureaux BARNES pour la démo. */
window.LOUNGES = [
  { id:'PAR', city:'Paris', name:'BARNES Paris — Boutique Rive Droite', area:'Avenue Montaigne, Paris 8ᵉ', state:'Île-de-France',
    hours:'9h30–19h00', langs:['Français','Anglais','Italien','Arabe'], showFlat:true, lat:48.866, lng:2.306 },
  { id:'RIV', city:"Côte d'Azur", name:'BARNES Riviera — Bureau Saint-Tropez', area:'Place de la Garonne, Saint-Tropez', state:"Provence-Alpes-Côte d'Azur",
    hours:'9h30–19h00', langs:['Français','Anglais','Italien','Russe'], showFlat:true, lat:43.269, lng:6.640 },
  { id:'ALP', city:'Alpes', name:'BARNES Courchevel — Bureau Alpes', area:'Rue de l\'Église, Courchevel 1850', state:"Auvergne-Rhône-Alpes",
    hours:'9h00–19h00', langs:['Français','Anglais','Russe'], showFlat:true, lat:45.415, lng:6.634 },
  { id:'PRO', city:'Provence', name:'BARNES Provence — Bureau Luberon', area:'Cours Mirabeau, Aix-en-Provence', state:"Provence-Alpes-Côte d'Azur",
    hours:'9h30–18h30', langs:['Français','Anglais'], showFlat:true, lat:43.528, lng:5.447 },
  { id:'VRT', city:'Virtual', name:'Visite privée en visioconférence', area:'Visite guidée du bien en direct, sur WhatsApp ou Zoom', state:'—',
    hours:'8h00–22h00 CET, tous les jours', langs:['Français','Anglais','Italien'], showFlat:true, lat:0, lng:0 },
];
window.LOUNGE_BY_CITY = {};
window.LOUNGES.forEach(s => { window.LOUNGE_BY_CITY[s.city.toLowerCase()] = s; });
// app.js lit window.STORES / STORE_BY_CITY — alias.
window.STORES = window.LOUNGES;
window.STORE_BY_CITY = window.LOUNGE_BY_CITY;
