/* Annuaire illustratif des agences / bureaux Breteuil pour la démo. */
window.LOUNGES = [
  { id:'P16', city:'Paris', name:'Breteuil Paris — Agence Victor Hugo', area:'Avenue Victor Hugo, Paris 16ᵉ', state:'Île-de-France',
    hours:'9h30–19h00', langs:['Français','Anglais','Italien','Arabe'], showFlat:true, lat:48.870, lng:2.284 },
  { id:'P07', city:'Paris', name:'Breteuil Paris — Agence Champ-de-Mars', area:'Avenue de la Bourdonnais, Paris 7ᵉ', state:'Île-de-France',
    hours:'9h30–19h00', langs:['Français','Anglais','Espagnol'], showFlat:true, lat:48.858, lng:2.301 },
  { id:'NEU', city:'Neuilly', name:'Breteuil Neuilly — Agence Sablons', area:'Avenue Charles de Gaulle, Neuilly-sur-Seine', state:'Île-de-France',
    hours:'9h30–19h00', langs:['Français','Anglais'], showFlat:true, lat:48.883, lng:2.269 },
  { id:'NIC', city:"Côte d'Azur", name:'Breteuil Nice — Agence Carré d\'Or', area:'Rue de France, Nice', state:"Provence-Alpes-Côte d'Azur",
    hours:'9h30–18h30', langs:['Français','Anglais','Italien'], showFlat:true, lat:43.695, lng:7.259 },
  { id:'VRT', city:'Virtual', name:'Visite privée en visioconférence', area:'Visite guidée du bien en direct, sur WhatsApp ou Zoom', state:'—',
    hours:'8h00–22h00 CET, tous les jours', langs:['Français','Anglais','Italien'], showFlat:true, lat:0, lng:0 },
];
window.LOUNGE_BY_CITY = {};
window.LOUNGES.forEach(s => { window.LOUNGE_BY_CITY[s.city.toLowerCase()] = s; });
// app.js lit window.STORES / STORE_BY_CITY — alias.
window.STORES = window.LOUNGES;
window.STORE_BY_CITY = window.LOUNGE_BY_CITY;
