/* Illustrative service / experience-centre directory for the demo. */
window.CENTRES = [
  { id:'MUM', city:'Mumbai', name:'Tata Power Solar Experience Centre — Mumbai', area:'Senapati Bapat Marg, Lower Parel, Mumbai', state:'Maharashtra',
    hours:'09:30–18:30 Mon–Sat', langs:['English','Hindi','Marathi','Gujarati'], showFlat:true, lat:19.00, lng:72.83 },
  { id:'PUN', city:'Pune', name:'Tata Power Solar Channel Partner Hub — Pune', area:'Baner Road, Pune', state:'Maharashtra',
    hours:'09:30–18:30 Mon–Sat', langs:['Marathi','Hindi','English'], showFlat:true, lat:18.56, lng:73.78 },
  { id:'JAI', city:'Jaipur', name:'Ghar Ghar Solar Centre — Jaipur', area:'Tonk Road, Jaipur', state:'Rajasthan',
    hours:'09:30–18:30 Mon–Sat', langs:['Hindi','English'], showFlat:true, lat:26.85, lng:75.80 },
  { id:'VRT', city:'Virtual', name:'Video Site Survey', area:'Engineer joins on WhatsApp video — walk them across your roof with your phone', state:'—',
    hours:'09:00–21:00 IST, all days', langs:['English','Hindi','Marathi'], showFlat:true, lat:0, lng:0 },
];
window.CENTRE_BY_CITY = {};
window.CENTRES.forEach(s => { window.CENTRE_BY_CITY[s.city.toLowerCase()] = s; });
// app.js reads window.STORES / STORE_BY_CITY — alias.
window.STORES = window.CENTRES;
window.STORE_BY_CITY = window.CENTRE_BY_CITY;
