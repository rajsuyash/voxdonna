/* Illustrative sales-lounge / experience-centre directory for the demo. */
window.LOUNGES = [
  { id:'PWI', city:'Mumbai', name:'Hiranandani Gardens Sales Lounge', area:'Central Avenue, Hiranandani Gardens, Powai', state:'Maharashtra',
    hours:'10:00–19:30', langs:['English','Hindi','Marathi','Gujarati'], showFlat:true, lat:19.12, lng:72.91 },
  { id:'THN', city:'Thane', name:'Hiranandani Estate Experience Centre', area:'Ghodbunder Road, Hiranandani Estate, Thane West', state:'Maharashtra',
    hours:'10:00–19:30', langs:['Marathi','Hindi','English','Gujarati'], showFlat:true, lat:19.26, lng:72.97 },
  { id:'PNV', city:'Panvel', name:'Fortune City Experience Centre', area:'Mumbai–Pune Highway, Panvel, Navi Mumbai', state:'Maharashtra',
    hours:'10:00–19:00', langs:['Marathi','Hindi','English'], showFlat:true, lat:18.99, lng:73.12 },
  { id:'VRT', city:'Virtual', name:'Live Video Walkthrough', area:'Guided video tour of show flat + township, on WhatsApp or Zoom', state:'—',
    hours:'09:00–21:00 IST, all days', langs:['English','Hindi','Marathi'], showFlat:true, lat:0, lng:0 },
];
window.LOUNGE_BY_CITY = {};
window.LOUNGES.forEach(s => { window.LOUNGE_BY_CITY[s.city.toLowerCase()] = s; });
// app.js reads window.STORES / STORE_BY_CITY — alias.
window.STORES = window.LOUNGES;
window.STORE_BY_CITY = window.LOUNGE_BY_CITY;
