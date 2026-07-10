/* Illustrative chapter-office directory for the demo. */
window.CHAPTERS = [
  { id:'BOM', city:'Mumbai', name:'JITO Apex Head Office', area:'Dadar East, Mumbai', state:'Maharashtra',
    hours:'10:00–18:00 Mon–Sat', langs:['English','Hindi','Gujarati','Marathi'], showFlat:false, lat:19.02, lng:72.84 },
  { id:'AMD', city:'Ahmedabad', name:'JITO Ahmedabad Chapter', area:'Navrangpura, Ahmedabad', state:'Gujarat',
    hours:'10:30–18:30 Mon–Sat', langs:['Gujarati','Hindi','English'], showFlat:false, lat:23.03, lng:72.56 },
  { id:'PNQ', city:'Pune', name:'JITO Pune Chapter', area:'Shivajinagar, Pune', state:'Maharashtra',
    hours:'10:30–18:30 Mon–Sat', langs:['Marathi','Hindi','English'], showFlat:false, lat:18.53, lng:73.85 },
  { id:'HYD', city:'Hyderabad', name:'JITO Hyderabad Chapter', area:'Banjara Hills, Hyderabad', state:'Telangana',
    hours:'10:30–18:30 Mon–Sat', langs:['Hindi','English','Telugu'], showFlat:false, lat:17.41, lng:78.44 },
  { id:'VRT', city:'Virtual', name:'JITO Global Member Desk', area:'Video call — for overseas chapters & NRI members', state:'—',
    hours:'09:00–21:00 IST, all days', langs:['English','Hindi','Gujarati'], showFlat:false, lat:0, lng:0 },
];
window.CHAPTER_BY_CITY = {};
window.CHAPTERS.forEach(s => { window.CHAPTER_BY_CITY[s.city.toLowerCase()] = s; });
// app.js reads window.STORES / STORE_BY_CITY — alias.
window.STORES = window.CHAPTERS;
window.STORE_BY_CITY = window.CHAPTER_BY_CITY;
