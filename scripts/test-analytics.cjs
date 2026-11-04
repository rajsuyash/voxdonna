const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname,'../assets/analytics.js'),'utf8');
function fixture(saved, blocked=false) {
  const nodes=[];
  function element(tag) {return {tag,dataset:{},attrs:{},listeners:{},setAttribute(k,v){this.attrs[k]=v;},addEventListener(k,v){this.listeners[k]=v;},focus(){},querySelector(){return {focus(){}};}};}
  const document={currentScript:{dataset:{measurementId:'G-TEST123456'}},referrer:'https://example.com/?email=private',cookie:'_ga=abc; session=keep',getElementById(id){return nodes.find(n=>n.id===id);},createElement:element,head:{appendChild(n){nodes.push(n);}},body:{append(...n){nodes.push(...n);}}};
  let storage=JSON.stringify(saved);
  const context={document,window:{},Date,URL,location:{href:'https://voxdonna.com/?email=private&utm_source=test#secret',hostname:'voxdonna.com'},localStorage:{getItem(){if(blocked)throw Error();return storage;},setItem(k,v){if(blocked)throw Error();storage=v;}}};
  vm.runInNewContext(source,context);
  return {context,nodes,click(value){nodes.find(n=>n.id==='vd-analytics-panel').listeners.click({target:{dataset:{choice:value}}});},tags(){return nodes.filter(n=>n.tag==='script');}};
}
test('unknown and rejected consent never load Google; accepting loads once with sanitized location',()=>{
 const f=fixture();assert.equal(f.tags().length,0);f.click('denied');assert.equal(f.tags().length,0);f.click('granted');f.click('granted');assert.equal(f.tags().length,1);
 const config=f.context.window.dataLayer.find(x=>x[0]==='config');assert.equal(config[2].page_location,'https://voxdonna.com/?utm_source=test');assert.equal(config[2].page_referrer,'https://example.com/');assert.equal(config[2].allow_google_signals,false);
 f.click('denied');assert.equal(f.context.window['ga-disable-G-TEST123456'],true);
});
test('saved consent, expired consent and unavailable storage are handled',()=>{
 assert.equal(fixture({value:'granted',updated:Date.now()}).tags().length,1);
 assert.equal(fixture({value:'denied',updated:Date.now()}).tags().length,0);
 assert.equal(fixture({value:'granted',updated:0}).tags().length,0);
 const f=fixture(null,true);assert.equal(f.tags().length,0);f.click('granted');assert.equal(f.tags().length,1);
});
