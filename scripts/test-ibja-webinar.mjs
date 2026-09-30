import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const html = readFileSync(new URL('../ibja-webinar.html', import.meta.url), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(script);
const individualEnd = html.match(/data-offer-ends="([^"]+)"/)?.[1];
const bundleEnd = html.match(/data-bundle-ends="([^"]+)"/)?.[1];
assert.equal(individualEnd, '2026-09-30T15:30:00Z');
assert.equal(bundleEnd, '2026-09-30T13:30:00Z');
assert.match(html, /Voice Agent \+ Support Agent/);
assert.match(html, /₹8,00,000[\s\S]*?₹4,49,000[\s\S]*?44% off setup[\s\S]*?₹65,000/);
assert.match(html, /id="seat-label">Bundle allocation<\/span><strong class="count" id="seat-count">10<\/strong><span class="unit" id="seat-unit">Total bundle places<\/span>/);
assert.match(html, /id="bundle-claim" class="button bundle-claim" aria-disabled="true" data-claim-url="https:\/\/rzp\.io\/rzp\/uoCh15n" target="_blank" rel="noopener noreferrer"/);
assert.doesNotMatch(html, /<a (?:id="bundle-claim" )?class="button (?:bundle-claim|claim)"[^>]*\shref=/);

for (const text of ['₹5,00,000', '₹2,99,000', '₹43,500', '500 minutes', '₹3,00,000', '₹1,79,000', '₹32,500', '1,000 conversations', '₹10,500', '300 images', '35 ultra-HD', '₹50,000', '₹20,000', '₹4,999', '100 credits', '₹9,999', '300 credits', '₹19,999', '700 credits']) assert.ok(html.includes(text), `missing ${text}`);
const cards = [...html.matchAll(/<article class="card">([\s\S]*?)<\/article>/g)].map(match => match[1]);
assert.equal(cards.length, 4);
for (const [index, url] of ['https://rzp.io/rzp/qMcwHCg', 'https://rzp.io/rzp/o96ymWe', 'https://photo.voxdonna.com', 'https://rzp.io/rzp/tpFougJ9'].entries()) assert.ok(cards[index].includes(`data-claim-url="${url}" target="_blank" rel="noopener noreferrer"`));
assert.ok(cards.every(card => !card.includes('data-seat-limited')));

function link(url) {
  return {
    dataset: {claimUrl:url}, attributes:new Map([['aria-disabled', 'true']]),
    setAttribute(name, value) { this.attributes.set(name, value); },
    removeAttribute(name) { this.attributes.delete(name); },
    getAttribute(name) { return this.attributes.get(name) ?? null; },
    addEventListener(name, handler) { this[name] = handler; },
  };
}
function run(now, fetchImpl = async () => { throw new Error('offline'); }, ends = individualEnd, bundleEnds = bundleEnd) {
  let current = now;
  const links = cards.map(card => link(card.match(/data-claim-url="([^"]+)"/)[1]));
  const bundleLink = link('https://rzp.io/rzp/uoCh15n');
  const nodes = new Map();
  for (const id of ['offer-status', 'bundle-status', 'deadline-label', 'hours', 'minutes', 'seconds', 'bundle-hours', 'bundle-minutes', 'bundle-seconds', 'seat-label', 'seat-count', 'seat-unit', 'seat-note']) nodes.set('#' + id, {textContent:'--'});
  const document = {
    visibilityState:'visible',
    querySelector(selector) { return selector === '#offer' ? {dataset:{offerEnds:ends, bundleEnds}} : selector === '.bundle-claim' ? bundleLink : nodes.get(selector); },
    querySelectorAll() { return links; },
    addEventListener(name, handler) { this[name] = handler; },
  };
  const window = {intervals:[], setInterval(handler) { this.intervals.push(handler); }, setTimeout() { return 1; }, clearTimeout() {}};
  class TestDate extends Date { static now() { return current; } }
  vm.runInNewContext(script, {document, window, Date:TestDate, Intl, Number, Math, String, AbortController, fetch:fetchImpl});
  return {nodes, links, bundleLink, window, setNow(value) { current = value; }};
}
const settle = () => new Promise(resolve => setImmediate(resolve));
const data = (claimed, updatedAt) => ({capacity:10, remaining:Math.max(0, 10 - claimed), claimed, updatedAt:new Date(updatedAt).toISOString()});
const response = payload => ({ok:true, json:async () => payload});
const seven = Date.parse(bundleEnd);
const nine = Date.parse(individualEnd);
const open = seven - 65_000;

let page = run(open);
assert.equal(page.nodes.get('#bundle-minutes').textContent, '01');
assert.equal(page.nodes.get('#bundle-seconds').textContent, '05');
assert.equal(page.bundleLink.getAttribute('href'), page.bundleLink.dataset.claimUrl);
assert.ok(page.links.every(item => item.attributes.has('href')));
assert.equal(page.nodes.get('#seat-unit').textContent, 'Total bundle places');
page.setNow(seven); // A suspended tab cannot follow a stale bundle link.
let prevented = false;
page.bundleLink.click({preventDefault() { prevented = true; }});
assert.equal(prevented, true);
assert.equal(page.bundleLink.getAttribute('href'), null);
assert.ok(page.links.every(item => item.attributes.has('href')));
assert.equal(page.nodes.get('#bundle-status').textContent, 'Bundle offer closed');

page = run(seven);
assert.equal(page.nodes.get('#bundle-seconds').textContent, '00');
assert.equal(page.bundleLink.getAttribute('href'), null);
assert.ok(page.links.every(item => item.attributes.has('href')));
page.setNow(nine);
page.window.intervals[0]();
assert.equal(page.nodes.get('#offer-status').textContent, 'Individual offers ended');
assert.ok(page.links.every(item => !item.attributes.has('href')));
page = run(nine);
assert.equal(page.bundleLink.getAttribute('href'), null);
assert.ok(page.links.every(item => !item.attributes.has('href')));

const early = seven - 300_000;
let calls = 0;
page = run(early, async (url, options) => {
  assert.equal(url, '/ibja-seats.php');
  assert.equal(options.cache, 'no-store');
  return response(data(calls++, early));
});
await settle();
assert.equal(page.nodes.get('#seat-count').textContent, '10');
assert.equal(page.nodes.get('#seat-unit').textContent, 'Bundle places left');
page.window.intervals[1]();
await settle();
assert.equal(page.nodes.get('#seat-count').textContent, '9');

let sequence = 0;
page = run(early, async () => {
  sequence++;
  if (sequence === 2) throw new Error('temporary outage');
  return response(data(sequence >= 3 ? 9 : 10, sequence === 4 ? early + 121_000 : early));
});
await settle();
assert.equal(page.nodes.get('#seat-count').textContent, '0');
assert.equal(page.bundleLink.getAttribute('href'), null);
assert.ok(page.links.every(item => item.attributes.has('href')));
page.window.intervals[1]();
await settle();
assert.match(page.nodes.get('#seat-note').textContent, /Last confirmed bundle sold out/);
assert.equal(page.bundleLink.getAttribute('href'), null);
page.window.intervals[1](); // The same timestamp cannot overturn confirmed sellout.
await settle();
assert.equal(page.bundleLink.getAttribute('href'), null);
page.setNow(early + 121_000);
page.window.intervals[0]();
assert.equal(page.bundleLink.getAttribute('href'), null);
assert.ok(page.links.every(item => item.attributes.has('href')));
page.window.intervals[1]();
await settle();
assert.equal(page.nodes.get('#seat-count').textContent, '1');
assert.equal(page.bundleLink.getAttribute('href'), page.bundleLink.dataset.claimUrl);

for (const bad of [{...data(1, early), remaining:10}, data(1, early - 121_000)]) {
  page = run(early, async () => response(bad));
  await settle();
  assert.equal(page.nodes.get('#seat-count').textContent, '10');
  assert.equal(page.nodes.get('#seat-unit').textContent, 'Total bundle places');
  assert.equal(page.bundleLink.getAttribute('href'), page.bundleLink.dataset.claimUrl);
}

let release;
page = run(early, () => new Promise(resolve => { release = resolve; }));
page.setNow(seven);
page.window.intervals[0]();
release(response(data(0, early)));
await settle();
assert.equal(page.bundleLink.getAttribute('href'), null);
assert.ok(page.links.every(item => item.attributes.has('href')));

page = run(open, undefined, 'invalid');
assert.ok(page.links.every(item => !item.attributes.has('href')));
assert.equal(page.bundleLink.getAttribute('href'), null);
console.log('IBJA webinar bundle, seats, pricing, and deadline checks passed');
