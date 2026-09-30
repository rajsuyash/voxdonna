import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const html = readFileSync(new URL('../ibja-webinar.html', import.meta.url), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(script, 'countdown script exists');
assert.match(html, /id="seat-label">Agent onboarding allocation<\/span><strong class="count" id="seat-count">10<\/strong><span class="unit" id="seat-unit">Total seats<\/span>/);

for (const price of ['₹5,00,000', '₹2,99,000', '₹43,500', '500 minutes', '₹3,00,000', '₹1,79,000', '₹32,500', '1,000 conversations', '₹10,500', '300 images', '35 ultra-HD', '₹50,000', '₹20,000', '₹4,999', '100 credits', '₹9,999', '300 credits', '₹19,999', '700 credits']) {
  assert.ok(html.includes(price), `missing ${price}`);
}
assert.equal((html.match(/class="button claim" aria-disabled="true" data-claim-url=/g) ?? []).length, 4);
const cards = [...html.matchAll(/<article class="card">([\s\S]*?)<\/article>/g)].map(match => match[1]);
assert.equal(cards.length, 4);
for (const [index, url] of ['https://rzp.io/rzp/qMcwHCg', 'https://rzp.io/rzp/o96ymWe', 'https://photo.voxdonna.com', 'https://rzp.io/rzp/tpFougJ9'].entries()) {
  assert.ok(cards[index].includes(`data-claim-url="${url}" target="_blank" rel="noopener noreferrer"`));
}
assert.match(cards[3], /Telegram/);
assert.deepEqual(cards.map(card => card.includes('data-seat-limited')), [true, true, false, true]);

function run(deadline, now, fetchImpl = async () => { throw new Error('offline'); }) {
  let current = now;
  const nodes = new Map();
  const links = cards.map(card => ({
    dataset: { claimUrl: card.match(/data-claim-url="([^"]+)"/)[1] },
    attributes: new Map([['aria-disabled', 'true']]),
    setAttribute(name, value) { this.attributes.set(name, value); },
    removeAttribute(name) { this.attributes.delete(name); },
    hasAttribute(name) { return name === 'data-seat-limited' ? card.includes('data-seat-limited') : this.attributes.has(name); },
    getAttribute(name) { return this.attributes.get(name) ?? null; },
    addEventListener(name, handler) { this[name] = handler; },
  }));
  for (const id of ['offer-status', 'deadline-label', 'hours', 'minutes', 'seconds', 'seat-label', 'seat-count', 'seat-unit', 'seat-note']) nodes.set('#' + id, { textContent: id === 'offer-status' ? 'Checking offer availability…' : '--' });
  const document = {
    querySelector(selector) { return selector === '#offer' ? { dataset: { offerEnds: deadline } } : nodes.get(selector); },
    querySelectorAll() { return links; },
    addEventListener(name, handler) { this[name] = handler; },
    visibilityState: 'visible',
  };
  const window = { intervals: [], setInterval(handler) { this.intervals.push(handler); }, setTimeout() { return 1; }, clearTimeout() {} };
  class TestDate extends Date { static now() { return current; } }
  vm.runInNewContext(script, { document, window, Date: TestDate, Intl, Number, Math, String, AbortController, fetch: fetchImpl });
  return { nodes, links, document, window, setNow(value) { current = value; } };
}
const settle = () => new Promise(resolve => setImmediate(resolve));
const seatData = (claimed, updatedAt) => ({capacity:10, remaining:Math.max(0, 10 - claimed), claimed, updatedAt:new Date(updatedAt).toISOString()});
const seatResponse = data => ({ok:true, json:async () => data});

const deadline = html.match(/data-offer-ends="([^"]+)"/)?.[1];
assert.equal(deadline, '2026-09-30T15:30:00Z', 'offer ends at 9 pm IST on webinar day');
let now = Date.parse(deadline) - 65_000;
let page = run(deadline, now);
assert.equal(page.nodes.get('#minutes').textContent, '01');
assert.equal(page.nodes.get('#seconds').textContent, '05');
assert.ok(page.links.every(link => link.attributes.get('href') === link.dataset.claimUrl && link.attributes.get('aria-disabled') === 'false'));
page.setNow(Date.parse(deadline) - 60_000);
page.window.intervals[0]();
assert.equal(page.nodes.get('#seconds').textContent, '00');

now = Date.parse(deadline) - 30_000;
page = run(deadline, now); // A reload keeps the same absolute deadline.
assert.equal(page.nodes.get('#seconds').textContent, '30');

now = Date.parse(deadline);
page = run(deadline, now);
assert.equal(page.nodes.get('#offer-status').textContent, 'Webinar offer ended');
assert.equal(page.nodes.get('#seconds').textContent, '00');
assert.ok(page.links.every(link => !link.attributes.has('href') && link.attributes.get('aria-disabled') === 'true'));

page = run('invalid', Date.parse(deadline) - 30_000);
assert.equal(page.nodes.get('#offer-status').textContent, 'Webinar offer unavailable');
assert.equal(page.nodes.get('#seconds').textContent, '--');
assert.ok(page.links.every(link => !link.attributes.has('href')));

// Only a fresh, internally consistent server result may be called "seats left".
const first = Date.parse(deadline) - 60_000;
let calls = 0;
page = run(deadline, first, async (url, options) => {
  assert.equal(url, '/ibja-seats.php');
  assert.equal(options.cache, 'no-store');
  return seatResponse(seatData(calls++, first));
});
await settle();
assert.equal(page.nodes.get('#seat-count').textContent, '10');
assert.equal(page.nodes.get('#seat-unit').textContent, 'Agent seats left');
assert.match(page.nodes.get('#seat-note').textContent, /Live availability updated/);
page.window.intervals[1]();
await settle();
assert.equal(page.nodes.get('#seat-count').textContent, '9');

page = run(deadline, first, async () => seatResponse(seatData(10, first)));
await settle();
assert.equal(page.nodes.get('#seat-count').textContent, '0');
assert.equal(page.nodes.get('#offer-status').textContent, 'Agent seats filled. Photo App remains available until 9 pm IST.');
assert.deepEqual(page.links.map(link => link.attributes.has('href')), [false, false, true, false]);
let soldOutClickPrevented = false;
page.links[0].click({preventDefault() { soldOutClickPrevented = true; }});
assert.equal(soldOutClickPrevented, true);

const early = Date.parse(deadline) - 300_000;
let soldOutCalls = 0;
page = run(deadline, early, async () => {
  soldOutCalls++;
  if (soldOutCalls === 2) throw new Error('temporary outage');
  return seatResponse(seatData(soldOutCalls === 3 ? 9 : 10, soldOutCalls === 3 ? early + 121_000 : early));
});
await settle();
page.window.intervals[1](); // A failed refresh cannot reopen a confirmed sellout.
await settle();
assert.equal(page.nodes.get('#seat-count').textContent, '0');
assert.match(page.nodes.get('#seat-label').textContent, /Last confirmed/);
assert.deepEqual(page.links.map(link => link.attributes.has('href')), [false, false, true, false]);
page.setNow(early + 121_000); // An aged-out result still cannot reopen checkout.
page.window.intervals[0]();
assert.match(page.nodes.get('#seat-note').textContent, /Last confirmed sold out/);
assert.deepEqual(page.links.map(link => link.attributes.has('href')), [false, false, true, false]);
page.window.intervals[1](); // A newly verified positive count can reopen checkout.
await settle();
assert.equal(page.nodes.get('#seat-count').textContent, '1');
assert.ok(page.links.every(link => link.attributes.has('href')));

for (const bad of [{...seatData(1, first), remaining:10}, seatData(1, first - 121_000)]) {
  page = run(deadline, first, async () => seatResponse(bad));
  await settle();
  assert.equal(page.nodes.get('#seat-count').textContent, '10');
  assert.equal(page.nodes.get('#seat-unit').textContent, 'Total seats');
  assert.match(page.nodes.get('#seat-note').textContent, /Live availability unavailable\. Confirm before paying\./);
  assert.ok(page.links.every(link => link.attributes.has('href')));
}

let release;
page = run(deadline, first, () => new Promise(resolve => { release = resolve; }));
page.setNow(Date.parse(deadline));
page.window.intervals[0]();
release(seatResponse(seatData(0, first)));
await settle();
assert.equal(page.nodes.get('#offer-status').textContent, 'Webinar offer ended');
assert.ok(page.links.every(link => !link.attributes.has('href')));

page = run(deadline, Date.parse(deadline) - 30_000);
assert.ok(page.links[0].attributes.has('href'));
page.setNow(Date.parse(deadline) + 1); // Simulate a suspended tab with a stale active link.
let prevented = false;
page.links[0].click({ preventDefault() { prevented = true; } });
assert.equal(prevented, true);
assert.ok(page.links.every(link => !link.attributes.has('href')));

console.log('IBJA webinar pricing, seats, and countdown checks passed');
