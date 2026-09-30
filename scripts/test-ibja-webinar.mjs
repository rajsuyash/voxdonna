import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const html = readFileSync(new URL('../ibja-webinar.html', import.meta.url), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(script, 'countdown script exists');

for (const price of ['₹5,00,000', '₹2,99,000', '₹43,500', '500 minutes', '₹3,00,000', '₹1,79,000', '₹32,500', '1,000 conversations', '₹5,300', '300 images', '35 ultra-HD', '₹50,000', '₹20,000', '₹4,999', '100 credits', '₹9,999', '300 credits', '₹19,999', '700 credits']) {
  assert.ok(html.includes(price), `missing ${price}`);
}
assert.equal((html.match(/class="button claim" aria-disabled="true" data-claim-url=/g) ?? []).length, 4);
const cards = [...html.matchAll(/<article class="card">([\s\S]*?)<\/article>/g)].map(match => match[1]);
assert.equal(cards.length, 4);
for (const [index, url] of ['https://rzp.io/rzp/qMcwHCg', 'https://rzp.io/rzp/o96ymWe', null, 'https://rzp.io/rzp/tpFougJ9'].entries()) {
  if (url) {
    assert.ok(cards[index].includes(`data-claim-url="${url}" target="_blank" rel="noopener noreferrer"`));
  } else {
    assert.match(cards[index], /data-claim-url="https:\/\/wa\.me\/18023920148\?text=/);
  }
}
assert.match(cards[3], /Telegram/);

function run(deadline, now) {
  let current = now;
  const nodes = new Map();
  const links = Array.from({ length: 4 }, () => ({
    dataset: { claimUrl: 'https://wa.me/18023920148?text=test' },
    attributes: new Map([['aria-disabled', 'true']]),
    setAttribute(name, value) { this.attributes.set(name, value); },
    removeAttribute(name) { this.attributes.delete(name); },
    addEventListener(name, handler) { this[name] = handler; },
  }));
  for (const id of ['offer-status', 'deadline-label', 'hours', 'minutes', 'seconds']) nodes.set('#' + id, { textContent: id === 'offer-status' ? 'Checking offer availability…' : '--' });
  const document = {
    querySelector(selector) { return selector === '#offer' ? { dataset: { offerEnds: deadline } } : nodes.get(selector); },
    querySelectorAll() { return links; },
    addEventListener(name, handler) { this[name] = handler; },
  };
  const window = { setInterval(handler) { this.tick = handler; } };
  class TestDate extends Date { static now() { return current; } }
  vm.runInNewContext(script, { document, window, Date: TestDate, Intl, Number, Math, String });
  return { nodes, links, document, window, setNow(value) { current = value; } };
}

const deadline = '2026-10-01T00:00:00Z';
let now = Date.parse(deadline) - 65_000;
let page = run(deadline, now);
assert.equal(page.nodes.get('#minutes').textContent, '01');
assert.equal(page.nodes.get('#seconds').textContent, '05');
assert.ok(page.links.every(link => link.attributes.get('href') === link.dataset.claimUrl && link.attributes.get('aria-disabled') === 'false'));
page.setNow(Date.parse(deadline) - 60_000);
page.window.tick();
assert.equal(page.nodes.get('#seconds').textContent, '00');

now = Date.parse(deadline) - 30_000;
page = run(deadline, now); // A reload keeps the same absolute deadline.
assert.equal(page.nodes.get('#seconds').textContent, '30');

now = Date.parse(deadline) + 1;
page = run(deadline, now);
assert.equal(page.nodes.get('#offer-status').textContent, 'Webinar offer ended');
assert.equal(page.nodes.get('#seconds').textContent, '00');
assert.ok(page.links.every(link => !link.attributes.has('href') && link.attributes.get('aria-disabled') === 'true'));

page = run('invalid', Date.parse(deadline) - 30_000);
assert.equal(page.nodes.get('#offer-status').textContent, 'Webinar offer unavailable');
assert.equal(page.nodes.get('#seconds').textContent, '--');
assert.ok(page.links.every(link => !link.attributes.has('href')));

page = run(deadline, Date.parse(deadline) - 30_000);
assert.ok(page.links[0].attributes.has('href'));
page.setNow(Date.parse(deadline) + 1); // Simulate a suspended tab with a stale active link.
let prevented = false;
page.links[0].click({ preventDefault() { prevented = true; } });
assert.equal(prevented, true);
assert.ok(page.links.every(link => !link.attributes.has('href')));

console.log('IBJA webinar pricing and countdown checks passed');
