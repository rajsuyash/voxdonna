import { readFileSync } from 'node:fs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { boot } from './helpers.mjs';
import { DEMO_CATALOGUE, TOOL_DECLARATIONS, createLead, handleToolCall } from '../tools.mjs';

const html = readFileSync(new URL('../../demos.html', import.meta.url), 'utf8');
const unescape = (t) => t.replace(/&amp;/g, '&').trim();
const cards = [...html.matchAll(/<article class="demo-card"([^>]*)>([\s\S]*?)<\/article>/g)].map((m) => ({
  slug: /data-slug="([^"]+)"/.exec(m[1])?.[1],
  title: unescape(/demo-card-title">([^<]*)/.exec(m[2])?.[1] ?? ''),
}));
const nav = (args) => handleToolCall(createLead(), { name: 'navigate', args });
const instructions = readFileSync(new URL('../instructions.md', import.meta.url), 'utf8');

test('catalogue and demos.html cover the same cards, with the same titles', () => {
  assert.ok(cards.length > 0, 'found demo cards');
  const cat = new Map(DEMO_CATALOGUE.map((d) => [d.slug, d.title]));
  assert.equal(cat.size, DEMO_CATALOGUE.length, 'no duplicate slugs');
  assert.deepEqual([...cat.keys()].sort(), cards.map((c) => c.slug).sort());
  for (const c of cards) assert.equal(cat.get(c.slug), c.title, c.slug);
  for (const d of DEMO_CATALOGUE) assert.match(d.slug, /^[a-z0-9]+(-[a-z0-9]+)*$/);
});

test('navigate demos + valid slug deep-links to that demo card', () => {
  const { response, events } = nav({ route: 'demos', demo: 'restaurant-table-booking' });
  assert.equal(response.ok, true);
  assert.deepEqual(events, [{ type: 'navigate', route: 'demos', url: '/demos.html#restaurant-table-booking', demo: 'restaurant-table-booking' }]);
  assert.match(response.note, /Do not speak again/);
});

test('navigate demos without a slug opens the gallery', () => {
  assert.deepEqual(nav({ route: 'demos' }).events, [{ type: 'navigate', route: 'demos', url: '/demos.html' }]);
});

test('navigate rejects an unknown slug (listing valid ones) and a slug on another route', () => {
  for (const demo of ['nope', '../x', 'https://evil.example', 42]) {
    const r = nav({ route: 'demos', demo });
    assert.equal(r.response.ok, false, String(demo));
    assert.match(r.response.error, /unknown demo; valid demos: .*restaurant-table-booking/);
    assert.deepEqual(r.events, []);
  }
  const r = nav({ route: 'pricing', demo: 'restaurant-table-booking' });
  assert.equal(r.response.ok, false);
  assert.deepEqual(r.events, []);
});

test('navigate declaration exposes the demo enum and the catalogue', () => {
  const d = TOOL_DECLARATIONS.find((t) => t.name === 'navigate');
  assert.deepEqual(d.parameters.properties.demo.enum, DEMO_CATALOGUE.map((x) => x.slug));
  assert.ok(d.description.includes('restaurant-table-booking = Restaurant Table Booking'));
});

test('a demo-slug navigate passes the mid-intake guard when the visitor picks one', () => {
  const lead = createLead();
  lead.set('name', 'Asha');
  lead.hear('the first one');
  assert.equal(handleToolCall(lead, { name: 'navigate', args: { route: 'demos', demo: 'clinic-appointment-triage' } }).response.ok, true);
  lead.hear('Jewellery retail');
  assert.equal(handleToolCall(lead, { name: 'navigate', args: { route: 'demos', demo: 'clinic-appointment-triage' } }).response.ok, false);
});

test('over the wire: the browser only receives the relay-built url', async (t) => {
  const env = await boot(); t.after(env.stop);
  const c = await env.open();
  env.fake.send({ toolCall: { functionCalls: [{ id: 'd1', name: 'navigate', args: { route: 'demos', demo: 'hvac-emergency-dispatch', url: 'https://evil.example' } }] } });
  const m = await c.waitFor((x) => x.type === 'navigate');
  assert.equal(m.url, '/demos.html#hvac-emergency-dispatch');
});

test('instructions: one transition line before navigate, demo guidance, confirm-before-save email', () => {
  assert.match(instructions, /BEFORE you call navigate and nothing after the tool response/);
  assert.match(instructions, /Recommend the 1 or 2 best matches/);
  assert.match(instructions, /offer to book a call|book a call with the team/);
  assert.match(instructions, /Do NOT call save_field yet\. Save it only AFTER the visitor confirms/);
  assert.match(instructions, /do not repeat the question you just asked/);
  assert.match(instructions, /demo's slug/);
});

test('instructions: custom need offers the call; recommendations end with "which one"; no filler openers', () => {
  assert.match(instructions, /Want me to book a call with the team\?/);
  assert.match(instructions, /takes priority over continuing intake, so do not ask for their name/);
  assert.match(instructions, /Which one should I open\?/);
  assert.match(instructions, /No filler openers: never "I'd be happy to", "I can certainly", "definitely", "absolutely"/);
});
