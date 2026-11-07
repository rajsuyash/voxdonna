import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const here = fileURLToPath(new URL('.', import.meta.url));
const repo = join(here, '..', '..');
const raw = readFileSync(join(repo, 'assets', 'automation-plan', 'industries.json'), 'utf8');
const lib = JSON.parse(readFileSync(join(here, '..', 'industry-library.json'), 'utf8'));
const data = JSON.parse(raw);
const MENU = ['jewellery-retail', 'jewellery-manufacturing', 'sap-manufacturing', 'real-estate', 'rooftop-solar', 'kitchen-appliances', 'luxury-furniture'];
const SUBSUMED = 3; // research industries folded into featured ones (see scripts/automation-plan-overrides.json)
const RESEARCH_INDUSTRIES = 40;
const UNITS = ['calls', 'messages', 'orders', 'documents', 'leads'];
const CHANNELS = ['voice', 'whatsapp', 'email', 'chat', 'sms', 'web'];
const TYPES = ['revenue', 'cost', 'experience', 'risk'];
const EFFORTS = ['days', '2-4 weeks', '1-2 months'];
const BANNED = ['delve', 'robust', 'comprehensive', 'nuanced', 'multifaceted', 'leverage', 'pivotal', 'landscape', 'intricate', 'vibrant', 'fundamental', 'significant'];
const VENDORS = ['elevenlabs', 'eleven labs', 'vapi', 'retell', 'bland', 'synthflow', 'openai', 'chatgpt', 'gpt', 'intercom', 'fin\\.ai', 'brilo', 'cordiva', 'polyai', 'air\\.ai', 'google', 'gemini', 'anthropic', 'claude', 'twilio', 'deepgram', 'cartesia', 'sarvam', 'dm champ', 'dmchamp', 'zapier', 'shopify', 'zendesk', 'gorgias', 'klaviyo', 'salesforce', 'hubspot'];
const wordRe = (w) => new RegExp(`(?<![\\p{L}\\p{N}])(?:${w.join('|')})(?![\\p{L}\\p{N}])`, 'iu');
const words = (s) => s.trim().split(/\s+/).length;
const inds = data.industries;
const autos = inds.flatMap((i) => i.automations.map((a) => ({ ...a, industry: i.id })));
const textOf = (a) => [a.title, a.what_it_does, a.first_step];
const urlFile = (u) => join(repo, u.replace('https://voxdonna.com/', ''));

test('shape: schema_version, 7 featured first in menu order, industry count', () => {
  assert.equal(data.schema_version, 1);
  assert.deepEqual(inds.filter((i) => i.featured).map((i) => i.id), MENU);
  assert.deepEqual(inds.slice(0, 7).map((i) => i.id), MENU);
  assert.equal(inds.length, 7 + (RESEARCH_INDUSTRIES - SUBSUMED));
  const rest = inds.slice(7).map((i) => i.name.toLowerCase());
  assert.deepEqual(rest, [...rest].sort());
  for (const i of inds) {
    assert.ok(/^[a-z0-9-]+$/.test(i.id) && i.name && i.group, i.id);
    assert.ok(UNITS.includes(i.volume_unit), `${i.id} unit`);
    assert.ok(i.pains.length >= 4 && i.pains.length <= 6, `${i.id} pains ${i.pains.length}`);
    assert.ok(i.automations.length >= 3, `${i.id} automations ${i.automations.length}`);
  }
});

test('ids unique; pain refs resolve both ways', () => {
  assert.equal(new Set(inds.map((i) => i.id)).size, inds.length);
  assert.equal(new Set(autos.map((a) => a.id)).size, autos.length);
  for (const i of inds) {
    const ids = i.pains.map((p) => p.id);
    assert.equal(new Set(ids).size, ids.length, `${i.id} duplicate pain ids`);
    for (const p of i.pains) assert.ok(words(p.label) <= 6, `${i.id} pain label ${p.label}`);
    for (const a of i.automations) {
      assert.ok(a.pains.length > 0, `${a.id} no pains`);
      for (const p of a.pains) assert.ok(ids.includes(p), `${a.id} unknown pain ${p}`);
    }
    for (const p of i.pains) assert.ok(i.automations.some((a) => a.pains.includes(p.id)), `${i.id}/${p.id} unaddressed`);
  }
});

test('enums, score, title length, ordering, source', () => {
  assert.ok(autos.length > 100);
  for (const i of inds) {
    const scores = i.automations.map((a) => a.score);
    assert.deepEqual(scores, [...scores].sort((x, y) => y - x), `${i.id} not sorted by score`);
  }
  for (const a of autos) {
    assert.ok(a.channels.length > 0 && a.channels.every((c) => CHANNELS.includes(c)), `${a.id} channels`);
    assert.ok(TYPES.includes(a.type), `${a.id} type`);
    assert.ok(EFFORTS.includes(a.effort), `${a.id} effort`);
    assert.ok(Number.isInteger(a.score) && a.score >= 0 && a.score <= 100, `${a.id} score`);
    assert.ok(words(a.title) <= 8, `${a.id} title words`);
    assert.ok(['site', 'research'].includes(a.source), `${a.id} source`);
    assert.ok(a.what_it_does.length > 20 && a.first_step.length > 10, a.id);
  }
});

test('page_url is null or maps to an existing repo file', () => {
  for (const x of [...inds, ...autos]) {
    if (x.page_url === null) continue;
    assert.match(x.page_url, /^https:\/\/voxdonna\.com\/[A-Za-z0-9/_-]+\.html$/, x.id);
    assert.ok(existsSync(urlFile(x.page_url)), `${x.id}: missing ${x.page_url}`);
  }
  for (const i of inds.slice(0, 7)) assert.ok(i.page_url, `${i.id} featured needs page_url`);
});

test('featured industries hold every library entry, on_site and owner-approved proposed', () => {
  const entries = lib.industries.flatMap((i) => i.automations);
  const proposed = entries.filter((a) => a.status === 'proposed').map((a) => a.id);
  assert.equal(proposed.length, 10);
  const bySite = new Map(autos.filter((a) => a.source === 'site').map((a) => [a.id, a]));
  for (const e of entries) assert.ok(bySite.has(e.id), `${e.id} missing`);
  assert.equal(bySite.size, entries.length);
  for (const id of proposed) assert.ok(bySite.has(id), `proposed ${id} missing`);
});

test('no digits in titles, descriptions, first steps, pain labels or industry names', () => {
  for (const i of inds) for (const s of [i.name, ...i.pains.map((p) => p.label)]) assert.doesNotMatch(s, /\d/, `${i.id}: ${s}`);
  for (const a of autos) for (const s of textOf(a)) assert.doesNotMatch(s, /\d/, `${a.id}: ${s}`);
});

test('no banned words, vendor names, links, emojis or em dashes', () => {
  const strings = [];
  for (const i of inds) strings.push(i.name, i.group, ...i.pains.map((p) => p.label));
  for (const a of autos) strings.push(...textOf(a));
  assert.ok(strings.length > 500);
  for (const s of strings) {
    assert.doesNotMatch(s, wordRe(BANNED), `banned word: ${s}`);
    assert.doesNotMatch(s, wordRe(VENDORS), `vendor name: ${s}`);
    assert.doesNotMatch(s, /\p{Extended_Pictographic}|[—–]/u, `emoji or dash: ${s}`);
    assert.doesNotMatch(s, /https?:|www\.|@/i, `link: ${s}`);
  }
});

test('no benchmark, evidence or source fields anywhere, and no source urls in the file', () => {
  const FORBIDDEN = /^(source_?urls?|source_?name|evidence|benchmark|benchmarks|kpi|financial_impact)$/i;
  const walk = (n) => {
    if (Array.isArray(n)) return n.forEach(walk);
    if (n && typeof n === 'object') for (const [k, v] of Object.entries(n)) { assert.doesNotMatch(k, FORBIDDEN, `forbidden field ${k}`); walk(v); }
  };
  walk(data);
  const urls = raw.match(/https?:\/\/[^"\s]+/g) ?? [];
  assert.ok(urls.length > 0);
  for (const u of urls) assert.match(u, /^https:\/\/voxdonna\.com\//, `foreign url ${u}`);
  assert.doesNotMatch(raw, /\.xlsx/i);
});
