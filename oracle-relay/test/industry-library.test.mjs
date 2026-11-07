import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const here = fileURLToPath(new URL('.', import.meta.url));
const repo = join(here, '..', '..');
const lib = JSON.parse(readFileSync(join(here, '..', 'industry-library.json'), 'utf8'));
const catalogue = JSON.parse(readFileSync(join(here, '..', 'catalogue.json'), 'utf8'));
const EFFORTS = ['days', '2-4 weeks', '1-2 months'];
const UNITS = ['calls', 'messages', 'orders', 'documents', 'leads'];
const BANNED = ['delve', 'robust', 'comprehensive', 'nuanced', 'multifaceted', 'leverage', 'pivotal', 'landscape', 'intricate', 'vibrant', 'fundamental', 'significant'];
const VENDORS = ['elevenlabs', 'eleven labs', 'openai', 'chatgpt', 'gpt', 'google', 'gemini', 'vertex', 'anthropic', 'claude', 'twilio', 'resend', 'deepgram', 'cartesia', 'sarvam', 'vapi', 'retell', 'bland', 'synthflow', 'dm champ', 'dmchamp', 'zapier'];
const wordRe = (w) => new RegExp(`(?<![\\p{L}\\p{N}])(?:${w.join('|')})(?![\\p{L}\\p{N}])`, 'iu');
const NAMED = { amp: '&', nbsp: ' ', quot: '"', apos: "'", mdash: '-', ndash: '-', rarr: '>', rsquo: "'", lsquo: "'", ldquo: '"', rdquo: '"', middot: '.' };
const norm = (s) => s.replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
  .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
  .replace(/&([a-z]+);/gi, (m, n) => NAMED[n.toLowerCase()] ?? m)
  .replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/[–—]/g, '-')
  .replace(/\s+/g, ' ').trim();
const pageText = (path) => norm(readFileSync(join(repo, path), 'utf8')
  .replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' '));
const words = (s) => s.trim().split(/\s+/).length;
const autos = lib.industries.flatMap((i) => i.automations.map((a) => ({ ...a, industry: i.id })));
const textOf = (a) => [a.title, a.what_it_does, a.first_step];

test('shape: schema_version 1 and 7 industries with required fields', () => {
  assert.equal(lib.schema_version, 1);
  assert.equal(lib.industries.length, 7);
  for (const i of lib.industries) {
    assert.ok(UNITS.includes(i.volume_unit), `${i.id} volume_unit`);
    assert.ok(i.name && /^[a-z0-9-]+$/.test(i.id));
    assert.ok(i.pains.length >= 4 && i.pains.length <= 6, `${i.id} pains ${i.pains.length}`);
    assert.ok(i.automations.length >= 8 && i.automations.length <= 10, `${i.id} automations ${i.automations.length}`);
    assert.ok(i.automations.filter((a) => a.status === 'proposed').length <= 3, `${i.id} proposed cap`);
    for (const p of i.pains) assert.ok(p.id && words(p.label) <= 6, `${i.id} pain label ${p.label}`);
  }
});

test('ids: automation ids globally unique, pain ids unique per industry, refs resolve', () => {
  assert.equal(new Set(autos.map((a) => a.id)).size, autos.length);
  for (const i of lib.industries) {
    const ids = i.pains.map((p) => p.id);
    assert.equal(new Set(ids).size, ids.length, `${i.id} duplicate pain ids`);
    for (const a of i.automations) {
      assert.ok(a.pains.length > 0, `${a.id} has no pains`);
      for (const p of a.pains) assert.ok(ids.includes(p), `${a.id} unknown pain ${p}`);
    }
    for (const p of i.pains) assert.ok(i.automations.some((a) => a.pains.includes(p.id)), `${i.id}/${p.id} addressed by nothing`);
  }
});

test('enums, product_id, title length, status/evidence pairing', () => {
  const cat = new Map(catalogue.map((c) => [c.id, c]));
  for (const a of autos) {
    assert.ok(EFFORTS.includes(a.effort), `${a.id} effort`);
    assert.ok(UNITS.includes(a.volume_driver), `${a.id} volume_driver`);
    assert.ok(a.product_id === null || cat.has(a.product_id), `${a.id} product_id`);
    if (a.product_id) assert.equal(a.effort, cat.get(a.product_id).effort, `${a.id} effort differs from catalogue`);
    assert.ok(words(a.title) <= 8, `${a.id} title words`);
    assert.ok(['on_site', 'proposed'].includes(a.status), `${a.id} status`);
    if (a.status === 'proposed') assert.equal(a.evidence, null, `${a.id} proposed must have null evidence`);
    else assert.ok(a.evidence && a.evidence.page && a.evidence.quote, `${a.id} on_site needs evidence`);
  }
});

test('page_url resolves to a file in the repo', () => {
  for (const a of autos) {
    assert.match(a.page_url, /^https:\/\/voxdonna\.com\/[A-Za-z0-9/_-]+\.html$/, a.id);
    const rel = a.page_url.replace('https://voxdonna.com/', '');
    assert.ok(existsSync(join(repo, rel)), `${a.id}: missing ${rel}`);
  }
  for (const i of lib.industries) assert.ok(existsSync(join(repo, i.page_url.replace('https://voxdonna.com/', ''))), `${i.id} page_url`);
});

test('on_site quotes appear verbatim in their evidence page (and are short)', () => {
  const cache = new Map();
  let checked = 0;
  for (const a of autos.filter((x) => x.status === 'on_site')) {
    assert.ok(existsSync(join(repo, a.evidence.page)), `${a.id}: evidence page ${a.evidence.page}`);
    if (!cache.has(a.evidence.page)) cache.set(a.evidence.page, pageText(a.evidence.page));
    const q = norm(a.evidence.quote);
    assert.ok(words(q) <= 30, `${a.id} quote ${words(q)} words`);
    assert.ok(cache.get(a.evidence.page).includes(q), `${a.id}: quote not found in ${a.evidence.page}: "${q}"`);
    checked += 1;
  }
  assert.ok(checked > 0);
});

test('no digits in text fields (quotes excepted)', () => {
  for (const i of lib.industries) {
    for (const s of [i.name, ...i.pains.map((p) => p.label)]) assert.doesNotMatch(s, /\d/, `${i.id}: ${s}`);
  }
  for (const a of autos) for (const s of textOf(a)) assert.doesNotMatch(s, /\d/, `${a.id}: ${s}`);
});

test('no banned words, vendor names, links, emojis or em dashes', () => {
  const strings = [];
  for (const i of lib.industries) strings.push(i.name, ...i.pains.map((p) => p.label));
  for (const a of autos) strings.push(...textOf(a), a.evidence?.quote ?? '');
  assert.ok(strings.length > 100);
  for (const s of strings) {
    assert.doesNotMatch(s, wordRe(BANNED), `banned word: ${s}`);
    assert.doesNotMatch(s, wordRe(VENDORS), `vendor name: ${s}`);
    assert.doesNotMatch(s, /\p{Extended_Pictographic}|—/u, `emoji or em dash: ${s}`);
  }
  for (const a of autos) for (const s of textOf(a)) assert.doesNotMatch(s, /https?:|www\.|@/i, `link: ${s}`);
});
