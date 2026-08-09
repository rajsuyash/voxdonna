/*
 * Self-check for the Kisna Partner Desk demo.
 *   node demo/kisna-partner-whatsapp/test/selfcheck.mjs
 *
 * A scripted node-graph fails silently: a chip points at a node that was renamed,
 * a scenario cites a SKU code that was edited, a RAG query stops matching and the
 * bot quietly says "let me get a person". None of that throws in the browser.
 * This asserts every reference resolves, and that the ledger numbers add up.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const sandbox = { window: {}, document: undefined };
sandbox.window.matchMedia = () => ({ matches: false });
vm.createContext(sandbox);

for (const f of ['js/data/catalog.js', 'js/data/partners.js', 'js/engine/catalog.js', 'js/engine/rag.js', 'js/data/scenarios.js']) {
  vm.runInContext(readFileSync(join(root, f), 'utf8'), sandbox, { filename: f });
}
const W = sandbox.window;

let failures = 0;
const check = (ok, msg) => { if (!ok) { failures++; console.error('FAIL  ' + msg); } };

// ---- 1. every scenario reference resolves -------------------------------
const RENDERED_BY_ID = new Set(['orderpipe']);
let nodeCount = 0, specCount = 0;

for (const [key, sc] of Object.entries(W.SCENARIOS)) {
  check(sc.nodes[sc.entry], `${key}: entry node "${sc.entry}" does not exist`);
  for (const [nk, node] of Object.entries(sc.nodes)) {
    nodeCount++;
    (node.choices || []).forEach(c => {
      const target = c.goto;
      if (typeof target === 'string' && target.startsWith('__')) {
        check(W.SCENARIOS[target.slice(2)], `${key}.${nk}: chip "${c.label}" jumps to unknown scenario "${target}"`);
      } else if (target && target !== 'END') {
        check(sc.nodes[target], `${key}.${nk}: chip "${c.label}" points at missing node "${target}"`);
      }
    });
    (node.bot || []).forEach(spec => {
      specCount++;
      if (spec.t === 'skus') spec.codes.forEach(c => check(W.SKU_BY_CODE[c], `${key}.${nk}: unknown SKU code ${c}`));
      if (spec.t === 'cart') spec.lines.forEach(l => check(W.SKU_BY_CODE[l.code], `${key}.${nk}: cart line references unknown SKU ${l.code}`));
      if (RENDERED_BY_ID.has(spec.t)) check(W.ORDER_BY_ID[spec.id], `${key}.${nk}: unknown order ${spec.id}`);
      if (spec.t === 'scheme' || spec.t === 'schemeterms') check(W.SCHEMES.some(s => s.id === spec.id), `${key}.${nk}: unknown scheme ${spec.id}`);
      if (spec.t === 'drop') check(W.DESIGN_DROPS.some(d => d.id === spec.id), `${key}.${nk}: unknown design drop ${spec.id}`);
      if (spec.t === 'rag') check(W.RAG.answer(spec.q), `${key}.${nk}: RAG query "${spec.q}" retrieves nothing — the bot would deflect to a human`);
      if (spec.t === 'reco') {
        const hits = W.CatalogEngine.recommend(spec.query, spec.n || 3);
        check(hits.length > 0, `${key}.${nk}: reco query returns an empty carousel`);
      }
    });
  }
}
check(W.SCENARIO_ORDER.length === Object.keys(W.SCENARIOS).length, 'SCENARIO_ORDER does not list every scenario');
W.SCENARIO_ORDER.forEach(k => check(W.SCENARIOS[k], `SCENARIO_ORDER lists unknown scenario "${k}"`));

// ---- 2. ledger arithmetic ------------------------------------------------
const p = W.PARTNER;
const aged = p.ageing.reduce((t, a) => t + a.amount, 0);
check(aged === p.outstanding, `ageing buckets sum to ${aged}, outstanding is ${p.outstanding}`);
check(p.creditLimit - p.outstanding === p.available, `available should be ${p.creditLimit - p.outstanding}, is ${p.available}`);
W.ORDERS.forEach(o => check(o.stage >= 0 && o.stage < W.ORDER_STAGES.length, `${o.id}: stage index ${o.stage} out of range`));

// ---- 3. catalogue integrity ---------------------------------------------
W.SKUS.forEach(s => {
  check(s.mrp > s.wsp, `${s.code}: MRP must exceed wholesale price`);
  check(s.moq >= 1, `${s.code}: MOQ must be at least 1`);
  check(['ready', 'make-to-order'].includes(s.stock), `${s.code}: unknown stock state "${s.stock}"`);
  check(!!W.kisnaSVG(s.icon), `${s.code}: icon "${s.icon}" renders nothing`);
});
check(new Set(W.SKUS.map(s => s.code)).size === W.SKUS.length, 'duplicate SKU codes in the catalogue');

// ---- 4. every message type has a renderer --------------------------------
// app.js needs a DOM, so this reads it as text: RENDER falls back to text() for an
// unknown `t`, which renders an empty bubble rather than throwing.
const appSrc = readFileSync(join(root, 'js/app.js'), 'utf8');
const renderBlock = appSrc.slice(appSrc.indexOf('const RENDER = {'), appSrc.indexOf('function renderVoice'));
const renderers = new Set([...renderBlock.matchAll(/\n {4}([a-zA-Z]+)\s*\(/g)].map(m => m[1]));
check(renderers.size > 5, 'could not parse the RENDER map out of app.js — this check needs updating');
const usedTypes = new Set();
Object.values(W.SCENARIOS).forEach(sc => Object.values(sc.nodes).forEach(n => (n.bot || []).forEach(s => usedTypes.add(s.t))));
usedTypes.forEach(t => check(renderers.has(t), `message type "${t}" is used in a scenario but has no renderer in app.js`));

// ---- 5. order maths ------------------------------------------------------
const order = W.CatalogEngine.buildOrder([{ code:'KSN-ER-1042', qty:10 }, { code:'KSN-NP-1150', qty:20 }]);
check(order.pcs === 30, `buildOrder piece count is ${order.pcs}, expected 30`);
check(order.subtotal === 14200 * 10 + 7400 * 20, `buildOrder subtotal is ${order.subtotal}`);
check(order.total === order.subtotal + order.gst, 'buildOrder total does not equal subtotal + GST');
check(W.CatalogEngine.sellThrough(order).profit > 0, 'sell-through profit should be positive');

console.log(`${nodeCount} nodes · ${specCount} message specs · ${W.SKUS.length} SKUs · ${W.RAG.KB.length} KB docs checked`);
if (failures) { console.error(`\n${failures} check(s) failed.`); process.exit(1); }
console.log('All checks passed.');
