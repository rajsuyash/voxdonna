// Self-check for train/app.js mdToHtml against the real generated modules.
//   node scripts/test-train-render.mjs
// Fails loudly if the renderer regresses on code fences, HTML escaping, or tables.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TRAIN = path.join(ROOT, 'train');

const sandbox = { window: {}, document: { querySelector: () => null, querySelectorAll: () => [] } };
sandbox.self = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(TRAIN, 'app.js'), 'utf8'), sandbox);
const { mdToHtml } = sandbox.window.Train;

// --- unit cases -------------------------------------------------------------

const fenced = mdToHtml('Intro text.\n\n```bash\nnpm install -g @anthropic-ai/claude-code\n```\n\nAfter.');
assert.match(fenced, /<pre><code class="lang-bash">npm install -g @anthropic-ai\/claude-code<\/code><\/pre>/);
assert.ok(!fenced.includes('```'), 'fence markers leaked into output');
assert.ok(!fenced.includes('\u0001'), 'sentinel token leaked into output');

// The guide is full of literal XML-ish tags; they must render as text, not markup.
const xml = mdToHtml('Wrap them in <example> tags like <system>this</system>.');
assert.ok(xml.includes('&lt;example&gt;'), 'literal XML tags were not escaped');
assert.ok(!/<example>/.test(xml), 'literal XML tag survived into the DOM');

const inCode = mdToHtml('Use `<thinking>` blocks.');
assert.ok(inCode.includes('<code>&lt;thinking&gt;</code>'), 'inline code lost escaping');

const table = mdToHtml('| Model | Latency |\n|---|---|\n| Haiku 4.5 | Fastest |');
assert.match(table, /<div class="table-scroll"><table>/);
assert.match(table, /<th>Model<\/th>/);
assert.match(table, /<td>Haiku 4\.5<\/td>/);
assert.ok(!table.includes('<th>Haiku'), 'body row rendered as header');

const heads = [];
mdToHtml('## Big One\n\ntext\n\n### Small One\n\nmore', { headings: heads });
assert.deepEqual(heads.map(h => h.id), ['big-one', 'small-one']);
assert.deepEqual(heads.map(h => h.level), [2, 3]);

const bq = mdToHtml('> Verify against current docs.');
assert.match(bq, /<blockquote>Verify against current docs\.<\/blockquote>/);

assert.match(mdToHtml('- one\n- two'), /<ul><li>one<\/li><li>two<\/li><\/ul>/);
assert.match(mdToHtml('1. first\n2. second'), /<ol><li>first<\/li><li>second<\/li><\/ol>/);
assert.match(mdToHtml('**bold** and *soft*'), /<strong>bold<\/strong> and <em>soft<\/em>/);

// --- every real module ------------------------------------------------------

const manifest = JSON.parse(fs.readFileSync(path.join(TRAIN, 'content/manifest.json'), 'utf8'));
let fences = 0, tables = 0;

for (const mod of manifest.modules) {
  const md = fs.readFileSync(path.join(TRAIN, 'content', mod.file), 'utf8');
  const headings = [];
  const html = mdToHtml(md, { headings });

  assert.ok(html.length > 200, `${mod.id}: rendered suspiciously short`);
  assert.ok(!html.includes('\u0001'), `${mod.id}: sentinel token leaked`);
  assert.ok(!html.includes('```'), `${mod.id}: unconverted code fence`);
  assert.equal(
    (html.match(/<pre>/g) || []).length,
    (html.match(/<\/pre>/g) || []).length,
    `${mod.id}: unbalanced <pre>`
  );
  assert.equal(
    (html.match(/<table>/g) || []).length,
    (html.match(/<\/table>/g) || []).length,
    `${mod.id}: unbalanced <table>`
  );
  assert.ok(!/<p>\s*<pre>/.test(html), `${mod.id}: <pre> wrapped in <p>`);
  assert.equal(new Set(headings.map(h => h.id)).size, headings.length,
    `${mod.id}: duplicate heading ids would break the ToC`);

  fences += (html.match(/<pre>/g) || []).length;
  tables += (html.match(/<table>/g) || []).length;
}

// --- quiz integrity ---------------------------------------------------------

const quiz = JSON.parse(fs.readFileSync(path.join(TRAIN, 'content/quiz.json'), 'utf8'));
assert.equal(quiz.questions.length, 100);
for (const q of quiz.questions) {
  assert.equal(q.options.length, 4, `Q${q.n}: not 4 options`);
  assert.ok('ABCD'.includes(q.correct), `Q${q.n}: bad answer letter`);
  assert.ok(q.options.every(o => o.text.trim()), `Q${q.n}: empty option text`);
  assert.ok(q.why && q.why.length > 5, `Q${q.n}: missing rationale`);
}
assert.equal(quiz.sections.length, 10);
assert.equal(quiz.sections.reduce((a, s) => a + s.count, 0), 100);

console.log(
  `ok — ${manifest.modules.length} modules rendered (${fences} code blocks, ${tables} tables), ` +
  `${quiz.questions.length} questions valid`
);
