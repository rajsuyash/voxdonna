// Self-check for train/app.js mdToHtml against the real generated modules.
//   node scripts/test-train-render.mjs
// Fails loudly if the renderer regresses on code fences, HTML escaping, or tables.

import assert from 'node:assert/strict';
const chr1 = String.fromCharCode(1);
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
const sb = sandbox;
const { mdToHtml } = sandbox.window.Train;

// --- unit cases -------------------------------------------------------------

const fenced = mdToHtml('Intro text.\n\n```bash\nnpm install -g @anthropic-ai/claude-code\n```\n\nAfter.');
assert.match(fenced, /<figure class="code">.*install -g @anthropic-ai\/claude-code.*<\/figure>/s);
assert.match(fenced, /<span class="t-k">npm<\/span>/, 'bash keyword not highlighted');
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

// --- unit cases: the lesson-era additions --------------------------------

const cal = mdToHtml(':::exercise Try it #3\nDo the **thing**.\n\n- one\n- two\n:::');
assert.match(cal, /<aside class="cal cal-exercise">/);
assert.match(cal, /<div class="cal-h">Try it #3<\/div>/);
assert.match(cal, /<strong>thing<\/strong>/, 'callout body lost markdown rendering');
assert.match(cal, /<ul><li>one<\/li>/, 'callout body lost list rendering');
assert.ok(!cal.includes(':::'), 'callout fence markers leaked');

const bar = mdToHtml('```bash\ncurl -fsSL https://example.com | bash\n```');
assert.match(bar, /<figure class="code">/);
assert.match(bar, /<button type="button" class="code-copy" data-copy>Copy<\/button>/);
assert.match(bar, /<span class="t-k">curl<\/span>/, 'bash keyword not highlighted');

const py = mdToHtml('```python\n# note\nx = "s"\n```');
assert.match(py, /<span class="t-c"># note<\/span>/);
assert.match(py, /<span class="t-s">"s"<\/span>/);

// Bare fences are the guide's ASCII diagrams — they must not be tokenised.
const ascii = mdToHtml('```\n+---+\n| a |\n+---+\n```');
assert.ok(!/class="t-[cskn]"/.test(ascii), 'bare fence was syntax-highlighted');
assert.match(ascii, /<figure class="code">/);

const cited = mdToHtml('Adaptive thinking is on by default (Anthropic Docs, Jul 2026).');
assert.match(cited, /<span class="cite">Anthropic Docs, Jul 2026<\/span>/);

const flagged = mdToHtml('reads 0.1x \u26a0 as of Aug 2026');
assert.match(flagged, /<span class="flag"[^>]*>\u26a0<\/span>/);

// --- every generated lesson ------------------------------------------------

const manifest = JSON.parse(fs.readFileSync(path.join(TRAIN, 'content/manifest.json'), 'utf8'));
let fences = 0, tables = 0, callouts = 0, lessons = 0;

for (const mod of manifest.modules) {
  assert.ok(mod.lessons.length > 0, `${mod.id}: no lessons`);
  for (const lesson of mod.lessons) {
    lessons++;
    const md = fs.readFileSync(path.join(TRAIN, 'content', lesson.file), 'utf8');
    const headings = [];
    const html = mdToHtml(md, { headings });

    assert.ok(html.length > 120, `${lesson.id}: rendered suspiciously short`);
    assert.ok(!html.includes(chr1), `${lesson.id}: sentinel token leaked`);
    assert.ok(!html.includes('```'), `${lesson.id}: unconverted code fence`);
    assert.ok(!html.includes(':::'), `${lesson.id}: unconverted callout fence`);
    assert.equal((html.match(/<pre>/g) || []).length, (html.match(/<\/pre>/g) || []).length,
      `${lesson.id}: unbalanced <pre>`);
    assert.equal((html.match(/<table>/g) || []).length, (html.match(/<\/table>/g) || []).length,
      `${lesson.id}: unbalanced <table>`);
    assert.equal((html.match(/<aside/g) || []).length, (html.match(/<\/aside>/g) || []).length,
      `${lesson.id}: unbalanced <aside>`);
    assert.equal((html.match(/<figure/g) || []).length, (html.match(/<\/figure>/g) || []).length,
      `${lesson.id}: unbalanced <figure>`);
    assert.ok(!/<p>\s*<pre>/.test(html), `${lesson.id}: <pre> wrapped in <p>`);
    assert.equal(new Set(headings.map(h => h.id)).size, headings.length,
      `${lesson.id}: duplicate heading ids would break the rail`);
    assert.equal((html.match(/data-copy/g) || []).length, (html.match(/<figure class="code">/g) || []).length,
      `${lesson.id}: a code block is missing its copy button`);

    if (!mod.view) {
      assert.ok(lesson.minutes >= 1 && lesson.minutes <= 9, `${lesson.id}: ${lesson.minutes} min out of range`);
    }
    fences += (html.match(/<figure class="code">/g) || []).length;
    tables += (html.match(/<table>/g) || []).length;
    callouts += (html.match(/<aside class="cal/g) || []).length;
  }
}

assert.equal(lessons, manifest.counts.lessons, 'manifest lesson count disagrees with the modules');
assert.equal(callouts, manifest.counts.exercises + manifest.counts.caveats,
  'rendered callouts do not match what the build promoted');

// --- browsers ---------------------------------------------------------------

const prompts = JSON.parse(fs.readFileSync(path.join(TRAIN, 'content/prompts.json'), 'utf8')).prompts;
assert.ok(prompts.length >= 100, `only ${prompts.length} prompts`);
assert.ok(prompts.every(p => p.title && p.body && p.category), 'a prompt is missing title/body/category');

const mistakes = JSON.parse(fs.readFileSync(path.join(TRAIN, 'content/mistakes.json'), 'utf8')).mistakes;
assert.equal(mistakes.length, 100);
assert.ok(mistakes.every(m => m.title && m.fix && m.category), 'a pitfall is missing title/fix/category');

const glossary = JSON.parse(fs.readFileSync(path.join(TRAIN, 'content/glossary.json'), 'utf8'));
assert.ok(glossary.terms.length >= 40 && glossary.faq.length >= 20);
assert.ok(glossary.terms.every(t => t.term && t.def && t.letter), 'a glossary term is malformed');

const sheets = JSON.parse(fs.readFileSync(path.join(TRAIN, 'content/sheets.json'), 'utf8')).sheets;
assert.ok(sheets.length >= 8 && sheets.every(s => s.title && s.body));

// --- spaced repetition ------------------------------------------------------

const { scheduleReview, dueQuestions } = sb.window.Train;
const T0 = 1_700_000_000_000, D = 86_400_000;
const st = { review: {} };

scheduleReview(st, 7, true, manifest, T0);
assert.equal(Object.keys(st.review).length, 0, 'a question never missed should not enter the queue');

scheduleReview(st, 7, false, manifest, T0);
assert.equal(st.review['7'].due, T0 + 1 * D, 'a miss should come back tomorrow');
assert.equal(dueQuestions(st, T0).join(), '', 'not due yet');
assert.equal(dueQuestions(st, T0 + 1 * D).join(), '7', 'should be due after 1 day');

scheduleReview(st, 7, true, manifest, T0 + 1 * D);
assert.equal(st.review['7'].due, T0 + 1 * D + 3 * D, 'correct recall should advance to 3 days');
scheduleReview(st, 7, false, manifest, T0 + 2 * D);
assert.equal(st.review['7'].step, 0, 'a miss should reset the ladder');

let t = T0;
for (const gap of [1, 3, 7, 21]) { t += gap * D; scheduleReview(st, 7, true, manifest, t); }
assert.ok(!('7' in st.review), 'clearing the last interval should retire the question');

// --- quiz integrity ---------------------------------------------------------

const quiz = JSON.parse(fs.readFileSync(path.join(TRAIN, 'content/quiz.json'), 'utf8'));
for (const q of quiz.questions) {
  assert.equal(q.options.length, 4, `Q${q.n}: not 4 options`);
  assert.ok('ABCD'.includes(q.correct), `Q${q.n}: bad answer letter`);
  assert.ok(q.options.every(o => o.text.trim()), `Q${q.n}: empty option text`);
  assert.ok(q.why && q.why.length > 5, `Q${q.n}: missing rationale`);
}

// The exam paper is section 1-10; recall checks sit in section 0 so exam.html,
// which scopes by quiz.sections, can never pull them into a certification run.
const exam = quiz.questions.filter(q => q.section > 0);
const recall = quiz.questions.filter(q => q.section === 0);
assert.equal(exam.length, 100);
assert.ok(recall.every(q => q.n > 100), 'recall numbers must not collide with the exam');
assert.equal(new Set(quiz.questions.map(q => q.n)).size, quiz.questions.length, 'duplicate question numbers');
assert.equal(quiz.sections.length, 10);
assert.equal(quiz.sections.reduce((a, s) => a + s.count, 0), 100);
assert.ok(quiz.sections.every(s => s.n > 0), 'section 0 must stay out of the exam scope list');

const known = new Set(quiz.questions.map(q => q.n));
let withChecks = 0;
for (const m of manifest.modules) {
  for (const l of m.lessons) {
    for (const n of l.questions) assert.ok(known.has(n), `${l.id}: question ${n} not in quiz.json`);
    if (l.questions.length) withChecks++;
  }
}
// Every reading lesson gets a recall check except the quiz appendix itself.
const readingLessons = manifest.modules
  .filter(m => !m.view && m.id !== 'appendix-b')
  .reduce((a, m) => a + m.lessons.length, 0);
assert.equal(withChecks, readingLessons, 'some reading lessons have no recall check');

console.log(
  `ok — ${manifest.modules.length} modules / ${lessons} lessons rendered ` +
  `(${fences} code blocks, ${tables} tables, ${callouts} callouts), ` +
  `${exam.length} exam questions, ${recall.length} recall checks on ${withChecks} lessons, ` +
  `${prompts.length} prompts, ${mistakes.length} pitfalls, ` +
  `${glossary.terms.length} terms, ${sheets.length} sheets, review schedule verified`
);
