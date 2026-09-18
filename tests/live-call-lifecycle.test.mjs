/*
 * The homepage call widget, exercised against a fake SDK.
 *
 * Regression under test: startSession resolves seconds after the click, and the
 * conversation handle used to be captured only in .then(). Anything happening in
 * that window saw null — so End Call skipped endSession() and reset the UI, and the
 * call then went live with no way to stop it.
 *
 *   node tests/live-call-lifecycle.test.mjs
 */
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const ROOT = path.resolve(import.meta.dirname, '..');
const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');

// pull the widget's module body straight out of the page, so the test can never
// drift from the shipped code
const m = html.match(/<script type="module">\s*import \{ Conversation \} from '\/lib\/voice-sdk\.js';([\s\S]*?)<\/script>/);
assert.ok(m, 'could not find the live-call module in index.html');
const body = m[1];

function run({ endDuringConnect = false, doubleStart = false, connectMs = 20 } = {}) {
  const calls = { start: 0, end: 0 };
  let classes = new Set();
  const el = {
    className: '', classList: {
      toggle: (c, on) => { on ? classes.add(c) : classes.delete(c); },
      add: c => classes.add(c), remove: c => classes.delete(c),
    },
    addEventListener() {},
  };
  const Conversation = {
    startSession() {
      calls.start++;
      return new Promise(res => setTimeout(() => res({ endSession() { calls.end++; } }), connectMs));
    },
  };
  const ctx = {
    Conversation, console: { log() {}, warn() {}, error() {} },
    alert() {}, setTimeout, Promise,
    document: { querySelector: () => el, getElementById: () => el },
    window: { addEventListener() {} },
  };
  ctx.window.__donna = undefined;
  vm.createContext(ctx);
  vm.runInContext(body, ctx);
  const donna = ctx.window.__donna;

  donna.start();
  if (doubleStart) donna.start();
  if (endDuringConnect) donna.end();
  return new Promise(res => setTimeout(() => res({ calls, classes, donna }), connectMs + 40));
}

let failed = 0;
const check = (name, cond, extra = '') => {
  if (cond) { console.log(`  PASS  ${name}`); }
  else { console.log(`  FAIL  ${name} ${extra}`); failed++; }
};

// 1. the regression itself
const a = await run({ endDuringConnect: true });
check('End pressed while connecting still hangs the session up', a.calls.end === 1,
      `(endSession called ${a.calls.end}x)`);
check('…and the widget is left idle, not stuck mid-call', !a.classes.has('is-active'));
check('…with no dangling handle', a.donna.session === null && a.donna.starting === false);

// 2. a second click during the connect window must not open a second session
const b = await run({ doubleStart: true });
check('Clicking start twice while connecting opens one session', b.calls.start === 1,
      `(startSession called ${b.calls.start}x)`);

// 3. the ordinary path still works
const c = await run();
check('A normal call goes active', c.classes.has('is-active'));
c.donna.end();
check('…and End after connect hangs it up', c.calls.end === 1);
check('…leaving the widget idle', !c.classes.has('is-active') && c.donna.session === null);

console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed');
process.exit(failed ? 1 : 0);
