// Hero ambience checks (mesh gradient, magnetic CTA), added 2026-09-17.
// Separate from homepage-smoke.mjs: these need their own fresh browser, and
// opening a second page inside that suite hangs on navigation.
// Run:  node tests/hero-ambience.mjs     (serve the site first)
import { createRequire } from 'node:module';
const require_ = createRequire(import.meta.url);
let chromium;
for (const p of ['playwright', '/opt/homebrew/lib/node_modules/omniroute/node_modules/playwright', process.env.PLAYWRIGHT_PATH].filter(Boolean)) {
  try { ({ chromium } = require_(p)); break; } catch { /* next */ }
}
if (!chromium) { console.error('playwright not found; set PLAYWRIGHT_PATH'); process.exit(2); }
import assert from 'node:assert/strict';

const URL = process.env.URL || 'http://localhost:8899/index.html';
const fails = [];
const check = (n, fn) => { try { fn(); console.log('  PASS  ' + n); }
  catch (e) { fails.push(n); console.log('  FAIL  ' + n + '\n        ' + e.message); } };

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 820 } });
await page.goto(URL, { waitUntil: 'networkidle' });
await page.waitForTimeout(900);

// a canvas that paints once but never advances is pixel-identical in a screenshot,
// so assert the pixels actually CHANGE over time
const sample = () => page.evaluate(() => {
  const c = document.getElementById('heroMesh');
  if (!c) return null;
  const d = c.getContext('2d').getImageData(Math.floor(c.width * 0.4), Math.floor(c.height * 0.4), 8, 8).data;
  let s = 0; for (let i = 0; i < d.length; i++) s += d[i];
  return s;
});
const a = await sample();
await page.waitForTimeout(2200);
const b = await sample();
check('hero mesh canvas paints', () => assert.ok(a !== null && a > 0, 'canvas blank or missing'));
check('hero mesh canvas animates', () => assert.ok(a !== b, 'canvas painted once but never advanced'));

const cta = await page.$('.hero-cta .btn-primary');
const box = await cta.boundingBox();
await page.mouse.move(box.x + box.width * 0.95, box.y + box.height / 2);
await page.waitForTimeout(250);
const tf = await page.evaluate(() => document.querySelector('.hero-cta .btn-primary').style.transform);
const pull = Math.abs(parseFloat((tf.match(/translate\(([-\d.]+)px/) || [0, '0'])[1]));
check(`magnetic CTA pull stays capped (${pull}px)`, () => assert.ok(pull > 0 && pull <= 10.5, `pull ${pull}px, want 0 < x <= 10`));
await page.mouse.move(box.x - 300, box.y - 300);
await page.waitForTimeout(500);
const rest = await page.evaluate(() => document.querySelector('.hero-cta .btn-primary').style.transform);
check('magnetic CTA returns to rest', () => assert.match(rest, /translate\(0px,\s*0px\)/));
await page.close();

// NOTE: reduced-motion behaviour (mesh paints one static frame, no rAF loop) was
// verified manually on 2026-09-17. It is not asserted here because opening a second
// browser context in this harness hangs on navigation.

await browser.close();
console.log(fails.length ? `\n${fails.length} FAILED: ${fails.join(', ')}` : '\nall checks passed');
process.exit(fails.length ? 1 : 0);
