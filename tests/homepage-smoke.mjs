// Regression checks for three homepage defects found 2026-09-17:
//   1. page auto-scrolled away from the top on load (qualify-form goTo(1) called scrollIntoView)
//   2. mobile menu content overflowed the viewport with no way to scroll to the hidden items
//   3. the floating WhatsApp button stacked above the mobile menu and covered it
// Run:  node tests/homepage-smoke.mjs   (serve the site on :8899 first)
// playwright is not a project dependency; resolve it from wherever it is installed
import { createRequire } from 'node:module';
const require_ = createRequire(import.meta.url);
const PW_PATHS = [
  'playwright',
  '/opt/homebrew/lib/node_modules/omniroute/node_modules/playwright',
  process.env.PLAYWRIGHT_PATH,
].filter(Boolean);
let chromium;
for (const p of PW_PATHS) {
  try { ({ chromium } = require_(p)); break; } catch { /* try next */ }
}
if (!chromium) { console.error('playwright not found; set PLAYWRIGHT_PATH'); process.exit(2); }
import assert from 'node:assert/strict';

const URL = process.env.URL || 'http://localhost:8899/index.html';
const fails = [];
const check = (name, fn) => { try { fn(); console.log('  PASS  ' + name); }
  catch (e) { fails.push(name); console.log('  FAIL  ' + name + '\n        ' + e.message); } };

const browser = await chromium.launch();

// ---- 1. desktop + mobile: the page must stay at the top on load
for (const vp of [{ width: 1280, height: 800 }, { width: 390, height: 844 }]) {
  const page = await browser.newPage({ viewport: vp });
  await page.goto(URL, { waitUntil: 'networkidle' });
  await page.waitForTimeout(2500);               // let smooth-scroll + ScrollTrigger refresh settle
  const y = await page.evaluate(() => window.scrollY);
  check(`loads at top @${vp.width}px (scrollY=${y})`, () => assert.ok(y <= 2, `expected scrollY 0, got ${y}`));
  await page.close();
}

// ---- 2 & 3. mobile menu must be fully reachable and on top
const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
await page.goto(URL, { waitUntil: 'networkidle' });
// the .open X relies on the three bars sitting 6px apart (collapsed block margins);
// switching the button to flex silently spreads them and the X stops meeting.
// MUST be measured before opening — once open, the transform moves the bars.
const bars = await page.evaluate(() => {
  const s = [...document.querySelectorAll('#navHamburger span')].map(e => e.getBoundingClientRect());
  return { pitch: Math.round(s[1].top - s[0].top) };
});

await page.click('#navHamburger');
await page.waitForTimeout(500);

const m = await page.evaluate(() => {
  const menu = document.getElementById('mobileMenu');
  const cs = getComputedStyle(menu);
  const wa = document.querySelector('.wa-float');
  const links = [...menu.querySelectorAll('a')];
  const vh = window.innerHeight;
  return {
    open: menu.classList.contains('open'),
    scrollable: ['auto', 'scroll'].includes(cs.overflowY),
    contentH: menu.scrollHeight, clientH: menu.clientHeight,
    unreachable: links.filter(a => { const r = a.getBoundingClientRect(); return r.bottom < 0 || r.top > vh; }).length,
    allScrollable: menu.scrollHeight <= menu.clientHeight || ['auto','scroll'].includes(cs.overflowY),
    menuZ: parseInt(cs.zIndex, 10),
    waZ: wa ? parseInt(getComputedStyle(wa).zIndex, 10) : null,
    shortestLink: Math.min(...links.map(a => Math.round(a.getBoundingClientRect().height))),
    hamburger: (() => { const r = document.getElementById('navHamburger').getBoundingClientRect();
      return { w: Math.round(r.width), h: Math.round(r.height) }; })()
  };
});

check('mobile menu opens', () => assert.ok(m.open));
check(`every menu item reachable (content ${m.contentH}px in ${m.clientH}px, overflowY scrollable=${m.scrollable})`,
  () => assert.ok(m.allScrollable, 'menu content overflows the viewport and cannot be scrolled'));
check(`WhatsApp button sits under the menu (menu z=${m.menuZ}, wa z=${m.waZ})`,
  () => assert.ok(m.waZ < m.menuZ, `wa-float z-index ${m.waZ} covers the menu at ${m.menuZ}`));
check(`menu links are tappable (shortest ${m.shortestLink}px)`,
  () => assert.ok(m.shortestLink >= 40, `shortest link is ${m.shortestLink}px, want >= 40`));
check(`hamburger bars keep 6px pitch so the X closes (got ${bars.pitch}px)`,
  () => assert.equal(bars.pitch, 6));
check(`hamburger is tappable (${m.hamburger.w}x${m.hamburger.h})`,
  () => assert.ok(m.hamburger.w >= 40 && m.hamburger.h >= 40, `hamburger is ${m.hamburger.w}x${m.hamburger.h}, want >= 40x40`));

// the hero headline must never wrap "work" onto its own line (reported 2026-09-17).
// spans are block-level, so wrapping shows as extra HEIGHT, never as extra client rects.
// reuse the page already loaded above: no re-navigation needed, resizing alone
// re-evaluates the clamp, and a same-URL goto on this page hangs.
for (const w of [1920, 1440, 1024, 768, 480, 390, 360, 320]) {
  await page.setViewportSize({ width: w, height: 900 });
  await page.waitForTimeout(250);
  const r = await page.evaluate(() => {
    const h1 = document.querySelector('.hero-h1');
    const lh = parseFloat(getComputedStyle(h1).lineHeight);
    return { fs: Math.round(parseFloat(getComputedStyle(h1).fontSize)),
             lines: [...h1.querySelectorAll('.line')].map(s => Math.round(s.offsetHeight / lh)) };
  });
  check(`hero headline is one line per row @${w}px (${r.fs}px, rows=${r.lines})`,
    () => assert.ok(r.lines.every(n => n === 1), `wrapped into rows ${r.lines}`));
}
await page.close();

await browser.close();
console.log(fails.length ? `\n${fails.length} FAILED: ${fails.join(', ')}` : '\nall checks passed');
process.exit(fails.length ? 1 : 0);
