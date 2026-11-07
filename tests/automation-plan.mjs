// Automation Plan Generator (Phase 2) end-to-end check.
// Run:  URL=http://127.0.0.1:3511 SHOTS=/path/to/shots node tests/automation-plan.mjs
// Serve the worktree root first (php -S so /oracle-lead.php exists). The lead POST is intercepted; nothing is sent.
import { createRequire } from 'node:module';
import { readFileSync, mkdirSync } from 'node:fs';
import assert from 'node:assert/strict';
const require_ = createRequire(import.meta.url);
let chromium;
for (const p of ['playwright', '/opt/homebrew/lib/node_modules/omniroute/node_modules/playwright', process.env.PLAYWRIGHT_PATH].filter(Boolean)) {
  try { ({ chromium } = require_(p)); break; } catch { /* next */ }
}
if (!chromium) { console.error('playwright not found; set PLAYWRIGHT_PATH'); process.exit(2); }

const BASE = process.env.URL || 'http://127.0.0.1:3511';
const SHOTS = process.env.SHOTS || '/tmp/automation-plan-shots';
mkdirSync(SHOTS, { recursive: true });
const DATA = JSON.parse(readFileSync(new URL('../assets/automation-plan/industries.json', import.meta.url))).industries;
const byId = (id) => DATA.find((i) => i.id === id);

// Independent restatement of the spec: score + 25 per matched pain + 5 if volume >= 500 and voice/whatsapp.
function expectedTop(industryId, pains, volume) {
  const ind = byId(industryId);
  const high = volume === '500-2000' || volume === '2000-plus';
  return ind.automations
    .map((a, i) => ({ a, i, t: a.score + 25 * a.pains.filter((p) => pains.includes(p)).length
      + (high && a.channels.some((c) => c === 'voice' || c === 'whatsapp') ? 5 : 0) }))
    .sort((x, y) => y.t - x.t || y.a.score - x.a.score || x.i - y.i)
    .slice(0, 3).map((r) => r.a.id);
}

const fails = [];
const check = async (name, fn) => {
  try { await fn(); console.log('  PASS  ' + name); }
  catch (e) { fails.push(name); console.log('  FAIL  ' + name + '\n        ' + e.message.split('\n').slice(0, 6).join('\n        ')); }
};

// CHROMIUM_PATH: use when the installed playwright wants a browser build that is not downloaded
const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const leadPosts = [];

async function newPage(vp) {
  const ctx = await browser.newContext({ viewport: vp });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
  page.on('console', (m) => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) errors.push('console: ' + m.text()); });
  await page.route('**/*', (route) => {
    const u = new URL(route.request().url());
    if (u.pathname === '/oracle-lead.php') {
      leadPosts.push(JSON.parse(route.request().postData() || '{}'));
      return route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
    }
    if (u.origin !== BASE) return route.abort();
    return route.continue();
  });
  return { page, errors };
}

async function assertResults(page, expected, label) {
  await page.waitForSelector('#ap-top .ap-result');
  const ids = await page.$$eval('#ap-top .ap-result', (n) => n.map((x) => x.dataset.automation));
  assert.deepEqual(ids, expected, label + ': top-3 order');
  assert.equal(ids.length, 3);
  const bad = await page.$$eval('#ap-top .ap-result', (n) => n.filter((x) => !x.querySelector('.ap-first') || !x.querySelector('.ap-why')).length);
  assert.equal(bad, 0, 'each top card has first step and why-line');
}
const noOverflow = async (page, label) => {
  const m = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: innerWidth }));
  assert.ok(m.sw <= m.iw, `${label}: horizontal overflow ${m.sw} > ${m.iw}`);
};

for (const vp of [{ width: 390, height: 844 }, { width: 1440, height: 900 }]) {
  const tag = vp.width;

  // (a) featured industry, walked through the visible UI, then the lead form
  await check(`jewellery-retail walk @${tag}`, async () => {
    const { page, errors } = await newPage(vp);
    await page.goto(BASE + '/automation-plan.html');
    await page.waitForSelector('[data-industry="jewellery-retail"]');
    assert.equal(await page.locator('h1').count(), 1);
    // viewport (not full-page) shot at scroll top: the site nav must sit above the hero, not over it
    await page.screenshot({ path: `${SHOTS}/top-${tag}.png` });
    const gap = await page.evaluate(() => ({ nav: document.querySelector('.vd-nav').getBoundingClientRect().bottom, eyebrow: document.querySelector('.ap-eyebrow').getBoundingClientRect().top, y: scrollY }));
    assert.equal(gap.y, 0);
    assert.ok(gap.eyebrow >= gap.nav, `nav overlaps hero: nav bottom ${gap.nav}, eyebrow top ${gap.eyebrow}`);
    await page.click('[data-industry="jewellery-retail"]');
    await page.click('[data-pain="cold-bridal"]');
    await page.click('[data-pain="missed-calls"]');
    await page.click('[data-volume="500-2000"]');
    await assertResults(page, expectedTop('jewellery-retail', ['cold-bridal', 'missed-calls'], '500-2000'), 'a');
    assert.ok(/industry=jewellery-retail/.test(page.url()) && /volume=500-2000/.test(page.url()), 'url updated: ' + page.url());
    await noOverflow(page, 'a results');
    await page.screenshot({ path: `${SHOTS}/a-jewellery-${tag}.png`, fullPage: true });
    // lead form
    leadPosts.length = 0;
    await page.fill('#ap-name', 'Test Person');
    await page.fill('#ap-email', 'test@example.com');
    // website is required: missing and malformed are blocked client-side, nothing is posted
    await page.click('#ap-form button[type=submit]');
    await page.waitForSelector('.ap-msg.ap-bad');
    for (const bad of ['', 'not a domain', 'acme', 'http://']) {
      await page.fill('#ap-website', bad);
      await page.click('#ap-form button[type=submit]');
      assert.equal(await page.locator('.ap-msg.ap-bad').count(), 1, `blocked: "${bad}"`);
      assert.equal(leadPosts.length, 0, `posted despite website "${bad}"`);
    }
    // bare domain accepted, company name left empty (optional)
    await page.fill('#ap-website', 'acme.com');
    assert.equal(await page.inputValue('#ap-company'), '');
    await page.click('#ap-form button[type=submit]');
    await page.waitForSelector('.ap-msg.ap-ok');
    assert.equal(leadPosts.length, 1);
    assert.equal(leadPosts[0].lead.company, '');
    assert.equal(leadPosts[0].lead.website, 'acme.com');
    assert.match(await page.textContent('#ap-cta-h'), /turned into a plan/);
    const b = leadPosts[0];
    assert.deepEqual(b.next, ['plan']); assert.equal(b.hp, '');
    assert.equal(b.lead.industry, 'Jewellery Retail & Wholesale');
    assert.match(b.lead.volume, /500 to 2,000 calls/);
    assert.match(b.lead.problem, /Bridal leads go cold/);
    assert.deepEqual(Object.keys(b.lead).sort(), ['company', 'email', 'industry', 'name', 'problem', 'volume', 'website']);
    assert.deepEqual(errors, []);
    await page.close();
  });

  // (b) non-featured industry via search, "Not sure"
  await check(`dental-practices via search @${tag}`, async () => {
    const { page, errors } = await newPage(vp);
    await page.goto(BASE + '/automation-plan.html');
    await page.click('#ap-other > summary');
    await page.fill('#ap-search', 'dental');
    await page.click('[data-industry="dental-practices"]');
    await page.click('[data-pain="not-sure"]');
    await page.click('[data-volume="100-500"]');
    await assertResults(page, expectedTop('dental-practices', [], '100-500'), 'b');
    await noOverflow(page, 'b results');
    await page.screenshot({ path: `${SHOTS}/b-dental-${tag}.png`, fullPage: true });
    assert.deepEqual(errors, []);
    await page.close();
  });

  // (c) deep link straight to results
  await check(`real-estate deep link @${tag}`, async () => {
    const { page, errors } = await newPage(vp);
    const pains = ['slow-response', 'quiet-leads'];
    await page.goto(`${BASE}/automation-plan.html?industry=real-estate&pains=${pains.join(',')}&volume=500-2000`);
    await assertResults(page, expectedTop('real-estate', pains, '500-2000'), 'c');
    await noOverflow(page, 'c results');
    await page.screenshot({ path: `${SHOTS}/c-realestate-${tag}.png`, fullPage: true });
    // partial deep link stops at the furthest complete step
    // the link Donna builds: industry + volume, no pains -> lands on the pains step with volume already chosen
    await page.goto(`${BASE}/automation-plan.html?industry=jewellery-retail&volume=500-2000`);
    await page.waitForSelector('#ap-s-pains:not([hidden])');
    assert.equal(await page.locator('#ap-s-results').isHidden(), true);
    await page.click('[data-pain="missed-calls"]');
    await page.waitForSelector('#ap-s-size:not([hidden])');
    assert.equal(await page.getAttribute('[data-volume="500-2000"]', 'aria-pressed'), 'true');
    await page.goto(`${BASE}/automation-plan.html?industry=real-estate`);
    await page.waitForSelector('#ap-s-pains:not([hidden])');
    assert.equal(await page.locator('#ap-s-size').isHidden(), true);
    assert.equal(await page.locator('#ap-s-results').isHidden(), true);
    assert.deepEqual(errors, []);
    await page.close();
  });
}

await browser.close();
console.log(fails.length ? `\n${fails.length} FAILED` : '\nall passed');
process.exit(fails.length ? 1 : 0);
