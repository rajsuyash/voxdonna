// Run with a local server: node scripts/test-whatsapp-landing.mjs [Playwright module] [base URL]
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';

const { chromium } = await import(process.argv[2] || 'playwright');
const base = process.argv[3] || 'http://127.0.0.1:8765';
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ reducedMotion: 'reduce' });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/connect.facebook.net/**', route => route.fulfill({ body: '' }));
  await mkdir('/tmp/whatsapp-landing-check', { recursive: true });
  for (const width of [1440, 1024, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    const response = await page.goto(`${base}/whatsapp-donna-agents.html`);
    assert.equal(response.status(), 200);
    await page.evaluate(() => document.fonts.ready);
    assert.equal(await page.locator('h1').count(), 1);
    assert.equal(await page.locator('main').count(), 1);
    assert.equal(await page.locator('.price-card').count(), 4);
    assert.ok(await page.locator('.chat-window').isVisible());
    assert.deepEqual(await page.evaluate(() => [...document.querySelectorAll('main *')].filter(el => {
      const r = el.getBoundingClientRect();
      return r.width > 0 && (r.right > innerWidth + 1 || r.left < -1);
    }).map(el => el.className || el.tagName)), [], `Overflow at ${width}px`);
    assert.equal(await page.locator('.mobile-action').isVisible(), width <= 560);
    if (width <= 560) {
      const bar = await page.locator('.mobile-action').boundingBox();
      const chat = await page.locator('.wa-float').boundingBox();
      assert.ok(chat.y + chat.height <= bar.y, 'WhatsApp and mobile CTA overlap');
    }
    await page.locator('.hero-actions .btn-primary').click();
    assert.equal(new URL(page.url()).hash, '#pricing');
    const pricing = await page.locator('#pricing').boundingBox();
    const nav = await page.locator('nav').boundingBox();
    assert.ok(pricing.y >= nav.height && pricing.y < 150, 'Pricing anchor hidden by navigation');
    const faq = page.locator('.faq-list details').nth(1);
    await faq.locator('summary').focus();
    await page.keyboard.press('Enter');
    assert.ok(await faq.evaluate(el => el.open));
    await page.keyboard.press('Enter');
    assert.equal(await faq.evaluate(el => el.open), false);
    await page.evaluate(() => scrollTo(0, 0));
    await page.screenshot({ path: `/tmp/whatsapp-landing-check/${width}.png`, fullPage: true });
    console.log(`PASS ${width}px: layout, pricing anchor, keyboard FAQ, mobile CTA`);
  }
  assert.deepEqual(await page.evaluate(() => {
    const schema = [...document.querySelectorAll('script[type="application/ld+json"]')]
      .map(el => JSON.parse(el.textContent)).find(item => item['@type'] === 'FAQPage');
    return schema.mainEntity.map(item => [item.name, item.acceptedAnswer.text]);
  }), await page.locator('.faq-list details').evaluateAll(items => items.map(el => [
    el.querySelector('summary').textContent, el.querySelector('p').textContent
  ])));
  assert.deepEqual(await page.locator('a[href^="#"]').evaluateAll(links => links
    .map(a => a.getAttribute('href')).filter(href => href.length > 1 && !document.getElementById(href.slice(1)))), []);
  await page.setViewportSize({ width: 1440, height: 900 });
  for (const [tier, plan] of ['Starter', 'Plus', 'Growth', 'Max'].entries()) {
    await page.goto(`${base}/whatsapp-donna-agents.html`);
    const cta = page.getByRole('link', { name: `Choose ${plan}` });
    const card = page.locator('.price-card').nth(tier);
    assert.match(await card.locator('.price-amt').innerText(), new RegExp(`^\\$${[20, 99, 249, 499][tier]}\\b`));
    assert.match(await card.locator('.price-chats').innerText(), new RegExp(`${['40', '320', '1,000', '2,500'][tier]} credits`));
    assert.equal(await card.locator('.plan-features li').count(), 4);
    if (tier === 0) assert.match(await card.innerText(), /Appointment booking starts with Plus/);
    if (tier === 1) {
      assert.match(await card.getAttribute('class'), /featured/);
      assert.match(await card.innerText(), /AI appointment booking/);
    }
    const destination = new URL(await cta.getAttribute('href'));
    assert.equal(destination.origin, 'https://api.voxdonna.com');
    assert.equal(destination.pathname, '/v1/checkout');
    assert.equal(destination.searchParams.get('tierIndex'), String(tier));
    assert.equal(destination.searchParams.get('agencyId'), 'Kgm98tvkO7hNMhJ0xe9Z0d6BAlk1');
    await page.evaluate(() => {
      window.waEvents = [];
      window.fbq = (...args) => window.waEvents.push(args);
      // Keep the test on-page; the live checkout is checked separately without a payment.
      document.addEventListener('click', event => event.preventDefault());
    });
    await cta.locator('span').click();
    assert.deepEqual(await page.evaluate(() => window.waEvents), [[
      'trackCustom', 'WhatsAppDonnaCTA', { action: 'select_plan', location: 'pricing', plan }
    ]]);
  }
  await page.evaluate(() => { delete window.fbq; });
  await page.locator('.hero-actions .btn-primary').click();
  assert.deepEqual(errors, []);
  const noJs = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 390, height: 844 } });
  const fallback = await noJs.newPage();
  await fallback.goto(`${base}/whatsapp-donna-agents.html`);
  await fallback.locator('.hero-actions .btn-primary').click();
  assert.equal(new URL(fallback.url()).hash, '#pricing');
  await fallback.locator('.faq-list summary').nth(1).click();
  assert.ok(await fallback.locator('.faq-list details').nth(1).getAttribute('open') !== null);
  await noJs.close();
  console.log('PASS: FAQ schema, internal anchors, four checkout mappings, CTA tracking, no JavaScript fallback');
} finally {
  await browser.close();
}
