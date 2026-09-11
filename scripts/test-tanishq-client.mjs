// Run: node scripts/test-tanishq-client.mjs /path/to/installed/playwright/index.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const { chromium } = await import(process.argv[2] ? pathToFileURL(process.argv[2]).href : 'playwright');
const root = new URL('../demo/tanishq-personal-shopper/', import.meta.url);
const html = await readFile(new URL('index.html', root), 'utf8');
const client = await readFile(new URL('client.js', root), 'utf8');
const browser = await chromium.launch({ headless: true, channel: 'chrome' });
const page = await browser.newPage();
const errors = [];
page.on('pageerror', error => errors.push(error.message));
let bookings = 0;
let extracts = 0;
let releaseOld;
let releaseNew;
let releaseManual;
let sendStatus = 'failed';
await page.route('**/*', async route => {
  const path = new URL(route.request().url()).pathname;
  if (path.endsWith('/client.js')) return route.fulfill({ contentType: 'text/javascript', body: client });
  if (path === '/') return route.fulfill({ contentType: 'text/html', body: html });
  if (path === '/api/config') return route.fulfill({ json: { englishConfigured: true, hindiConfigured: true, bookingConfigured: true, stores: [{ id: 'mum-powai', name: 'Powai', city: 'Mumbai' }] } });
  if (path === '/api/session') return route.fulfill({ json: { provider: 'elevenlabs', url: 'wss://test.invalid/', sampleRate: 16000, maxSeconds: 300, dynamicVariables: { session_facts: 'Today is Friday, 2026-09-11 (India).' } } });
  if (path === '/api/booking/extract') {
    extracts++;
    if (extracts === 1) await new Promise(resolve => { releaseOld = resolve; });
    if (extracts === 2) await new Promise(resolve => { releaseNew = resolve; });
    if (extracts === 3) await new Promise(resolve => { releaseManual = resolve; });
    return route.fulfill({ json: { store_id: 'mum-powai', date: '2026-09-13', time: extracts === 1 ? '14:00' : '16:00', agent_announced_booking: true } });
  }
  if (path === '/api/booking/confirm') {
    bookings++;
    assert.equal(route.request().postDataJSON().time, '16:30');
    return route.fulfill({ json: { appointmentId: 'test-appointment', sentTo: '+919000000000', whatsappStatus: sendStatus } });
  }
  return route.fulfill({ status: 404, body: '' });
});
await page.addInitScript(() => {
  class Node {
    port = {};
    connect() {}
    disconnect() {}
  }
  class Context {
    audioWorklet = { addModule: async () => {} };
    destination = {};
    resume = async () => {};
    close = async () => {};
    createMediaStreamSource = () => new Node();
  }
  Object.defineProperty(window, 'AudioContext', { value: Context });
  Object.defineProperty(window, 'AudioWorkletNode', { value: Node });
  Object.defineProperty(navigator, 'mediaDevices', { value: { getUserMedia: async () => ({ getTracks: () => [{ stop() {} }] }) } });
  Object.defineProperty(window, 'WebSocket', { value: class {
    static OPEN = 1;
    readyState = 1;
    bufferedAmount = 0;
    constructor() {
      window.dispatchEvent(new CustomEvent('test-socket', { detail: this }));
      setTimeout(() => this.onopen(), 0);
    }
    send(data) { document.body.dataset.sent = data; }
    close() {}
  } });
  window.addEventListener('test-socket', event => {
    window.addEventListener('test-caption', caption => event.detail.onmessage({ data: JSON.stringify({ type: 'agent_response', agent_response_event: { agent_response: caption.detail } }) }));
  });
});
const caption = text => page.evaluate(value => window.dispatchEvent(new CustomEvent('test-caption', { detail: value })), text);
const until = async predicate => {
  for (let i = 0; i < 100; i++) { if (predicate()) return; await new Promise(resolve => setTimeout(resolve, 50)); }
  throw new Error('Timed out waiting for test request.');
};
try {
  await page.goto('http://127.0.0.1:4318/');
  assert.equal(await page.locator('#start').isDisabled(), true);
  await page.locator('#name').fill('Demo Test');
  await page.locator('#phone').fill('9000000000');
  await page.locator('#start').click();
  await page.waitForFunction(() => document.querySelector('#status').textContent.includes('Connecting your voice'));
  await page.waitForFunction(() => Boolean(document.body.dataset.sent));
  assert.deepEqual(JSON.parse(await page.locator('body').getAttribute('data-sent')), {
    type: 'conversation_initiation_client_data', dynamic_variables: { session_facts: 'Today is Friday, 2026-09-11 (India).' },
  });
  await caption('Submitting Powai on Sunday at two.');
  await until(() => releaseOld);
  await caption('Correction: Sunday at four.');
  releaseOld();
  await until(() => releaseNew);
  assert.equal(bookings, 0, 'A new caption invalidates the previous extraction before its replacement starts.');
  releaseNew();
  await page.waitForFunction(() => document.querySelector('#booking-time').value === '16:00');
  assert.equal(bookings, 0, 'Agent speech cannot authorize a booking.');
  await caption('Your visit is at four o’clock.');
  await until(() => releaseManual);
  await page.locator('#booking-time').fill('16:30');
  releaseManual();
  await new Promise(resolve => setTimeout(resolve, 200));
  assert.equal(await page.locator('#booking-time').inputValue(), '16:30', 'Late extraction cannot overwrite a manual correction.');
  await page.locator('#confirm').click();
  await page.waitForFunction(() => document.querySelector('#confirm').textContent === 'Retry WhatsApp confirmation');
  assert.equal(bookings, 1);
  assert.match(await page.locator('#booking-status').textContent(), /saved.*failed/i);
  sendStatus = 'queued';
  await page.locator('#confirm').click();
  await page.waitForFunction(() => document.querySelector('#booking-status').textContent.includes('queued'));
  assert.equal(bookings, 2, 'Exactly one manual retry.');
  assert.equal(await page.locator('#confirm').isVisible(), false);
  await caption('Your visit request is submitted.');
  await new Promise(resolve => setTimeout(resolve, 2200));
  assert.equal(extracts, 3, 'No extraction or automatic rebooking after a saved visit.');
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  }
  await page.locator('#stop').click();
  assert.equal(await page.locator('#start').isVisible(), true);
  assert.deepEqual(errors, []);
  console.log('PASS: Hindi facts, stale extraction, manual correction, partial success, manual retry, no automatic resend, desktop/mobile layout and End.');
} finally { await browser.close(); }
