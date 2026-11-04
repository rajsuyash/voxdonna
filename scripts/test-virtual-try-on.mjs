import assert from 'node:assert/strict';
import { mkdtemp, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { chromium, request } from '/Users/suyashraj/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/index.mjs';
const base = process.env.BASE_URL || 'http://127.0.0.1:3499';
const fixture = await mkdtemp(join(tmpdir(), 'vton-endpoint-'));
await copyFile(new URL('../virtual-try-on-token.php', import.meta.url), join(fixture, 'token.php'));
function mintFixture(method = 'POST', origin = 'https://voxdonna.com', upstream = 200) {
  const code = [
    '$_SERVER["REQUEST_METHOD"] = ' + JSON.stringify(method) + ';',
    '$_SERVER["HTTP_ORIGIN"] = ' + JSON.stringify(origin) + ';',
    '$_SERVER["REMOTE_ADDR"] = "test"; putenv("DECART_API_KEY=dct_fixture");',
    'function curl_init($url) { return true; }',
    'function curl_setopt_array($ch,$options) { $GLOBALS["payload"]=json_decode($options[CURLOPT_POSTFIELDS],true); return true; }',
    'function curl_exec($ch) { return json_encode(["apiKey"=>"ek_fixture","expiresAt"=>"2099-01-01"]); }',
    'function curl_getinfo($ch,$key) { return ' + upstream + '; }',
    'register_shutdown_function(function() { fwrite(STDERR,json_encode(["status"=>http_response_code() ?: 200,"payload"=>$GLOBALS["payload"] ?? null])); });',
    'require ' + JSON.stringify(join(fixture, 'token.php')) + ';',
  ].join('\n');
  const result = spawnSync('php', ['-d', 'disable_functions=curl_init,curl_setopt_array,curl_exec,curl_getinfo', '-d', 'error_log=/dev/null', '-r', code], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return { ...JSON.parse(result.stderr), body: JSON.parse(result.stdout) };
}
assert.equal(mintFixture('GET').status, 405);
assert.equal(mintFixture('POST', 'https://attacker.example').status, 403);
assert.equal(mintFixture('POST', 'https://voxdonna.com', 401).status, 502);
const minted = mintFixture();
assert.equal(minted.status, 200);
assert.deepEqual(minted.payload.allowedModels, ['lucy-vton-latest', 'lucy-vton-3.6']);
assert.deepEqual(minted.payload.allowedOrigins, ['https://voxdonna.com']);
assert.equal(minted.payload.expiresIn, 60);
assert.equal(minted.payload.constraints.realtime.maxSessionDuration, 120);
assert.equal(minted.body.apiKey, 'ek_fixture');
for (let i = 0; i < 4; i++) assert.equal(mintFixture().status, 200);
assert.equal(mintFixture().status, 429);
console.log('PASS: isolated PHP token scopes, TTL, session cap, upstream failure, rate limiter.');
const browser = await chromium.launch({ channel: 'chrome', headless: true, args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream'] });
const mockSDK = [
  'export const models = { realtime: () => ({width:640,height:480,fps:{ideal:30,max:30}}) };',
  'export function createDecartClient(options) { return { realtime: { connect: async (stream, settings) => {',
  'window.testStream = stream; window.initialState = settings.initialState;',
  'await options.apiKeyProvider();',
  'if (window.delayConnect) await new Promise(resolve => { window.finishConnect = resolve; });',
  'settings.onRemoteStream(stream.clone());',
  'return { on: () => {}, disconnect: () => { window.disconnected = true; }, set: async state => {',
  'window.applied = {prompt:state.prompt, image:state.image?.name, enhance:state.enhance};',
  'if (window.failApply) throw new Error("apply failed");',
  '} }; } } }; }',
].join('\n');
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  let tokens = 0;
  await page.route('https://esm.sh/**', route => route.fulfill({ contentType: 'application/javascript', body: mockSDK }));
  await page.route('**/virtual-try-on-token.php', route => { tokens++; return route.fulfill({ json: { apiKey: 'ek_test_only', expiresAt: '2099-01-01' } }); });
  await page.goto(base + '/demo/virtual-try-on.html');
  assert.equal(tokens, 0, 'no tokens on page load');
  assert(await page.locator('#start').isDisabled());
  for (const width of [1440, 390, 320]) {
    const visual = await browser.newPage({ viewport: { width, height: 1100 } });
    await visual.goto(base + '/demo/virtual-try-on.html');
    await visual.evaluate(() => document.fonts.ready);
    assert(await visual.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'overflow at ' + width);
    await visual.screenshot({ path: '/private/tmp/vton-' + width + '.png', fullPage: width === 1440 });
    await visual.close();
  }
  await page.setViewportSize({ width: 1440, height: 1100 });
  await page.locator('#consent').check();
  await page.locator('#start').click();
  await page.waitForFunction(() => !document.querySelector('#apply').disabled);
  assert.equal(tokens, 1);
  assert.equal(await page.evaluate(() => window.testStream.getAudioTracks().length), 0);
  await page.locator('[data-look="1"]').click();
  await page.locator('#apply').click();
  await page.waitForFunction(() => window.applied?.prompt.includes('red leather'));
  const png = await page.evaluate(() => { const c = document.createElement('canvas'); c.width=512; c.height=512; c.getContext('2d').fillRect(0,0,512,512); return c.toDataURL().split(',')[1]; });
  await page.locator('#garment').setInputFiles({ name: 'garment.png', mimeType: 'image/png', buffer: Buffer.from(png, 'base64') });
  await page.waitForFunction(() => !document.querySelector('#reference-preview').hidden);
  assert.equal(await page.locator('#prompt').inputValue(), '');
  await page.locator('#prompt').fill('Substitute the current top with a black cotton shirt.');
  await page.locator('#apply').click();
  await page.waitForFunction(() => window.applied?.image === 'garment.png');
  await page.locator('#prompt').fill('Substitute the current top with a black cotton shirt with a relaxed fit.');
  await page.locator('#apply').click();
  assert.equal(await page.evaluate(() => window.applied.image), 'garment.png', 'image survives prompt edit');
  await page.locator('[data-look="3"]').click();
  await page.locator('#apply').click();
  await page.waitForFunction(() => window.applied?.prompt.includes('denim'));
  assert.equal(await page.evaluate(() => window.applied.image), undefined, 'preset clears uploaded image');
  await page.evaluate(() => { window.failApply = true; });
  await page.locator('#apply').click();
  await page.waitForFunction(() => document.querySelector('#status').dataset.error === 'true');
  assert(await page.locator('#apply').isEnabled());
  await page.locator('#stop').click();
  assert(await page.evaluate(() => window.disconnected && window.testStream.getTracks().every(track => track.readyState === 'ended')));
  assert.equal(await page.locator('#output').evaluate(video => video.srcObject), null);
  await page.locator('#garment').setInputFiles({ name: 'bad.txt', mimeType: 'text/plain', buffer: Buffer.from('invalid') });
  await page.waitForFunction(() => document.querySelector('#status').textContent.includes('Choose a JPG'));
  await page.evaluate(() => { window.delayConnect = true; window.disconnected = false; });
  await page.locator('#start').click();
  await page.waitForFunction(() => window.finishConnect);
  await page.locator('#stop').click();
  await page.evaluate(() => window.finishConnect());
  await page.waitForFunction(() => window.disconnected);
  assert.equal(await page.locator('#output').evaluate(video => video.srcObject), null, 'late connect cannot revive stopped session');
  await page.reload();
  await page.clock.install();
  await page.locator('#consent').check();
  await page.locator('#start').click();
  await page.waitForFunction(() => !document.querySelector('#apply').disabled);
  await page.clock.fastForward(121000);
  assert.match(await page.locator('#status').innerText(), /two-minute demo has ended/);
  assert(await page.evaluate(() => window.testStream.getTracks().every(track => track.readyState === 'ended')));
  await page.reload();
  await page.evaluate(() => { navigator.mediaDevices.getUserMedia = async () => { throw new DOMException('Denied', 'NotAllowedError'); }; });
  await page.locator('#consent').check();
  await page.locator('#start').click();
  await page.waitForFunction(() => document.querySelector('#status').textContent.includes('permission was declined'));
  assert(await page.locator('#start').isEnabled());
  assert.deepEqual(errors, []);
  console.log('PASS: 3 responsive layouts, consent, presets, upload/retention/clearing, apply failure, stop/late-connect cleanup, camera denial.');
  await page.close();
  for (const [method, origin, expected] of [['GET', base, 405], ['POST', 'https://attacker.example', 403], ['POST', '', 403]]) {
    const context = await request.newContext();
    const response = await context.fetch(base + '/virtual-try-on-token.php', { method, headers: { Origin: origin } });
    assert.equal(response.status(), expected);
    await context.dispose();
  }
  console.log('PASS: live PHP method and origin gates.');
  if (process.env.LIVE_VTON === '1') {
    const live = await browser.newPage();
    await live.goto(base + '/demo/virtual-try-on.html');
    await live.locator('#consent').check();
    await live.locator('#start').click();
    await live.waitForFunction(() => document.querySelector('#output').videoWidth > 0 || document.querySelector('#status').dataset.error === 'true', null, { timeout: 90000 });
    const result = await live.evaluate(() => ({ status: document.querySelector('#status').textContent, width: document.querySelector('#output').videoWidth, height: document.querySelector('#output').videoHeight }));
    if (await live.locator('#stop').isEnabled()) await live.locator('#stop').click();
    assert(result.width > 0, JSON.stringify(result));
    console.log('PASS: real Decart output frames using synthetic camera:', JSON.stringify(result));
    await live.close();
  }
} finally { await browser.close(); }
