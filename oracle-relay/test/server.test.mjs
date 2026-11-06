import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../server.mjs';
import { ORIGIN, boot } from './helpers.mjs';

test('refuses to load config without TICKET_SECRET', () => {
  assert.throws(() => loadConfig({ AUTH_MODE: 'none' }), /TICKET_SECRET/);
});

test('GET /health and /healthz', async (t) => {
  const env = await boot(); t.after(env.stop);
  for (const path of ['/health', '/healthz']) {
    const r = await env.request('GET', path);
    assert.equal(r.status, 200, path);
    assert.equal(r.body.ok, true);
  }
});

test('POST /ticket: allowed origin gets ticket, expiry, wsUrl and CORS', async (t) => {
  const env = await boot(); t.after(env.stop);
  const r = await env.request('POST', '/ticket', { origin: ORIGIN, host: 'relay.test' });
  assert.equal(r.status, 200);
  assert.ok(r.body.ticket && r.body.expiresAt > Date.now());
  assert.equal(r.body.wsUrl, `ws://relay.test/live?ticket=${r.body.ticket}`);
  assert.equal(r.headers['access-control-allow-origin'], ORIGIN);
});

test('POST /ticket: disallowed or missing Origin is rejected with no CORS header', async (t) => {
  const env = await boot(); t.after(env.stop);
  for (const headers of [{ origin: 'https://evil.example' }, {}]) {
    const r = await env.request('POST', '/ticket', headers);
    assert.equal(r.status, 403);
    assert.equal(r.headers['access-control-allow-origin'], undefined);
  }
});

test('OPTIONS /ticket preflight: allowed origin gets 204, others 403', async (t) => {
  const env = await boot(); t.after(env.stop);
  const ok = await env.request('OPTIONS', '/ticket', { origin: ORIGIN });
  assert.equal(ok.status, 204);
  assert.match(ok.headers['access-control-allow-methods'], /POST/);
  assert.equal((await env.request('OPTIONS', '/ticket', { origin: 'https://evil.example' })).status, 403);
});

test('POST /ticket: 6th request from one IP in 10 minutes is rate limited', async (t) => {
  const env = await boot(); t.after(env.stop);
  for (let i = 0; i < 5; i++) assert.equal((await env.request('POST', '/ticket', { origin: ORIGIN })).status, 200);
  const r = await env.request('POST', '/ticket', { origin: ORIGIN });
  assert.equal(r.status, 429);
  const other = await env.request('POST', '/ticket', { origin: ORIGIN, 'x-forwarded-for': '9.9.9.9' });
  assert.equal(other.status, 200, 'a different IP is unaffected');
});

test('WS upgrade: bad Origin is 403, missing Origin 403', async (t) => {
  const env = await boot(); t.after(env.stop);
  const { ticket } = await env.ticket();
  assert.equal((await env.tryConnect(ticket, { origin: 'https://evil.example' })).status, 403);
  assert.equal((await env.tryConnect(ticket, { origin: null })).status, 403);
  const ok = await env.tryConnect(ticket);
  assert.ok(ok.client, 'ticket was not burned by the rejected attempts');
});

test('WS upgrade: bad, reused and wrong-IP tickets are 401', async (t) => {
  const env = await boot(); t.after(env.stop);
  assert.equal((await env.tryConnect('garbage')).status, 401);
  assert.equal((await env.tryConnect('')).status, 401);

  const { ticket } = await env.ticket();
  assert.ok((await env.tryConnect(ticket)).client);
  assert.equal((await env.tryConnect(ticket)).status, 401, 'reuse');

  const bound = await env.ticket(ORIGIN, { 'x-forwarded-for': '1.1.1.1' });
  assert.equal((await env.tryConnect(bound.ticket, { headers: { 'x-forwarded-for': '2.2.2.2' } })).status, 401, 'wrong IP');
});

test('WS upgrade: wsUrl with an extra appended ?ticket= still works', async (t) => {
  const env = await boot(); t.after(env.stop);
  const { ticket } = await env.ticket();
  assert.ok((await env.tryConnect(`${ticket}?ticket=${ticket}`)).client);
});

test('WS upgrade: 503 when MAX_CONCURRENT is reached', async (t) => {
  const env = await boot({ env: { MAX_CONCURRENT: '1' } }); t.after(env.stop);
  await env.open();
  const { ticket } = await env.ticket();
  assert.equal((await env.tryConnect(ticket)).status, 503);
});
