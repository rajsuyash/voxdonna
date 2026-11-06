import http from 'node:http';
import WebSocket from 'ws';
import { createApp, loadConfig } from '../server.mjs';
import { startFakeUpstream } from './fake-upstream.mjs';

export const ORIGIN = 'https://voxdonna.com';
export const SECRET = 'test-secret';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Tiny local lead webhook receiver.
export async function startReceiver(status = 200) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      requests.push({ headers: req.headers, body: Buffer.concat(chunks).toString() });
      res.writeHead(status).end('ok');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${server.address().port}/lead`,
    requests,
    waitFor: async (ms = 3000) => {
      const end = Date.now() + ms;
      while (Date.now() < end) { if (requests.length) return requests[0]; await sleep(10); }
      throw new Error('receiver: no request within timeout');
    },
    close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }),
  };
}

function wrapClient(ws) {
  const c = { ws, msgs: [], closed: false };
  ws.on('message', (d) => c.msgs.push(JSON.parse(d.toString())));
  ws.on('close', () => { c.closed = true; });
  c.send = (o) => ws.send(typeof o === 'string' ? o : JSON.stringify(o));
  c.waitFor = async (pred, ms = 3000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const hit = c.msgs.find(pred);
      if (hit) return hit;
      await sleep(10);
    }
    throw new Error(`client: no matching message within ${ms}ms (saw types: ${c.msgs.map((m) => m.type).join(',')})`);
  };
  c.expectNone = async (pred, ms = 250) => {
    await sleep(ms);
    const hit = c.msgs.find(pred);
    if (hit) throw new Error(`client: unexpected message ${JSON.stringify(hit).slice(0, 200)}`);
  };
  c.waitClosed = async (ms = 3000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) { if (c.closed) return; await sleep(10); }
    throw new Error('client: socket did not close');
  };
  return c;
}

export async function boot({ env = {}, overrides = {}, webhook = false, webhookStatus = 200 } = {}) {
  const fake = await startFakeUpstream();
  const hook = webhook ? await startReceiver(webhookStatus) : null;
  const logs = [];
  const config = loadConfig({
    TICKET_SECRET: SECRET,
    AUTH_MODE: 'none',
    UPSTREAM_URL: fake.url,
    ALLOWED_ORIGINS: `${ORIGIN},http://localhost:8792`,
    ...(hook ? { LEAD_WEBHOOK_URL: hook.url } : {}),
    ...env,
  }, { log: (o) => logs.push(o), ...overrides });
  const app = createApp(config);
  const port = await app.listen(0);
  const clients = [];

  const env_ = {
    fake, hook, logs, app, config, port,
    request(method, path, headers = {}) {
      return new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString();
            let body = null;
            try { body = JSON.parse(text); } catch { /* not json */ }
            resolve({ status: res.statusCode, headers: res.headers, body, text });
          });
        });
        req.on('error', reject);
        req.end();
      });
    },
    async ticket(origin = ORIGIN, headers = {}) {
      const r = await env_.request('POST', '/ticket', { origin, ...headers });
      if (r.status !== 200) throw new Error(`ticket failed: ${r.status} ${r.text}`);
      return r.body;
    },
    // Resolves { client } on upgrade or { status } when the relay rejects the upgrade.
    tryConnect(ticket, { origin = ORIGIN, headers = {} } = {}) {
      return new Promise((resolve) => {
        const ws = new WebSocket(`ws://127.0.0.1:${port}/live?ticket=${encodeURIComponent(ticket)}`, { headers: { ...(origin ? { origin } : {}), ...headers } });
        ws.on('unexpected-response', (_req, res) => { res.resume(); resolve({ status: res.statusCode }); });
        ws.on('error', () => {});
        ws.on('open', () => { const client = wrapClient(ws); clients.push(client); resolve({ client }); });
      });
    },
    // Full happy-path open: ticket, connect, wait for "ready".
    async open() {
      const { ticket } = await env_.ticket();
      const r = await env_.tryConnect(ticket);
      if (!r.client) throw new Error(`upgrade rejected: ${r.status}`);
      await r.client.waitFor((m) => m.type === 'ready');
      return r.client;
    },
    async stop() {
      clients.forEach((c) => c.ws.terminate());
      await app.close();
      await fake.close();
      await hook?.close();
    },
  };
  return env_;
}

export const sleepMs = sleep;
