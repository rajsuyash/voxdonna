import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { WebSocketServer } from 'ws';
import { createRateLimiter, createTickets } from './tickets.mjs';
import { startSession } from './session.mjs';

const DEFAULT_ORIGINS = 'https://voxdonna.com,https://www.voxdonna.com,http://127.0.0.1:8792,http://localhost:8792';
const SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
const posNum = (v, d) => { const n = parseFloat(v); return Number.isFinite(n) && n > 0 ? n : d; };

export function loadConfig(env = process.env, overrides = {}) {
  if (!env.TICKET_SECRET) throw new Error('TICKET_SECRET is required');
  const project = env.GCP_PROJECT || 'voxdonna-oracle';
  const location = env.GCP_LOCATION || 'us-central1';
  const model = env.LIVE_MODEL || 'gemini-3.8-live';
  const authMode = env.AUTH_MODE || 'adc';
  if (!['adc', 'none'].includes(authMode)) throw new Error('AUTH_MODE must be adc or none');

  let adc = null;
  const getToken = authMode === 'none' ? async () => null : async () => {
    // google-auth-library caches and refreshes the token itself.
    adc ??= new (await import('google-auth-library')).GoogleAuth({ scopes: [SCOPE] });
    return (await adc.getAccessToken()) ?? null;
  };

  return {
    port: posNum(env.PORT, 8080),
    ticketSecret: env.TICKET_SECRET,
    origins: (env.ALLOWED_ORIGINS || DEFAULT_ORIGINS).split(',').map((s) => s.trim()).filter(Boolean),
    maxSessionSeconds: posNum(env.MAX_SESSION_SECONDS, 300),
    idleSeconds: posNum(env.IDLE_SECONDS, 45),
    graceSeconds: posNum(env.CAP_GRACE_SECONDS, 8),
    maxConcurrent: posNum(env.MAX_CONCURRENT, 20),
    leadWebhookUrl: env.LEAD_WEBHOOK_URL || '',
    trustProxy: env.TRUST_PROXY !== '0',
    upstreamUrl: env.UPSTREAM_URL || `wss://${location}-aiplatform.googleapis.com/ws/google.cloud.aiplatform.v1.LlmBidiService/BidiGenerateContent`,
    modelPath: `projects/${project}/locations/${location}/publishers/google/models/${model}`,
    instructions: readFileSync(new URL('./instructions.md', import.meta.url), 'utf8'),
    getToken,
    log: (o) => console.log(JSON.stringify({ ts: new Date().toISOString(), ...o })),
    ...overrides,
  };
}

// Behind Cloud Run the last X-Forwarded-For entry is the one Google's front end appended; earlier ones are client-supplied.
// Set TRUST_PROXY=0 when running without a proxy.
const clientIp = (req, trustProxy) => {
  const xff = trustProxy ? req.headers['x-forwarded-for'] : null;
  return (xff ? String(xff).split(',').pop().trim() : req.socket.remoteAddress) || 'unknown';
};

export function createApp(config) {
  const tickets = createTickets({ secret: config.ticketSecret });
  const limiter = createRateLimiter();
  const sessions = new Set();
  const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });
  const originOk = (req) => Boolean(req.headers.origin) && config.origins.includes(req.headers.origin);

  const json = (res, status, body, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(JSON.stringify(body));
  };

  const server = createServer((req, res) => {
    const { pathname } = new URL(req.url, 'http://relay');
    // Cloud Run's front end reserves paths ending in "z" (e.g. /healthz), so the public path is /health.
    if ((pathname === '/health' || pathname === '/healthz') && req.method === 'GET') return json(res, 200, { ok: true, sessions: sessions.size });

    if (pathname === '/ticket') {
      if (!originOk(req)) return json(res, 403, { error: 'origin_not_allowed' });
      const cors = {
        'access-control-allow-origin': req.headers.origin,
        'access-control-allow-methods': 'POST, OPTIONS',
        'access-control-allow-headers': 'content-type',
        'access-control-max-age': '600',
        vary: 'Origin',
      };
      if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
      if (req.method !== 'POST') return json(res, 405, { error: 'method_not_allowed' }, cors);
      const ip = clientIp(req, config.trustProxy);
      if (!limiter.allow(ip)) return json(res, 429, { error: 'rate_limited' }, { ...cors, 'retry-after': '600' });
      const { ticket, expiresAt } = tickets.issue(ip);
      const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
      const wsUrl = `${proto === 'https' ? 'wss' : 'ws'}://${req.headers.host}/live?ticket=${ticket}`;
      return json(res, 200, { ticket, expiresAt, wsUrl }, cors);
    }

    json(res, 404, { error: 'not_found' });
  });

  server.on('upgrade', (req, socket, head) => {
    socket.on('error', () => {});
    const reject = (code, text) => {
      socket.write(`HTTP/1.1 ${code} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      socket.destroy();
    };
    const url = new URL(req.url, 'http://relay');
    if (url.pathname !== '/live') return reject(404, 'Not Found');
    if (!originOk(req)) return reject(403, 'Forbidden');
    if (sessions.size >= config.maxConcurrent) return reject(503, 'Service Unavailable');
    // Tolerate a client that appended "?ticket=" to a wsUrl that already carries one.
    const ticket = (url.searchParams.get('ticket') ?? '').split('?')[0];
    if (!tickets.redeem(ticket, clientIp(req, config.trustProxy)).ok) return reject(401, 'Unauthorized');

    wss.handleUpgrade(req, socket, head, (ws) => {
      const handle = startSession({ client: ws, config, sessionId: randomUUID(), onEnd: () => sessions.delete(handle) });
      sessions.add(handle);
    });
  });

  return {
    server,
    sessions,
    listen: (port) => new Promise((resolve) => server.listen(port, () => resolve(server.address().port))),
    close: () => new Promise((resolve) => {
      [...sessions].forEach((s) => s.end('error'));
      wss.close();
      server.closeAllConnections?.();
      server.close(() => resolve());
    }),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let config;
  try { config = loadConfig(); } catch (e) { console.error(e.message); process.exit(1); }
  const app = createApp(config);
  const port = await app.listen(config.port);
  config.log({ event: 'listening', port, authMode: process.env.AUTH_MODE || 'adc' });
  const shutdown = () => app.close().then(() => process.exit(0));
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}
