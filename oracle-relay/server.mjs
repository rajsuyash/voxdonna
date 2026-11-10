import { createServer } from 'node:http';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { WebSocketServer } from 'ws';
import { createRateLimiter, createTickets } from './tickets.mjs';
import { startSession } from './session.mjs';
import { FIELDS, REQUIRED, signBody, validateField } from './tools.mjs';
import { generatePlan, loadCatalogue } from './plan.mjs';
import { renderPlanPdf } from './pdf.mjs';
import { sendPlanEmail } from './mail.mjs';

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
    silenceSeconds: posNum(env.SILENCE_SECONDS, 10),
    silenceGraceSeconds: posNum(env.SILENCE_GRACE_SECONDS, 8),
    voiceName: env.VOICE_NAME || 'Kore',
    voiceLanguage: env.VOICE_LANGUAGE || 'en-US',
    graceSeconds: posNum(env.CAP_GRACE_SECONDS, 8),
    maxConcurrent: posNum(env.MAX_CONCURRENT, 20),
    project,
    planModel: env.PLAN_MODEL || 'gemini-3.8-flash',
    planLocation: env.PLAN_LOCATION || 'global',
    resendApiKey: env.RESEND_API_KEY || '',
    maxPlansPerDay: posNum(env.MAX_PLANS_PER_DAY, 100),
    catalogue: loadCatalogue(),
    fetchFn: fetch,
    trustProxy: env.TRUST_PROXY !== '0',
    googleSearch: env.GOOGLE_SEARCH !== '0',
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

const MAX_PLAN_BODY = 20 * 1024;
const PER_EMAIL_PER_DAY = 3;

function readBody(req, max) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > max) { chunks.length = 0; resolve(null); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(null));
  });
}

const signatureOk = (secret, rawBody, header) => {
  const want = Buffer.from(signBody(secret, rawBody));
  const got = Buffer.from(String(header ?? ''));
  return got.length === want.length && timingSafeEqual(got, want);
};

// Keeps only validated lead fields; null when a required one is missing or invalid.
function cleanLead(input) {
  const lead = {};
  for (const f of FIELDS) {
    const r = validateField(f, input?.[f]);
    if (r.ok) lead[f] = r.value;
  }
  return REQUIRED.every((f) => lead[f]) ? lead : null;
}

// ponytail: daily caps live in this instance's memory, so with max 3 instances the real ceiling is up to 3x.
// Move the counters to Firestore if this is ever abused.
function createDailyCaps({ perEmail, global }) {
  let day = '';
  let total = 0;
  const byEmail = new Map();
  const roll = () => {
    const today = new Date().toISOString().slice(0, 10);
    if (today !== day) { day = today; total = 0; byEmail.clear(); }
  };
  return {
    take(email) {
      roll();
      const key = email.toLowerCase();
      if (total >= global || (byEmail.get(key) ?? 0) >= perEmail) return false;
      total += 1;
      byEmail.set(key, (byEmail.get(key) ?? 0) + 1);
      return true;
    },
    refund(email) {
      const key = email.toLowerCase();
      total = Math.max(0, total - 1);
      byEmail.set(key, Math.max(0, (byEmail.get(key) ?? 1) - 1));
    },
  };
}

export function createApp(config) {
  const tickets = createTickets({ secret: config.ticketSecret });
  const limiter = createRateLimiter();
  const caps = createDailyCaps({ perEmail: PER_EMAIL_PER_DAY, global: config.maxPlansPerDay });
  const sessions = new Set();
  const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });
  const originOk = (req) => Boolean(req.headers.origin) && config.origins.includes(req.headers.origin);

  const json = (res, status, body, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(JSON.stringify(body));
  };

  // Server-to-server: authenticated by the HMAC signature (HMAC-SHA256 of the raw body with TICKET_SECRET), not by Origin.
  const handlePlan = async (req, res) => {
    if (req.method !== 'POST') return json(res, 405, { error: 'method_not_allowed' });
    const raw = await readBody(req, MAX_PLAN_BODY);
    if (raw === null) return json(res, 413, { error: 'too_large' }, { connection: 'close' });
    if (!signatureOk(config.ticketSecret, raw, req.headers['x-oracle-signature'])) return json(res, 401, { error: 'bad_signature' });
    let payload;
    try { payload = JSON.parse(raw); } catch { return json(res, 400, { error: 'bad_json' }); }
    const lead = cleanLead(payload?.lead);
    if (!lead) return json(res, 400, { error: 'bad_lead' });
    if (!config.resendApiKey) return json(res, 503, { error: 'mail_not_configured' });
    if (!caps.take(lead.email)) return json(res, 429, { error: 'plan_cap_reached' });

    const sessionId = String(payload.sessionId ?? '').slice(0, 64);
    const started = Date.now();
    try {
      const { plan, source } = await generatePlan({
        lead, catalogue: config.catalogue, getToken: config.getToken, fetchFn: config.fetchFn,
        model: config.planModel, project: config.project, location: config.planLocation, log: config.log,
      });
      const pdf = await renderPlanPdf({ lead, plan, catalogue: config.catalogue });
      await sendPlanEmail({ apiKey: config.resendApiKey, lead, pdf, plan, fetchFn: config.fetchFn });
      config.log({ event: 'plan_sent', sessionId, source, bytes: pdf.length, ms: Date.now() - started });
      return json(res, 200, { ok: true, source });
    } catch (e) {
      caps.refund(lead.email);
      config.log({ event: 'plan_failed', sessionId, error: /^resend_\d+$/.test(e?.message) ? e.message : (e?.name ?? 'error'), ms: Date.now() - started });
      return json(res, 502, { error: 'plan_failed' });
    }
  };

  const server = createServer((req, res) => {
    const { pathname } = new URL(req.url, 'http://relay');
    // Cloud Run's front end reserves paths ending in "z" (e.g. /healthz), so the public path is /health.
    if ((pathname === '/health' || pathname === '/healthz') && req.method === 'GET') return json(res, 200, { ok: true, sessions: sessions.size });

    if (pathname === '/plan') return void handlePlan(req, res);

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
