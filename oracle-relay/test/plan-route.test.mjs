import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { SECRET, boot } from './helpers.mjs';
import { signBody } from '../tools.mjs';
import { fakeFetch, VERTEX_URL, RESEND_URL, vertexReply } from './fake-fetch.mjs';

const lead = { name: 'Asha Rao', email: 'asha@example.com', company: 'Rao Jewels', problem: 'We miss calls after 7pm' };

function post(env, body, { sign = true, signature, headers = {} } = {}) {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  const sig = signature ?? (sign ? signBody(SECRET, raw) : undefined);
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: env.port, method: 'POST', path: '/plan',
      headers: { 'content-type': 'application/json', ...(sig ? { 'x-oracle-signature': sig } : {}), ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => { const text = Buffer.concat(chunks).toString(); let j = null; try { j = JSON.parse(text); } catch { /* */ } resolve({ status: res.statusCode, body: j, text }); });
    });
    req.on('error', reject);
    req.end(raw);
  });
}

async function bootPlan({ resend = true, vertex = () => ({ status: 500 }), resendHandler = () => ({ status: 200, body: { id: 'e1' } }), env = {} } = {}) {
  const fetchFn = fakeFetch({ [VERTEX_URL()]: vertex, [RESEND_URL]: resendHandler });
  const e = await boot({ env: { ...(resend ? { RESEND_API_KEY: 're_test' } : {}), ...env }, overrides: { fetchFn } });
  e.fetchFn = fetchFn;
  return e;
}

test('POST /plan: happy path (LLM fallback) sends one email with a PDF and logs no PII', async (t) => {
  const env = await bootPlan(); t.after(env.stop);
  const r = await post(env, { sessionId: 's1', submittedAt: 'now', lead });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { ok: true, source: 'fallback' });
  const mail = env.fetchFn.calls.find((c) => c.url.includes('resend'));
  assert.deepEqual(mail.body.to, ['asha@example.com']);
  const pdf = Buffer.from(mail.body.attachments[0].content, 'base64');
  assert.equal(pdf.subarray(0, 4).toString(), '%PDF');
  const sent = env.logs.find((l) => l.event === 'plan_sent');
  assert.deepEqual(Object.keys(sent).sort(), ['bytes', 'event', 'ms', 'sessionId', 'source']);
  assert.doesNotMatch(JSON.stringify(env.logs), /asha@example|Rao|7pm|re_test/);
});

test('POST /plan: valid LLM output gives source llm', async (t) => {
  const plan = {
    summary: 'Calls after hours are the leak. Close it first.',
    picks: [
      { id: 'voice-agents', why: 'It answers after seven.', first_step: 'List the call types that repeat.', effort: '2-4 weeks' },
      { id: 'whatsapp-agents', why: 'It follows up on quiet enquiries.', first_step: 'Write down the common questions.', effort: 'days' },
      { id: 'automation-assessment', why: 'It checks what else repeats.', first_step: 'List four repeating tasks.', effort: 'days' },
    ],
    next_step: 'Book a call.',
  };
  const env = await bootPlan({ vertex: () => vertexReply(plan) }); t.after(env.stop);
  const r = await post(env, { sessionId: 's2', lead });
  assert.equal(r.body.source, 'llm');
  assert.equal(env.fetchFn.calls.length, 2);
});

test('POST /plan: missing, wrong and tampered signatures are 401 and send nothing', async (t) => {
  const env = await bootPlan(); t.after(env.stop);
  const body = { sessionId: 's', lead };
  assert.equal((await post(env, body, { sign: false })).status, 401);
  assert.equal((await post(env, body, { signature: 'deadbeef' })).status, 401);
  assert.equal((await post(env, body, { signature: signBody('other-secret', JSON.stringify(body)) })).status, 401);
  const raw = JSON.stringify(body);
  assert.equal((await post(env, raw.replace('Asha', 'Evil'), { signature: signBody(SECRET, raw) })).status, 401);
  assert.equal(env.fetchFn.calls.length, 0);
});

test('POST /plan: body over 20 KB is 413', async (t) => {
  const env = await bootPlan(); t.after(env.stop);
  const r = await post(env, JSON.stringify({ lead, pad: 'x'.repeat(21 * 1024) }));
  assert.equal(r.status, 413);
  assert.equal(env.fetchFn.calls.length, 0);
});

test('POST /plan: per-email cap is 3 per day (case-insensitive), 4th is 429; other emails unaffected', async (t) => {
  const env = await bootPlan(); t.after(env.stop);
  for (const email of ['asha@example.com', 'ASHA@example.com', 'asha@example.com']) {
    assert.equal((await post(env, { sessionId: 's', lead: { ...lead, email } })).status, 200);
  }
  assert.equal((await post(env, { sessionId: 's', lead })).status, 429);
  assert.equal((await post(env, { sessionId: 's', lead: { ...lead, email: 'b@example.com' } })).status, 200);
});

test('POST /plan: global MAX_PLANS_PER_DAY is 429', async (t) => {
  const env = await bootPlan({ env: { MAX_PLANS_PER_DAY: '2' } }); t.after(env.stop);
  assert.equal((await post(env, { lead: { ...lead, email: 'a@example.com' } })).status, 200);
  assert.equal((await post(env, { lead: { ...lead, email: 'b@example.com' } })).status, 200);
  assert.equal((await post(env, { lead: { ...lead, email: 'c@example.com' } })).status, 429);
});

test('POST /plan: missing RESEND_API_KEY is 503 mail_not_configured, no model call, no cap used', async (t) => {
  const env = await bootPlan({ resend: false }); t.after(env.stop);
  const r = await post(env, { lead });
  assert.equal(r.status, 503);
  assert.equal(r.body.error, 'mail_not_configured');
  assert.equal(env.fetchFn.calls.length, 0);
});

test('POST /plan: invalid lead is 400; header-injection email rejected', async (t) => {
  const env = await bootPlan(); t.after(env.stop);
  assert.equal((await post(env, { lead: { name: 'A', problem: 'x' } })).status, 400);
  assert.equal((await post(env, { lead: { ...lead, email: 'a@b.co\r\nBcc: x@y.z' } })).status, 400);
  assert.equal((await post(env, 'not json')).status, 400, 'validly signed but not JSON');
});

test('POST /plan: Resend failure is 502 and gives the cap back', async (t) => {
  const env = await bootPlan({ resendHandler: () => ({ status: 500 }) }); t.after(env.stop);
  for (let i = 0; i < 4; i++) assert.equal((await post(env, { lead })).status, 502);
  assert.match(JSON.stringify(env.logs.at(-1)), /resend_500/);
  assert.doesNotMatch(JSON.stringify(env.logs), /asha@example/);
});

test('POST /plan: is not subject to the Origin allow-list; GET is 405', async (t) => {
  const env = await bootPlan(); t.after(env.stop);
  assert.equal((await post(env, { lead }, { headers: { origin: 'https://evil.example' } })).status, 200);
  assert.equal((await env.request('GET', '/plan')).status, 405);
});
