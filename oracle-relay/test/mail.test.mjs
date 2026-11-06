import test from 'node:test';
import assert from 'node:assert/strict';
import { sendPlanEmail, attachmentName } from '../mail.mjs';
import { loadCatalogue, fallbackPlan } from '../plan.mjs';
import { fakeFetch, RESEND_URL } from './fake-fetch.mjs';

const lead = { name: 'Asha Rao', email: 'asha@example.com', company: 'Rao Jewels & Sons', problem: 'missed calls' };
const plan = fallbackPlan(lead, loadCatalogue());
const pdf = Buffer.from('%PDF-1.7 fake');

test('payload shape: from, reply_to, to, bcc, text, html, base64 attachment, bearer key', async () => {
  const fetchFn = fakeFetch({ [RESEND_URL]: () => ({ status: 200, body: { id: 'x' } }) });
  await sendPlanEmail({ apiKey: 're_test', lead, pdf, plan, fetchFn });
  const { body, init } = fetchFn.calls[0];
  assert.equal(init.headers.authorization, 'Bearer re_test');
  assert.equal(body.from, 'VoxDonna <hello@send.voxdonna.com>');
  assert.equal(body.reply_to, 'hello@voxdonna.com');
  assert.deepEqual(body.to, ['asha@example.com']);
  assert.deepEqual(body.bcc, ['hello@voxdonna.com']);
  assert.ok(body.subject.length < 60);
  assert.match(body.text, /^Hi Asha,/);
  assert.equal((body.html.match(/<a /g) ?? []).length, 1, 'one link max');
  assert.doesNotMatch(body.html, /<img/);
  assert.equal(body.attachments.length, 1);
  assert.equal(body.attachments[0].filename, 'VoxDonna-plan-Rao-Jewels-Sons.pdf');
  assert.deepEqual(Buffer.from(body.attachments[0].content, 'base64'), pdf);
});

test('html escapes visitor-derived text', async () => {
  const fetchFn = fakeFetch({ [RESEND_URL]: () => ({}) });
  await sendPlanEmail({ apiKey: 'k', lead: { ...lead, name: '<script>x</script>' }, pdf, plan, fetchFn });
  assert.doesNotMatch(fetchFn.calls[0].body.html, /<script>/);
});

test('non-2xx throws with status only: no address, no key', async () => {
  const fetchFn = fakeFetch({ [RESEND_URL]: () => ({ status: 422, body: { message: 'bad asha@example.com' } }) });
  await assert.rejects(() => sendPlanEmail({ apiKey: 're_secret', lead, pdf, plan, fetchFn }), (e) => {
    assert.equal(e.message, 'resend_422');
    assert.doesNotMatch(e.stack, /asha@example|re_secret/);
    return true;
  });
});

test('attachmentName is filesystem-safe, falls back to name then "plan"', () => {
  assert.equal(attachmentName({ name: 'Zoë', company: '' }), 'VoxDonna-plan-Zoe.pdf');
  assert.equal(attachmentName({ name: 'राहुल' }), 'VoxDonna-plan-plan.pdf');
  assert.match(attachmentName({ company: '../../etc/passwd' }), /^VoxDonna-plan-[A-Za-z0-9-]+\.pdf$/);
});
