import test from 'node:test';
import assert from 'node:assert/strict';
import { createRateLimiter, createTickets } from '../tickets.mjs';

const clock = (start = 1_000_000) => { let t = start; const now = () => t; now.advance = (ms) => { t += ms; }; return now; };

test('ticket signs and verifies for the same IP', () => {
  const now = clock();
  const t = createTickets({ secret: 's', now });
  const { ticket, expiresAt } = t.issue('1.1.1.1');
  assert.equal(expiresAt, 1_000_000 + 60_000);
  assert.deepEqual(t.redeem(ticket, '1.1.1.1'), { ok: true });
});

test('ticket expires after 60s', () => {
  const now = clock();
  const t = createTickets({ secret: 's', now });
  const { ticket } = t.issue('1.1.1.1');
  now.advance(60_001);
  assert.deepEqual(t.redeem(ticket, '1.1.1.1'), { ok: false, reason: 'expired' });
});

test('ticket is single use', () => {
  const t = createTickets({ secret: 's' });
  const { ticket } = t.issue('1.1.1.1');
  assert.equal(t.redeem(ticket, '1.1.1.1').ok, true);
  assert.deepEqual(t.redeem(ticket, '1.1.1.1'), { ok: false, reason: 'reused' });
});

test('ticket is bound to the issuing IP', () => {
  const t = createTickets({ secret: 's' });
  const { ticket } = t.issue('1.1.1.1');
  assert.deepEqual(t.redeem(ticket, '2.2.2.2'), { ok: false, reason: 'ip_mismatch' });
});

test('tampered, foreign-secret and malformed tickets are rejected', () => {
  const t = createTickets({ secret: 's' });
  const { ticket } = t.issue('1.1.1.1');
  const [body, sig] = ticket.split('.');
  const forged = Buffer.from(JSON.stringify({ id: 'x', exp: Date.now() + 1e9, iph: 'x' })).toString('base64url');
  assert.equal(t.redeem(`${forged}.${sig}`, '1.1.1.1').reason, 'bad_signature');
  assert.equal(createTickets({ secret: 'other' }).redeem(ticket, '1.1.1.1').reason, 'bad_signature');
  assert.equal(t.redeem(body, '1.1.1.1').reason, 'malformed');
  assert.equal(t.redeem(undefined, '1.1.1.1').reason, 'malformed');
  assert.equal(t.redeem('a.b.c', '1.1.1.1').reason, 'malformed');
});

test('rate limiter: 5 per 10 minutes per IP, other IPs unaffected', () => {
  const now = clock();
  const l = createRateLimiter({ now });
  for (let i = 0; i < 5; i++) assert.equal(l.allow('1.1.1.1'), true, `request ${i + 1}`);
  assert.equal(l.allow('1.1.1.1'), false);
  assert.equal(l.allow('2.2.2.2'), true);
  now.advance(600_001);
  assert.equal(l.allow('1.1.1.1'), true);
});

test('rate limiter: 10 per day even when spread across windows', () => {
  const now = clock();
  const l = createRateLimiter({ now });
  for (let i = 0; i < 10; i++) { assert.equal(l.allow('1.1.1.1'), true, `request ${i + 1}`); now.advance(300_000 * 3); }
  assert.equal(l.allow('1.1.1.1'), false);
  now.advance(86_400_000);
  assert.equal(l.allow('1.1.1.1'), true);
});
