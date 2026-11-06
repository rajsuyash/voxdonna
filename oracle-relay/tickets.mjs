import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const mac = (secret, data) => createHmac('sha256', secret).update(data).digest();

export const ipHash = (secret, ip) =>
  createHash('sha256').update(`${secret}|${ip}`).digest('hex').slice(0, 16);

// Ticket = base64url(JSON{id, exp, iph}) "." base64url(HMAC-SHA256). Single use.
// ponytail: the used-id set is in-memory, so with N Cloud Run instances a ticket could be
// redeemed once per instance within its 60s life. Upgrade path: Redis/Firestore if that matters.
export function createTickets({ secret, ttlMs = 60_000, now = Date.now }) {
  const used = new Map(); // id -> exp

  const sweep = () => {
    const t = now();
    for (const [id, exp] of used) if (exp <= t) used.delete(id);
  };
  const fail = (reason) => ({ ok: false, reason });

  return {
    issue(ip) {
      const expiresAt = now() + ttlMs;
      const body = b64u(JSON.stringify({ id: randomBytes(12).toString('hex'), exp: expiresAt, iph: ipHash(secret, ip) }));
      return { ticket: `${body}.${b64u(mac(secret, body))}`, expiresAt };
    },

    redeem(ticket, ip) {
      if (typeof ticket !== 'string') return fail('malformed');
      const parts = ticket.split('.');
      if (parts.length !== 2 || !parts[0] || !parts[1]) return fail('malformed');
      const [body, sig] = parts;
      const expected = mac(secret, body);
      const given = Buffer.from(sig, 'base64url');
      if (given.length !== expected.length || !timingSafeEqual(given, expected)) return fail('bad_signature');
      let p;
      try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return fail('malformed'); }
      if (!(p.exp > now())) return fail('expired');
      if (p.iph !== ipHash(secret, ip)) return fail('ip_mismatch');
      sweep();
      if (used.has(p.id)) return fail('reused');
      used.set(p.id, p.exp);
      return { ok: true };
    },
  };
}

// Per-IP ticket limiter: 5 per 10 min and 10 per day.
// ponytail: in-memory per instance; with max-instances=3 the real ceiling is up to 3x. Move to a shared store if abuse shows up.
export function createRateLimiter({ now = Date.now, perWindow = 5, windowMs = 600_000, perDay = 10, dayMs = 86_400_000 } = {}) {
  const hits = new Map(); // ip -> [timestamps within the last day]

  const sweep = (t) => {
    for (const [ip, list] of hits) {
      const live = list.filter((h) => h > t - dayMs);
      if (live.length) hits.set(ip, live); else hits.delete(ip);
    }
  };

  return {
    allow(ip) {
      const t = now();
      if (hits.size > 5000) sweep(t);
      const recent = (hits.get(ip) ?? []).filter((h) => h > t - dayMs);
      const inWindow = recent.filter((h) => h > t - windowMs).length;
      if (inWindow >= perWindow || recent.length >= perDay) {
        hits.set(ip, recent);
        return false;
      }
      hits.set(ip, [...recent, t]);
      return true;
    },
  };
}
