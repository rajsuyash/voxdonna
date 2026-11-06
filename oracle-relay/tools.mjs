import { createHmac } from 'node:crypto';

export const FIELDS = ['name', 'email', 'company', 'website', 'industry', 'problem', 'volume'];
export const REQUIRED = ['name', 'email', 'problem'];

// The model can only pick a key; the browser only ever sees the mapped url.
export const ROUTES = {
  demos: '/demos.html',
  pricing: '/ai-voice-agents.html#pricing',
  voice_agents: '/ai-voice-agents.html',
  jewellers: '/jewellers.html',
  ecommerce: '/ai-agents-for-ecommerce.html',
  book_call: '#contact',
  book_meeting: 'https://tidycal.com/rajsuyash/discovery-call-for-ai-voice-agent',
};

export const NEXT_STEPS = ['plan', 'demo', 'call'];

const MAX_LEN = 300;
const MAX_PROBLEM = 1500;
const LATIN_ONLY = ['name', 'company', 'industry'];
const PLACEHOLDERS = new Set(['n/a', 'na', 'none', 'null', 'unknown', 'not provided', 'not given', 'tbd', 'visitor', 'user', 'anonymous']);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export function validateField(field, value) {
  if (typeof field !== 'string' || !FIELDS.includes(field)) return { ok: false, error: `unknown field: ${String(field).slice(0, 40)}` };
  if (typeof value !== 'string') return { ok: false, error: `${field} must be a string` };
  const v = value.trim();
  if (!v) return { ok: false, error: `${field} is empty` };
  const bare = v.replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, '').toLowerCase();
  if (!bare || PLACEHOLDERS.has(bare)) {
    return { ok: false, error: 'No value given yet. Ask the visitor for it instead of saving a placeholder.' };
  }
  const max = field === 'problem' ? MAX_PROBLEM : MAX_LEN;
  if (v.length > max) return { ok: false, error: `${field} is too long (max ${max} characters)` };
  if (field === 'email' && !EMAIL_RE.test(v)) return { ok: false, error: 'email looks invalid; ask the visitor to spell it again' };
  if (LATIN_ONLY.includes(field) && !/\p{Script=Latin}/u.test(v)) {
    return { ok: false, error: `${field} must be saved in English/Latin script; transliterate it and call save_field again` };
  }
  return { ok: true, value: v };
}

export function createLead() {
  const data = {};
  let completed = false;
  let planSent = false;
  return {
    set(field, value) { data[field] = value; },
    snapshot: () => ({ ...data }),
    missing: () => REQUIRED.filter((f) => !data[f]),
    get completed() { return completed; },
    markCompleted() { completed = true; },
    get planSent() { return planSent; },
    markPlanSent() { planSent = true; },
  };
}

// Tool declarations sent to Gemini in the setup message.
export const TOOL_DECLARATIONS = [
  {
    name: 'save_field',
    description: 'Save one piece of lead information the visitor has given you. Call it as soon as you have the value.',
    parameters: {
      type: 'OBJECT',
      properties: {
        field: { type: 'STRING', enum: FIELDS, description: 'Which field to save.' },
        value: { type: 'STRING', description: 'The value, exactly as the visitor gave it (email lowercase, no spaces).' },
      },
      required: ['field', 'value'],
    },
  },
  {
    name: 'navigate',
    description: 'Take the visitor to a page on the VoxDonna site when they ask for it.',
    parameters: {
      type: 'OBJECT',
      properties: { route: { type: 'STRING', enum: Object.keys(ROUTES), description: 'Which page.' } },
      required: ['route'],
    },
  },
  {
    name: 'finish_intake',
    description: 'Call once name, email and problem are saved, you have asked the remaining questions, and the visitor has said what they want next. Records the lead and acts on their choice. Never call it without asking them first.',
    parameters: {
      type: 'OBJECT',
      properties: {
        next: {
          type: 'ARRAY',
          items: { type: 'STRING', enum: NEXT_STEPS },
          description: 'What the visitor chose: plan (emailed automation plan), demo (see live demos), call (book a call with the team). One or more.',
        },
      },
      required: ['next'],
    },
  },
];

// Runs one model tool call. Never trusts the args. Returns what to tell the model,
// what to tell the browser, and (only on first successful finish) the lead to ship.
export function handleToolCall(lead, call) {
  const args = call?.args && typeof call.args === 'object' ? call.args : {};
  const err = (error) => ({ response: { ok: false, error }, events: [] });

  switch (call?.name) {
    case 'save_field': {
      const r = validateField(args.field, args.value);
      if (!r.ok) return err(r.error);
      lead.set(args.field, r.value);
      return { response: { ok: true }, events: [{ type: 'field', field: args.field, value: r.value }] };
    }
    case 'navigate': {
      if (typeof args.route !== 'string' || !Object.hasOwn(ROUTES, args.route)) {
        return err(`unknown route; valid routes: ${Object.keys(ROUTES).join(', ')}`);
      }
      return { response: { ok: true }, events: [{ type: 'navigate', route: args.route, url: ROUTES[args.route] }] };
    }
    case 'finish_intake': {
      const picked = Array.isArray(args.next) ? [...new Set(args.next)] : [];
      if (!picked.length || !picked.every((n) => NEXT_STEPS.includes(n))) {
        return err('next must list one or more of plan, demo, call. Ask the visitor which they want: a plan by email, a live demo, or a call with the team.');
      }
      const wantsPlan = picked.includes('plan');
      const lines = {
        plan: 'Tell them the plan is on its way to their inbox in a couple of minutes, and to check spam or the updates tab if it does not show.',
        demo: 'Say one short line, then call navigate with route demos.',
        call: 'Say one short line, then call navigate with route book_meeting.',
      };
      const then = picked.filter((n) => n === 'plan' || !(n === 'demo' && picked.includes('call'))).map((n) => lines[n]);
      if (lead.completed) {
        // A later "also send me the plan" is allowed once; anything else is a repeat.
        if (!wantsPlan || lead.planSent) return { response: { ok: true, alreadySubmitted: true }, events: [] };
        lead.markPlanSent();
        return { response: { ok: true, planQueued: true, then: [lines.plan] }, events: [], submit: lead.snapshot() };
      }
      const missing = lead.missing();
      if (missing.length) return { response: { ok: false, missing }, events: [] };
      lead.markCompleted();
      if (wantsPlan) lead.markPlanSent();
      const snap = lead.snapshot();
      return {
        response: { ok: true, next: picked, planQueued: wantsPlan, then },
        events: [{ type: 'intake_complete', lead: snap, next: picked }],
        ...(wantsPlan ? { submit: snap } : {}),
      };
    }
    default:
      return err(`unknown tool: ${String(call?.name).slice(0, 40)}`);
  }
}

export const signBody = (secret, body) => createHmac('sha256', secret).update(body).digest('hex');

// Fire-and-log: a failing webhook never throws into the session.
export async function postLead({ url, secret, sessionId, lead, log, fetchFn = fetch }) {
  const body = JSON.stringify({ sessionId, submittedAt: new Date().toISOString(), lead });
  try {
    const res = await fetchFn(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-oracle-signature': signBody(secret, body) },
      body,
      signal: AbortSignal.timeout(60000),
    });
    log('lead_webhook', { sessionId, ok: res.ok, status: res.status });
  } catch (e) {
    log('lead_webhook', { sessionId, ok: false, error: e.name });
  }
}
