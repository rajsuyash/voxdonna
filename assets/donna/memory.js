// What Donna remembers about this visitor for the tab's lifetime (sessionStorage). Shared by the homepage hero and the dock.
export const FIELD_KEYS = ['name', 'email', 'company', 'website', 'industry', 'problem', 'volume'];
export const LEAD_KEY = 'donna.lead.v1';
const LEAD_ENDPOINT = '/oracle-lead.php';

export const readStore = () => {
  try { return JSON.parse(sessionStorage.getItem(LEAD_KEY)) || {}; } catch { return {}; }
};
export const writeStore = (patch) => {
  try { sessionStorage.setItem(LEAD_KEY, JSON.stringify({ ...readStore(), ...patch })); } catch { /* storage blocked */ }
};

// Saved fields for the resume frame; undefined once the lead was sent (a finished lead is not replayed).
export function savedFields() {
  const { fields, completed } = readStore();
  if (completed || !fields) return undefined;
  const out = {};
  for (const k of FIELD_KEYS) { const v = typeof fields[k] === 'string' ? fields[k].trim() : ''; if (v) out[k] = v; }
  return Object.keys(out).length ? out : undefined;
}

export const markTalked = () => writeStore({ talked: true });
export const hasTalked = () => readStore().talked === true;

// Route/demo identifiers come from the relay's navigate event; the relay validates them again on resume.
const ID = /^[a-z][a-z0-9_-]{0,63}$/;
export function rememberNavigation(route, demo) {
  if (typeof route !== 'string' || !ID.test(route)) return;
  writeStore({ context: { lastRoute: route, ...(typeof demo === 'string' && ID.test(demo) ? { lastDemo: demo } : {}) } });
}

// Which of the relay's route keys the visitor is on right now; 'other' for anything else.
export function pageKey(loc = location) {
  switch (loc.pathname) {
    case '/demos.html': return 'demos';
    case '/ai-voice-agents.html': return loc.hash === '#pricing' ? 'pricing' : 'voice_agents';
    case '/jewellers.html': return 'jewellers';
    case '/ai-agents-for-ecommerce.html': return 'ecommerce';
    case '/automation-plan.html': return 'automation_plan';
    default: return 'other';
  }
}
export const resumeContext = () => ({ ...(readStore().context || {}), page: pageKey() });

const dlPush = function () { window.dataLayer.push(arguments); };
export const track = (name, params) => {
  if (typeof gtag === 'function') gtag('event', name, params);
  else if (Array.isArray(window.dataLayer)) dlPush('event', name, params);
};

export async function sendLead(lead, next) {
  try {
    const res = await fetch(LEAD_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lead, next, hp: '' }),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok && body.ok === true;
  } catch {
    return false;
  }
}
