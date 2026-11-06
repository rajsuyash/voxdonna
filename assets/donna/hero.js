// Ask Donna hero UI. All state lives here; the voice comes from engine.js.
import { connect } from './engine.js?v=20261106g';
import { initSoundform } from './soundform.js?v=20261106g';

const root = document.querySelector('.donna-hero');
const $ = (id) => document.getElementById(id);
const reduced = matchMedia('(prefers-reduced-motion: reduce)');
const MOCK = new URLSearchParams(location.search).get('engine') === 'mock';
const sf = initSoundform(root);

const MODE_TEXT = {
  ready: 'Ready to talk', connecting: 'Connecting', listening: 'Listening',
  thinking: 'Thinking', speaking: 'Donna is speaking', error: 'Line down, type instead',
};

// Destination cards. The relay sends route + url; the words live here.
const DEST = {
  demos: { title: 'Hear a demo.', text: 'Pick a scenario and listen to an agent handle a real call.', label: 'Open the demos' },
  pricing: { title: 'Pricing.', text: 'A setup fee, then calls at a fixed rate. The plans are laid out in full.', label: 'See plans and rates' },
  voice_agents: { title: 'Voice agents.', text: 'They answer the phone, qualify the lead, book the visit and write it back to your CRM.', label: 'Meet the agents' },
  jewellers: { title: 'Jewellers.', text: 'Gift advice, appointment booking and after-hours calls, handled in the boutique’s own voice.', label: 'See the jeweller demo' },
  ecommerce: { title: 'E-commerce.', text: 'Order status, returns and delivery questions, answered before the customer sighs.', label: 'See ecommerce agents' },
  book_call: { title: 'Book a call.', text: 'Pick a slot. I’ll hold it and send the brief ahead.', label: 'Pick a time' },
  book_meeting: { title: 'Pick a time.', text: 'Choose a slot that suits you; the team will have your details.', label: 'Pick a time' },
};

const FIELDS = [
  ['name', 'Name', 'name'], ['email', 'Email', 'email'], ['company', 'Company', 'organization'],
  ['website', 'Website', 'url'], ['industry', 'Industry'], ['problem', 'Problem'], ['volume', 'Volume'],
];

let opened = false;
const markOpen = () => { if (!opened) { opened = true; track('oracle_open'); } };
const state = { eng: null, session: 0, active: false, muted: false, typing: false, leadDone: false, leadShown: false, mode: 'ready' };
const typers = new Map();

// ---------------------------------------------------------------- lead persistence (sessionStorage)

const LEAD_KEY = 'donna.lead.v1';
const readStore = () => {
  try { return JSON.parse(sessionStorage.getItem(LEAD_KEY)) || {}; } catch { return {}; }
};
const writeStore = (patch) => {
  try { sessionStorage.setItem(LEAD_KEY, JSON.stringify({ ...readStore(), ...patch })); } catch { /* storage blocked */ }
};
const saveFields = () => {
  if (state.leadDone) return; // a finished lead stays marked completed
  const fields = {};
  for (const [k] of FIELDS) { const v = fieldInput(k)?.value.trim(); if (v) fields[k] = v; }
  writeStore({ fields, completed: false });
};
const knownFields = () => {
  const fields = {};
  for (const [k] of FIELDS) { const v = fieldInput(k).value.trim(); if (v) fields[k] = v; }
  return Object.keys(fields).length ? fields : undefined;
};

// ---------------------------------------------------------------- mode, captions

function setMode(mode) {
  state.mode = mode;
  root.dataset.mode = mode;
  sf.setMode(mode);
  $('dh-state').textContent = mode === 'ready' && state.typing ? 'Text mode' : MODE_TEXT[mode];
}

const cap = { user: { el: $('dh-cap-user'), final: true }, donna: { el: $('dh-cap-donna'), final: true } };

// Relay/mock captions are deltas: append until a final closes the turn, then the next chunk starts a new line.
function captionDelta(who, text, final) {
  const slot = cap[who] || cap.donna;
  if (slot.final && text) caption(who, text, final);
  else if (text) caption(who, slot.el.textContent + text, final);
  if (final) slot.final = true;
}

function caption(who, text, final = true, notice = false) {
  $('dh-caps').hidden = false;
  if (who === 'user' && cap.donna.final) cap.donna.el.textContent = '';
  const slot = cap[who] || cap.donna;
  slot.el.textContent = text;
  slot.el.classList.toggle('dh-cap--notice', notice);
  slot.final = final;
}

function clearCaptions() {
  for (const s of Object.values(cap)) { s.el.textContent = ''; s.final = true; }
  $('dh-caps').hidden = true;
}

// ---------------------------------------------------------------- lead card

function buildLead() {
  const dl = $('dh-fields');
  dl.replaceChildren();
  for (const [key, label, autocomplete] of FIELDS) {
    const row = document.createElement('div');
    row.className = 'dh-field';
    row.dataset.field = key;
    const dt = document.createElement('dt');
    const lab = document.createElement('label');
    lab.htmlFor = 'dh-f-' + key;
    lab.textContent = label;
    dt.append(lab);
    const dd = document.createElement('dd');
    const input = document.createElement(key === 'problem' ? 'textarea' : 'input');
    input.id = 'dh-f-' + key;
    input.placeholder = 'Listening for it';
    input.autocomplete = 'off';
    input.dataset.hint = autocomplete || '';
    if (key === 'problem') input.rows = 2; else input.type = key === 'email' ? 'email' : 'text';
    input.addEventListener('change', () => onEdit(key, input, row));
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); input.blur(); } });
    if (key === 'problem') input.addEventListener('input', () => fit(input));
    dd.append(input);
    row.append(dt, dd);
    dl.append(row);
  }
}

const fieldInput = (key) => $('dh-f-' + key);
const fit = (el) => { if (el.tagName === 'TEXTAREA') { el.style.height = 'auto'; el.style.height = el.scrollHeight + 2 + 'px'; } };

function updateCount() {
  const n = FIELDS.filter(([k]) => fieldInput(k).value.trim()).length;
  $('dh-lead-count').textContent = n + ' of ' + FIELDS.length;
}

function onEdit(key, input, row) {
  const value = input.value.trim();
  input.value = value;
  row.classList.toggle('is-filled', !!value);
  row.classList.add('is-edited');
  updateCount();
  saveFields();
  state.eng?.editField(key, value);
}

function revealLead() {
  if (state.leadShown) return;
  state.leadShown = true;
  const lead = $('dh-lead');
  lead.hidden = false;
  if (innerWidth < 1200 && lead.getBoundingClientRect().bottom > innerHeight) {
    lead.scrollIntoView({ behavior: reduced.matches ? 'auto' : 'smooth', block: 'end' });
  }
}

function setField(key, value) {
  const input = fieldInput(key);
  if (!input || state.leadDone) return;
  revealLead();
  const row = input.closest('.dh-field');
  clearInterval(typers.get(key));
  const text = String(value ?? '');
  const done = () => { input.value = text; fit(input); row.classList.toggle('is-filled', !!text); updateCount(); saveFields(); };
  if (document.activeElement === input) return; // the visitor is mid-edit, leave it alone
  row.classList.remove('is-edited');
  row.classList.remove('is-flash');
  void row.offsetWidth;
  row.classList.add('is-flash');
  if (reduced.matches || !text) { done(); return; }
  let i = 0;
  const step = Math.max(1, Math.ceil(text.length / 18));
  typers.set(key, setInterval(() => {
    i = Math.min(text.length, i + step);
    input.value = text.slice(0, i);
    fit(input);
    if (i >= text.length) { clearInterval(typers.get(key)); done(); }
  }, 30));
  row.classList.add('is-filled');
  updateCount();
}

const LEAD_ENDPOINT = '/oracle-lead.php';
// analytics.js keeps gtag private; gtag.js reads queued `arguments` objects from dataLayer, and its consent mode still applies.
function dlPush() { window.dataLayer.push(arguments); }
const track = (name, params) => {
  if (typeof gtag === 'function') gtag('event', name, params);
  else if (Array.isArray(window.dataLayer)) dlPush('event', name, params);
};

async function sendLead(next) {
  const lead = {};
  for (const [k] of FIELDS) lead[k] = fieldInput(k).value.trim();
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

const NEXT_STEPS = ['plan', 'demo', 'call'];

// Donna voice, one line per choice; plan wins the first sentence when combined.
function doneCopy(next) {
  const plan = next.includes('plan');
  const call = next.includes('call');
  if (plan && call) return 'Done. Your plan is on its way to your inbox. Pick a time and the team will have your details.';
  if (plan) return 'Done. Your plan is on its way to your inbox.';
  if (call) return 'Got it. Pick a time and the team will have your details.';
  return 'Got it. The team has your details.';
}

async function completeLead(lead, rawNext) {
  const next = Array.isArray(rawNext) ? NEXT_STEPS.filter((n) => rawNext.includes(n)) : [];
  for (const [k] of FIELDS) if (lead && lead[k] && !fieldInput(k).value) setField(k, lead[k]);
  revealLead();
  state.leadDone = true;
  writeStore({ fields: {}, completed: true });
  for (const [k] of FIELDS) fieldInput(k).readOnly = true;
  const done = $('dh-lead-done-text');
  done.textContent = 'Sending it to the team…';
  $('dh-lead-done').hidden = false;
  // The mock engine plays a scripted lead; never send that to the real inbox.
  const ok = MOCK ? true : await sendLead(next);
  if (ok) {
    done.textContent = doneCopy(next);
    if (!MOCK) track('generate_lead', { method: 'ask_donna' });
  } else {
    done.textContent = 'That didn’t reach the team. Use the contact form further down and they’ll pick it up.';
    $('dh-lead-done').classList.add('is-failed');
  }
}

function restoreLead() {
  const { fields, completed } = readStore();
  if (completed || !fields) return;
  let any = false;
  for (const [k] of FIELDS) {
    const v = typeof fields[k] === 'string' ? fields[k].trim() : '';
    if (!v) continue;
    const input = fieldInput(k);
    input.value = v;
    fit(input);
    input.closest('.dh-field').classList.add('is-filled');
    any = true;
  }
  if (any) revealLead();
}

function resetLead() {
  typers.forEach((t) => clearInterval(t));
  typers.clear();
  state.leadDone = false;
  state.leadShown = false;
  $('dh-lead').hidden = true;
  $('dh-lead-done').hidden = true;
  $('dh-lead-done').classList.remove('is-failed');
  buildLead();
  updateCount();
}

// ---------------------------------------------------------------- destination card

const NAV_SECONDS = 3;
const NAV_SPEECH_WAIT_MS = 2500;
const nav = { url: null, pending: false, timer: null, waitTimer: null, sawSpeaking: false };

function cancelNav() {
  clearInterval(nav.timer);
  clearTimeout(nav.waitTimer);
  nav.timer = null;
  nav.waitTimer = null;
  nav.sawSpeaking = false;
  nav.pending = false;
  nav.url = null;
  $('dh-detail-count').textContent = '';
}

function goNow(url) {
  cancelNav();
  const target = new URL(url, location.href);
  if (target.pathname === location.pathname && target.hash) {
    // Same page: scroll there and keep the call going.
    hideDetail();
    document.querySelector(target.hash)?.scrollIntoView({ behavior: reduced.matches ? 'auto' : 'smooth', block: 'start' });
    history.replaceState(null, '', target.hash);
    return;
  }
  endSession();
  location.assign(target.href);
}

// Starts once Donna has stopped talking, so the redirect never cuts her off.
function armNav() {
  if (!nav.pending || nav.timer) return;
  clearTimeout(nav.waitTimer);
  const url = nav.url;
  let left = NAV_SECONDS;
  const count = $('dh-detail-count');
  const tick = () => { count.textContent = `Taking you there in ${left}…`; };
  tick();
  nav.timer = setInterval(() => {
    left -= 1;
    if (left <= 0) goNow(url);
    else tick();
  }, 1000);
}

function showDetail(route, url) {
  const d = DEST[route] || { title: route.replace(/_/g, ' '), text: '', label: 'Open it' };
  cancelNav();
  $('dh-detail-title').textContent = d.title;
  $('dh-detail-text').textContent = d.text;
  $('dh-detail-go').href = url || '#';
  $('dh-detail-go').querySelector('span').textContent = d.label;
  $('dh-detail').hidden = false;
  root.classList.add('has-detail');
  if (!url) return;
  nav.url = url;
  nav.pending = true;
  // The relay emits `listening` right after `navigate`, before Donna speaks. Wait for speaking -> listening;
  // if she never speaks, or there is no live session, don't wait forever.
  if (!state.eng) { armNav(); return; }
  nav.waitTimer = setTimeout(() => { if (!nav.sawSpeaking) armNav(); }, NAV_SPEECH_WAIT_MS);
}

function hideDetail() {
  cancelNav();
  $('dh-detail').hidden = true;
  root.classList.remove('has-detail');
}

// ---------------------------------------------------------------- session

function updateControls() {
  const talk = $('dh-talk');
  talk.querySelector('span').textContent = state.active ? 'End conversation' : 'Talk to Donna';
  talk.querySelector('use').setAttribute('href', state.active ? '#dh-stop' : '#dh-mic');
  talk.setAttribute('aria-pressed', String(state.active));
  const sound = $('dh-sound');
  sound.querySelector('span').textContent = state.muted ? 'Sound off' : 'Sound on';
  sound.querySelector('use').setAttribute('href', state.muted ? '#dh-muted' : '#dh-speaker');
  sound.setAttribute('aria-pressed', String(!state.muted));
}

function setTyping(on, focus = false) {
  if (on) markOpen();
  state.typing = on;
  $('dh-composer').hidden = !on;
  $('dh-type').setAttribute('aria-expanded', String(on));
  $('dh-type').querySelector('span').textContent = on ? 'Close typing' : 'Type instead';
  if (on && focus) $('dh-question').focus({ preventScroll: true });
  if (state.mode === 'ready') setMode('ready');
}

function handlersFor(session) {
  const live = (fn) => (...a) => { if (session === state.session) fn(...a); };
  return {
    onState: live((s) => {
      setMode(s);
      if (!nav.pending) return;
      if (s === 'speaking') nav.sawSpeaking = true;
      else if (s === 'listening' && nav.sawSpeaking) armNav();
    }),
    onAudioLevel: live((l) => sf.setLevel(l)),
    onCaption: live(({ who, text, final }) => {
      if (who === 'user' && text) cancelNav();
      captionDelta(who, text, final);
    }),
    onField: live((f, v) => setField(f, v)),
    onNavigate: live((route, url) => showDetail(route, url)),
    onIntakeComplete: live((lead, next) => { completeLead(lead, next); }),
    onError: live(({ code }) => {
      state.active = false;
      if (code === 'mic_denied') {
        caption('donna', 'Microphone’s off. Type it here and I’ll keep up.', true, true);
        setMode('ready');
      } else {
        state.eng = null;
        caption('donna', 'The line’s down. Type it here and I’ll catch up when it’s back.', true, true);
        setMode('error');
      }
      updateControls();
      setTyping(true, true);
    }),
    onEnded: live((reason) => {
      if (reason === 'silence') caption('donna', 'Call ended after 10 seconds of quiet. Tap to talk again.', true, true);
      state.eng = null;
      state.active = false;
      updateControls();
      sf.setLevel(0);
      setMode('ready');
      armNav();
    }),
  };
}

function ensureSession() {
  if (!state.eng) {
    state.session += 1;
    state.eng = connect(handlersFor(state.session), { relay: root.dataset.relay, resume: state.leadDone ? undefined : knownFields() });
    state.eng.setMuted(state.muted);
  }
  return state.eng;
}

function endSession() {
  state.session += 1; // drop any late events from the old session
  state.eng?.stop();
  state.eng = null;
  state.active = false;
  sf.setLevel(0);
  setMode('ready');
  updateControls();
}

async function startTalking() {
  markOpen();
  if (state.leadDone) resetLead();
  hideDetail();
  clearCaptions();
  state.active = true;
  updateControls();
  setMode('connecting');
  const eng = ensureSession();
  const ok = await eng.startMic();
  if (ok && state.eng === eng && state.mode === 'connecting') setMode('listening');
}

function ask(text) {
  const q = text.trim();
  if (!q) return;
  if (state.leadDone) resetLead();
  cancelNav();
  const eng = ensureSession();
  caption('user', q, true);
  eng.sendText(q);
}

// ---------------------------------------------------------------- wiring

$('dh-talk').addEventListener('click', () => (state.active ? endSession() : startTalking()));
$('dh-type').addEventListener('click', () => setTyping(!state.typing, !state.typing));
$('dh-sound').addEventListener('click', () => {
  state.muted = !state.muted;
  state.eng?.setMuted(state.muted);
  updateControls();
});
$('dh-composer').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = $('dh-question');
  const q = input.value;
  input.value = '';
  ask(q);
});
document.querySelectorAll('.donna-hero .dh-prompt').forEach((b) => b.addEventListener('click', () => ask(b.dataset.question)));
$('dh-detail-back').addEventListener('click', () => { hideDetail(); $('dh-talk').focus(); });
$('dh-question').addEventListener('input', cancelNav);
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  endSession();
  hideDetail();
  setTyping(false);
  $('dh-talk').focus();
});
addEventListener('pagehide', endSession);
document.addEventListener('visibilitychange', () => { if (document.hidden && state.active) endSession(); });

buildLead();
restoreLead();
updateCount();
updateControls();
setMode('ready');
