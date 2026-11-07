(() => {
'use strict';
const DATA_URL = '/assets/automation-plan/industries.json';
const LEAD_ENDPOINT = '/oracle-lead.php';
const NOT_SURE = 'not-sure';
const PAIN_BONUS = 25;
const VOLUME_BONUS = 5;
const TOP_N = 3;
const NOTES_MAX = 300;
// Bare domains (acme.com) or full URLs; no scheme required.
const WEBSITE_RE = /^(https?:\/\/)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(:\d+)?([/?#]\S*)?$/i;
const VOLUMES = [
  { id: 'under-100', label: 'Under 100', high: false },
  { id: '100-500', label: '100 to 500', high: false },
  { id: '500-2000', label: '500 to 2,000', high: true },
  { id: '2000-plus', label: '2,000+', high: true },
];
const TEAMS = [
  { id: '1-10', label: '1 to 10 people' },
  { id: '11-50', label: '11 to 50 people' },
  { id: '51-200', label: '51 to 200 people' },
  { id: '200-plus', label: 'More than 200' },
];
const CHANNEL_LABEL = { voice: 'Voice', whatsapp: 'WhatsApp', email: 'Email', sms: 'SMS', chat: 'Chat', web: 'Web' };

const reduced = matchMedia('(prefers-reduced-motion: reduce)');
const root = document.getElementById('ap-app');
const statusEl = document.getElementById('ap-status');
const state = { industry: null, pains: new Set(), volume: null, team: null, notes: '' };
let industries = [];
let started = false;
let resultsFiredFor = null;

// analytics.js keeps gtag private; gtag.js reads queued `arguments` objects from dataLayer, and its consent mode still applies.
function dlPush() { window.dataLayer.push(arguments); }
const track = (name, params) => {
  if (typeof gtag === 'function') gtag('event', name, params);
  else if (Array.isArray(window.dataLayer)) dlPush('event', name, params);
};

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else n.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids) if (k) n.append(k);
  return n;
}

// ---------------------------------------------------------------- ranking
function rank(industry, painIds, volumeId) {
  const high = !!VOLUMES.find((v) => v.id === volumeId && v.high);
  return industry.automations
    .map((a, i) => {
      const matched = a.pains.filter((p) => painIds.has(p));
      const volumeHit = high && a.channels.some((c) => c === 'voice' || c === 'whatsapp');
      const total = a.score + PAIN_BONUS * matched.length + (volumeHit ? VOLUME_BONUS : 0);
      return { a, matched, volumeHit, total, i };
    })
    .sort((x, y) => y.total - x.total || y.a.score - x.a.score || x.i - y.i);
}

// ---------------------------------------------------------------- url state
function writeUrl() {
  const q = new URLSearchParams();
  if (state.industry) q.set('industry', state.industry.id);
  if (state.pains.size) q.set('pains', [...state.pains].join(','));
  if (state.volume) q.set('volume', state.volume);
  if (state.team) q.set('team', state.team);
  const s = q.toString();
  history.replaceState(null, '', location.pathname + (s ? '?' + s : ''));
}

function readUrl() {
  const q = new URLSearchParams(location.search);
  const ind = industries.find((i) => i.id === q.get('industry'));
  if (!ind) return;
  state.industry = ind;
  const valid = new Set(ind.pains.map((p) => p.id));
  const wanted = (q.get('pains') || '').split(',');
  if (wanted.includes(NOT_SURE)) state.pains = new Set([NOT_SURE]);
  else state.pains = new Set(wanted.filter((p) => valid.has(p)));
  if (VOLUMES.some((v) => v.id === q.get('volume'))) state.volume = q.get('volume');
  if (TEAMS.some((t) => t.id === q.get('team'))) state.team = q.get('team');
}

// ---------------------------------------------------------------- steps
const sections = {};
function section(id, num, title, hint) {
  const h = el('h2', { id: 'ap-h-' + id, tabindex: '-1', text: title });
  const s = el('section', { class: 'ap-step', id: 'ap-s-' + id, 'aria-labelledby': 'ap-h-' + id, hidden: true },
    el('span', { class: 'ap-num', text: num }), h, hint ? el('p', { class: 'ap-hint', text: hint }) : null);
  const body = el('div');
  s.append(body);
  sections[id] = { s, h, body };
  return s;
}

function reveal(id, focus) {
  const { s, h } = sections[id];
  const wasHidden = s.hidden;
  s.hidden = false;
  if (focus && wasHidden) {
    s.scrollIntoView({ behavior: reduced.matches ? 'auto' : 'smooth', block: 'start' });
    h.focus({ preventScroll: true });
  }
}

function industryButton(ind, card) {
  const b = el('button', { type: 'button', class: card ? 'ap-card-btn' : 'ap-chip', 'aria-pressed': String(state.industry === ind), 'data-industry': ind.id });
  if (card) b.append(el('strong', { text: ind.name }), el('span', { text: ind.group }));
  else b.textContent = ind.name;
  b.addEventListener('click', () => pickIndustry(ind));
  return b;
}

function buildIndustryStep() {
  const body = sections.industry.body;
  body.replaceChildren();
  const featured = industries.filter((i) => i.featured);
  const others = industries.filter((i) => !i.featured);
  body.append(el('div', { class: 'ap-grid' }, ...featured.map((i) => industryButton(i, true))));

  const search = el('input', { type: 'search', class: 'ap-search', id: 'ap-search', placeholder: 'Search industries', autocomplete: 'off', 'aria-label': 'Search other industries' });
  const list = el('div', { id: 'ap-other-list' });
  const draw = () => {
    const term = search.value.trim().toLowerCase();
    list.replaceChildren();
    const groups = new Map();
    for (const i of others) {
      if (term && !(i.name + ' ' + i.group).toLowerCase().includes(term)) continue;
      if (!groups.has(i.group)) groups.set(i.group, []);
      groups.get(i.group).push(i);
    }
    if (!groups.size) list.append(el('p', { class: 'ap-empty', text: 'No match. Try a shorter word, or pick the closest industry.' }));
    for (const [g, items] of [...groups].sort((a, b) => a[0].localeCompare(b[0]))) {
      list.append(el('div', { class: 'ap-group' }, el('h3', { text: g }), el('div', { class: 'ap-chips' }, ...items.map((i) => industryButton(i, false)))));
    }
  };
  search.addEventListener('input', draw);
  draw();
  const more = el('details', { class: 'ap-more', id: 'ap-other', open: !!(state.industry && !state.industry.featured) },
    el('summary', { text: 'Other industries (' + others.length + ')' }),
    el('div', { class: 'ap-more-body' }, el('div', { class: 'ap-field' }, search), list));
  body.append(more);
}

function refreshIndustryButtons() {
  for (const b of root.querySelectorAll('[data-industry]')) b.setAttribute('aria-pressed', String(state.industry && b.dataset.industry === state.industry.id));
}

function buildPainStep() {
  const { body } = sections.pains;
  body.replaceChildren();
  if (!state.industry) return;
  const chips = el('div', { class: 'ap-chips', role: 'group', 'aria-labelledby': 'ap-h-pains' });
  const all = [...state.industry.pains, { id: NOT_SURE, label: 'Not sure yet' }];
  for (const p of all) {
    const b = el('button', { type: 'button', class: 'ap-chip', 'aria-pressed': String(state.pains.has(p.id)), 'data-pain': p.id, text: p.label });
    b.addEventListener('click', () => togglePain(p.id));
    chips.append(b);
  }
  body.append(chips);
}

function buildSizeStep() {
  const { body } = sections.size;
  body.replaceChildren();
  if (!state.industry) return;
  const unit = state.industry.volume_unit;
  const mk = (list, key, legend) => {
    const fs = el('fieldset', { class: 'ap-fs' }, el('legend', { class: 'ap-legend', text: legend }));
    const row = el('div', { class: 'ap-chips' });
    for (const o of list) {
      const b = el('button', { type: 'button', class: 'ap-chip', 'aria-pressed': String(state[key] === o.id), text: o.label });
      b.dataset[key] = o.id;
      b.addEventListener('click', () => pickSize(key, o.id));
      row.append(b);
    }
    fs.append(row);
    return fs;
  };
  body.append(
    mk(VOLUMES, 'volume', 'Roughly how many ' + unit + ' a month?'),
    mk(TEAMS, 'team', 'How big is the team that handles them? (optional)'),
    el('div', { class: 'ap-field' },
      el('label', { for: 'ap-notes', text: 'Anything specific? (optional)' }),
      el('textarea', { id: 'ap-notes', class: 'ap-textarea', maxlength: String(NOTES_MAX), placeholder: 'A process, a system, a language you need.' }),
      el('div', { class: 'ap-count', id: 'ap-notes-count', 'aria-hidden': 'true', text: '0 / ' + NOTES_MAX })));
  const ta = body.querySelector('#ap-notes');
  ta.value = state.notes;
  ta.addEventListener('input', () => {
    state.notes = ta.value.slice(0, NOTES_MAX);
    body.querySelector('#ap-notes-count').textContent = state.notes.length + ' / ' + NOTES_MAX;
  });
}

// ---------------------------------------------------------------- results
function channelTags(channels) {
  return el('ul', { class: 'ap-meta', 'aria-label': 'Channels' }, ...channels.map((c) => el('li', { class: 'ap-tag', text: CHANNEL_LABEL[c] || c })));
}

function whyText(r, painLabels) {
  const bits = [];
  if (r.matched.length) bits.push('Matches: ' + r.matched.map((p) => painLabels.get(p)).join(', '));
  if (r.volumeHit) bits.push('Voice and WhatsApp handle high volume well');
  return bits.length ? bits.join('. ') + '.' : 'Ranked by our default order for ' + state.industry.name + '.';
}

function resultCard(r, n, painLabels, compact) {
  const a = r.a;
  const card = el('article', { class: 'ap-result' + (compact ? ' ap-compact' : ''), 'data-automation': a.id },
    el('span', { class: 'ap-rank', text: String(n).padStart(2, '0') }),
    el('h3', { text: a.title }),
    el('p', { text: a.what_it_does }),
    el('p', { class: 'ap-why', text: whyText(r, painLabels) }),
    channelTags(a.channels),
    el('p', { class: 'ap-effort', text: 'Effort: ' + a.effort }));
  if (!compact) card.append(el('div', { class: 'ap-first' }, el('b', { text: 'First step' }), a.first_step));
  if (a.page_url) {
    const link = el('a', { class: 'ap-link', href: a.page_url, text: 'See it' });
    link.append(el('span', { class: 'ap-sr', text: ': ' + a.title }));
    card.append(el('p', { style: 'margin:12px 0 0' }, link));
  }
  return card;
}

function buildResults() {
  const { body } = sections.results;
  body.replaceChildren();
  if (!state.industry || !state.volume) return;
  const painLabels = new Map(state.industry.pains.map((p) => [p.id, p.label]));
  const ranked = rank(state.industry, state.pains, state.volume);
  const top = ranked.slice(0, TOP_N);
  const rest = ranked.slice(TOP_N);
  body.append(el('div', { class: 'ap-results', id: 'ap-top' }, ...top.map((r, i) => resultCard(r, i + 1, painLabels, false))));
  if (rest.length) {
    body.append(el('details', { class: 'ap-more', id: 'ap-rest' },
      el('summary', { text: 'More ideas for ' + state.industry.name + ' (' + rest.length + ')' }),
      el('div', { class: 'ap-more-body' }, el('div', { class: 'ap-more-list' }, ...rest.map((r, i) => resultCard(r, i + TOP_N + 1, painLabels, true))))));
  }
  body.append(buildCta(top));
  statusEl.textContent = 'Showing ' + ranked.length + ' ideas for ' + state.industry.name + ', top ' + top.length + ' first.';
}

// ---------------------------------------------------------------- email step
function field(id, label, type, opts) {
  const o = opts || {};
  return el('div', { class: 'ap-field' + (o.wide ? ' ap-wide' : '') },
    el('label', { for: id, text: label }),
    el('input', { id, name: id, class: 'ap-input', type, required: o.required, autocomplete: o.auto, maxlength: o.max, inputmode: o.inputmode }));
}

function buildCta(top) {
  const form = el('form', { class: 'ap-form', id: 'ap-form', novalidate: true },
    field('ap-name', 'Name', 'text', { required: true, auto: 'name', max: 120 }),
    field('ap-email', 'Work email', 'email', { required: true, auto: 'email', max: 160 }),
    field('ap-company', 'Company name (optional)', 'text', { auto: 'organization', max: 160 }),
    field('ap-website', 'Company website', 'text', { required: true, auto: 'url', max: 200, inputmode: 'url' }),
    el('div', { class: 'ap-hp', 'aria-hidden': 'true' }, el('label', { for: 'ap-hp', text: 'Leave this empty' }), el('input', { id: 'ap-hp', name: 'hp', type: 'text', tabindex: '-1', autocomplete: 'off' })));
  const consent = el('p', { class: 'ap-consent ap-wide' }, 'By sending this you agree we may use these details to reply about your plan, as described in our ');
  consent.append(el('a', { href: '/privacy.html', text: 'privacy policy' }), '.');
  const btn = el('button', { type: 'submit', class: 'ap-btn', text: 'Send my details' });
  const msg = el('p', { class: 'ap-msg ap-wide', id: 'ap-form-msg', role: 'status' });
  form.append(consent, el('div', { class: 'ap-wide' }, btn), msg);
  form.addEventListener('submit', (e) => onSubmit(e, top, btn, msg));
  return el('section', { class: 'ap-cta', id: 'ap-cta', 'aria-labelledby': 'ap-cta-h' },
    el('h2', { id: 'ap-cta-h', text: 'Want this turned into a plan for your business?' }),
    el('p', { class: 'ap-hint', text: 'Leave your details and the team will follow up with a custom plan built on this list.' }),
    form);
}

// Body shape matches assets/donna/hero.js and oracle-lead.php.
async function submitPlanRequest(payload) {
  const lead = {
    name: payload.name,
    email: payload.email,
    company: payload.company,
    website: payload.website,
    industry: payload.industry,
    problem: payload.problem,
    volume: payload.volume,
  };
  try {
    const res = await fetch(LEAD_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lead, next: ['plan'], hp: payload.hp || '' }),
    });
    const body = await res.json().catch(() => ({}));
    return res.ok && body.ok === true;
  } catch {
    return false;
  }
}

function buildPayload(form, top) {
  const v = (id) => form.querySelector('#' + id).value.trim();
  const volume = VOLUMES.find((x) => x.id === state.volume);
  const team = TEAMS.find((x) => x.id === state.team);
  const labels = new Map(state.industry.pains.map((p) => [p.id, p.label]));
  const pains = [...state.pains].map((p) => (p === NOT_SURE ? 'Not sure yet' : labels.get(p)));
  const lines = ['Automation Plan Generator.', 'Pains: ' + (pains.length ? pains.join('; ') : 'none selected') + '.'];
  if (team) lines.push('Team: ' + team.label + '.');
  if (state.notes.trim()) lines.push('Notes: ' + state.notes.trim());
  lines.push('Top ideas shown: ' + top.map((r) => r.a.title).join('; ') + '.');
  return {
    name: v('ap-name'), email: v('ap-email'), company: v('ap-company'), website: v('ap-website'),
    industry: state.industry.name,
    volume: volume.label + ' ' + state.industry.volume_unit + ' a month',
    problem: lines.join(' '),
    hp: v('ap-hp'),
  };
}

async function onSubmit(e, top, btn, msg) {
  e.preventDefault();
  const form = e.currentTarget;
  msg.className = 'ap-msg ap-wide';
  const email = form.querySelector('#ap-email');
  const missing = ['ap-name'].filter((id) => !form.querySelector('#' + id).value.trim());
  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim());
  const siteOk = WEBSITE_RE.test(form.querySelector('#ap-website').value.trim());
  if (missing.length || !emailOk || !siteOk) {
    msg.classList.add('ap-bad');
    msg.textContent = 'Add your name, a valid work email and your company website (acme.com is fine).';
    form.querySelector('#' + (missing[0] || (emailOk ? 'ap-website' : 'ap-email'))).focus();
    return;
  }
  btn.disabled = true;
  msg.textContent = 'Sending...';
  const ok = await submitPlanRequest(buildPayload(form, top));
  btn.disabled = false;
  if (ok) {
    msg.classList.add('ap-ok');
    msg.textContent = 'Got it. The team has your details and your answers.';
    track('generate_lead', { method: 'planner' });
    btn.hidden = true;
  } else {
    msg.classList.add('ap-bad');
    msg.textContent = 'That did not go through. Try again, or email hello@voxdonna.com.';
  }
}

// ---------------------------------------------------------------- actions
function sync(focusNext) {
  const ind = state.industry;
  const hasPains = ind && state.pains.size > 0;
  if (ind) reveal('pains', focusNext === 'pains');
  if (hasPains) reveal('size', focusNext === 'size');
  const done = hasPains && state.volume;
  if (!done) sections.results.s.hidden = true;
  else {
    buildResults();
    reveal('results', focusNext === 'results');
    const key = ind.id;
    if (resultsFiredFor !== key) { resultsFiredFor = key; track('planner_results', { industry_id: ind.id }); }
  }
  writeUrl();
}

function pickIndustry(ind) {
  if (!started) { started = true; track('planner_start'); }
  const changed = state.industry !== ind;
  state.industry = ind;
  if (changed) { state.pains = new Set(); state.volume = null; state.team = null; state.notes = ''; }
  refreshIndustryButtons();
  if (changed) { buildPainStep(); buildSizeStep(); sections.size.s.hidden = true; sections.results.s.hidden = true; }
  sections.pains.h.textContent = 'What hurts most in ' + ind.name + '?';
  sync('pains');
}

function togglePain(id) {
  if (id === NOT_SURE) state.pains = state.pains.has(NOT_SURE) ? new Set() : new Set([NOT_SURE]);
  else {
    state.pains.delete(NOT_SURE);
    if (state.pains.has(id)) state.pains.delete(id); else state.pains.add(id);
  }
  for (const b of sections.pains.body.querySelectorAll('[data-pain]')) b.setAttribute('aria-pressed', String(state.pains.has(b.dataset.pain)));
  if (!state.pains.size) { sections.size.s.hidden = true; sections.results.s.hidden = true; }
  sync(state.pains.size && !state.volume ? 'size' : null);
}

function pickSize(key, id) {
  state[key] = state[key] === id && key === 'team' ? null : id;
  for (const b of sections.size.body.querySelectorAll('[data-' + key + ']')) b.setAttribute('aria-pressed', String(b.dataset[key] === state[key]));
  sync(key === 'volume' ? 'results' : null);
}

function restart() {
  state.industry = null; state.pains = new Set(); state.volume = null; state.team = null; state.notes = '';
  for (const k of ['pains', 'size', 'results']) { sections[k].s.hidden = true; sections[k].body.replaceChildren(); }
  buildIndustryStep();
  statusEl.textContent = '';
  resultsFiredFor = null;
  writeUrl();
  sections.industry.s.scrollIntoView({ behavior: reduced.matches ? 'auto' : 'smooth', block: 'start' });
  sections.industry.h.focus({ preventScroll: true });
}

// ---------------------------------------------------------------- boot
function build() {
  root.replaceChildren(
    section('industry', 'Step 1 of 3', 'What kind of business do you run?', 'Pick the closest match. The list that follows is written for that industry.'),
    section('pains', 'Step 2 of 3', 'What hurts most?', 'Pick everything that applies. "Not sure yet" is a fine answer.'),
    section('size', 'Step 3 of 3', 'How busy are you?', 'A rough range is enough. It nudges voice and WhatsApp ideas up when volume is high.'),
    section('results', 'Your plan', 'What to automate first', null));
  sections.results.h.textContent = 'What to automate first';
  sections.industry.s.hidden = false;
  const again = el('button', { type: 'button', class: 'ap-restart', text: 'Start over' });
  again.addEventListener('click', restart);
  sections.results.s.append(el('p', null, again));
  buildIndustryStep();
  readUrl();
  if (state.industry) {
    refreshIndustryButtons();
    buildPainStep(); buildSizeStep();
    sections.pains.h.textContent = 'What hurts most in ' + state.industry.name + '?';
    sync(null);
  }
}

fetch(DATA_URL)
  .then((r) => { if (!r.ok) throw new Error(String(r.status)); return r.json(); })
  .then((d) => {
    if (!d || !Array.isArray(d.industries) || !d.industries.length) throw new Error('empty');
    industries = d.industries;
    build();
  })
  .catch(() => {
    root.replaceChildren(el('p', { class: 'ap-notice', text: 'The industry list could not load. Refresh the page, or talk to the team directly.' }));
  });
})();
