// "Continue with Donna": a small fixed pill on every page except the homepage, shown only to visitors who have already
// talked to her this tab. One tap resumes the conversation (saved fields + what she just opened). No auto-start: browsers
// need a user gesture for audio. Cold visitors cost one sessionStorage read; nothing else is fetched.
//
// Everything is imported dynamically with this file's own ?v= so build-chrome.py's single content hash busts all of it.
const V = new URL(import.meta.url).search;
const LEAD_KEY = 'donna.lead.v1';
const talked = () => { try { return JSON.parse(sessionStorage.getItem(LEAD_KEY)).talked === true; } catch { return false; } };

if (talked() && !document.querySelector('.donna-hero')) boot();

async function boot() {
  const [{ connect }, mem] = await Promise.all([import('./engine.js' + V), import('./memory.js' + V)]);
  const MOCK = new URLSearchParams(location.search).get('engine') === 'mock';
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const NAV_SECONDS = 3;
  const NAV_SPEECH_WAIT_MS = 2500;

  const css = document.createElement('link');
  css.rel = 'stylesheet';
  css.href = new URL('./dock.css' + V, import.meta.url).href;
  const cssReady = new Promise((done) => { css.onload = css.onerror = done; setTimeout(done, 3000); });
  document.head.append(css);

  const ICON = (d) => `<svg viewBox="0 0 24 24" aria-hidden="true">${d}</svg>`;
  const dock = document.createElement('div');
  dock.className = 'vd-dock';
  dock.setAttribute('role', 'region');
  dock.setAttribute('aria-label', 'Donna, voice guide');
  dock.dataset.state = 'idle';
  dock.innerHTML = `
    <button class="vd-dock-main" type="button"><span class="vd-dock-orb" aria-hidden="true"></span><span class="vd-dock-label">Continue with Donna</span></button>
    <div class="vd-dock-live" hidden>
      <span class="vd-dock-orb" aria-hidden="true"></span>
      <p class="vd-dock-cap" aria-hidden="true"></p>
      <button class="vd-dock-btn vd-dock-sound" type="button" aria-pressed="true" aria-label="Donna's sound is on">${ICON('<path d="M4 9v6h4l5 4V5L8 9H4z"/><path class="on" d="M16.5 8.5a5 5 0 0 1 0 7"/><path class="off" d="M17 9l5 6M22 9l-5 6"/>')}</button>
      <button class="vd-dock-btn vd-dock-end" type="button" aria-label="End conversation">${ICON('<path d="M6 6l12 12M18 6L6 18"/>')}<span>End</span></button>
    </div>
    <p class="vd-dock-sr" role="status" aria-live="polite"></p>`;
  const $ = (sel) => dock.querySelector(sel);
  const main = $('.vd-dock-main');
  const live = $('.vd-dock-live');
  const capEl = $('.vd-dock-cap');
  const label = $('.vd-dock-label');
  const sr = $('.vd-dock-sr');
  const soundBtn = $('.vd-dock-sound');

  const st = { eng: null, session: 0, muted: false, donnaFinal: true, donnaLine: '' };
  const nav = { url: null, pending: false, timer: null, waitTimer: null, sawSpeaking: false };

  const announce = (text) => { sr.textContent = ''; sr.textContent = text; };
  const setCap = (text, who = 'donna') => { capEl.textContent = text; capEl.dataset.who = who; };
  const setLevel = (l) => dock.style.setProperty('--lvl', reduced.matches ? 0 : l.toFixed(3));

  function setState(state, text) {
    dock.dataset.state = state;
    const isLive = state === 'live';
    live.hidden = !isLive;
    main.hidden = isLive;
    main.setAttribute('aria-busy', String(state === 'connecting'));
    if (text) label.textContent = text;
  }

  // ------------------------------------------------------------ navigation hand-off (same rules as the hero)
  function cancelNav() {
    clearInterval(nav.timer);
    clearTimeout(nav.waitTimer);
    Object.assign(nav, { url: null, pending: false, timer: null, waitTimer: null, sawSpeaking: false });
  }

  function goNow(url) {
    cancelNav();
    const target = new URL(url, location.href);
    if (target.pathname === location.pathname && target.origin === location.origin) {
      // Same page: keep the call going and jump to the anchor (demos.html listens for hashchange and highlights the card).
      if (target.hash && target.hash !== location.hash) location.hash = target.hash;
      return;
    }
    endSession();
    location.assign(target.href);
  }

  function armNav() {
    if (!nav.pending || nav.timer) return;
    clearTimeout(nav.waitTimer);
    const url = nav.url;
    let left = NAV_SECONDS;
    const tick = () => setCap(`Taking you there in ${left}…`);
    tick();
    nav.timer = setInterval(() => { left -= 1; if (left <= 0) goNow(url); else tick(); }, 1000);
  }

  function onNavigate(route, url, demo) {
    mem.rememberNavigation(route, demo);
    cancelNav();
    if (!url) return;
    nav.url = url;
    nav.pending = true;
    nav.waitTimer = setTimeout(() => { if (!nav.sawSpeaking) armNav(); }, NAV_SPEECH_WAIT_MS);
  }

  // ------------------------------------------------------------ lead (a resumed intake can still finish here)
  async function onIntakeComplete(lead, rawNext) {
    const next = Array.isArray(rawNext) ? ['plan', 'demo', 'call'].filter((n) => rawNext.includes(n)) : [];
    const full = Object.fromEntries(mem.FIELD_KEYS.map((k) => [k, (lead && lead[k]) || (mem.readStore().fields || {})[k] || '']));
    mem.writeStore({ fields: {}, completed: true });
    const ok = MOCK ? true : await mem.sendLead(full, next);
    if (ok && !MOCK) mem.track('generate_lead', { method: 'ask_donna' });
    if (!ok) announce('That did not reach the team. Use the contact form further down.');
  }

  function onField(field, value) {
    const store = mem.readStore();
    if (store.completed || !mem.FIELD_KEYS.includes(field)) return;
    mem.writeStore({ fields: { ...(store.fields || {}), [field]: String(value ?? '') } });
  }

  // ------------------------------------------------------------ session
  // Live as soon as the mic is open or the relay first reports a state, whichever comes first.
  function goLive() {
    if (!st.eng || dock.dataset.state === 'live') return;
    setState('live');
    if (!capEl.textContent) setCap('Listening…');
    announce('Connected. Donna is listening.');
  }

  function handlersFor(session) {
    const guard = (fn) => (...a) => { if (session === st.session) fn(...a); };
    return {
      onState: guard((s) => {
        goLive();
        if (s === 'thinking') setCap('Thinking…');
        if (!nav.pending) return;
        if (s === 'speaking') nav.sawSpeaking = true;
        else if (s === 'listening' && nav.sawSpeaking) armNav();
      }),
      onAudioLevel: guard(setLevel),
      onCaption: guard(({ who, text, final }) => {
        if (who === 'user') {
          if (text) { cancelNav(); setCap(text, 'user'); }
          return;
        }
        if (text) {
          st.donnaLine = st.donnaFinal ? text : st.donnaLine + text;
          st.donnaFinal = false;
          setCap(st.donnaLine);
        }
        if (final) { st.donnaFinal = true; if (st.donnaLine) announce(st.donnaLine); }
      }),
      onField: guard(onField),
      onNavigate: guard(onNavigate),
      onIntakeComplete: guard((lead, next) => { onIntakeComplete(lead, next); }),
      onError: guard(({ code }) => {
        endSession(code === 'mic_denied' ? 'Microphone is off. Allow it, then tap again.' : 'The line dropped. Tap to try again.');
      }),
      onEnded: guard((reason) => {
        endSession(reason === 'silence' ? 'Quiet for 10 seconds. Tap to talk again.' : 'Talk to Donna again');
      }),
    };
  }

  function endSession(text = 'Talk to Donna again') {
    st.session += 1; // drops late events from the old session
    const eng = st.eng;
    st.eng = null;
    cancelNav();
    try { eng?.stop(); } catch { /* already closed */ }
    setLevel(0);
    st.donnaFinal = true;
    st.donnaLine = '';
    setState('idle', text);
    if (text !== 'Talk to Donna again') announce(text);
  }

  // A demo call on the page (demos.html cards) owns the microphone. Its end button is the accessible stop handle.
  function demoCallActive() {
    const card = document.querySelector('.demo-card.is-active');
    if (!card) return false;
    card.querySelector('.demo-card-btn-end')?.click();
    return !!document.querySelector('.demo-card.is-active'); // still active: the demo is mid-connect and cannot be stopped yet
  }

  async function start() {
    if (st.eng) return;
    if (demoCallActive()) {
      label.textContent = 'End the demo call first';
      announce('End the demo call first');
      setTimeout(() => { if (dock.dataset.state === 'idle') label.textContent = 'Continue with Donna'; }, 4000);
      return;
    }
    mem.markTalked();
    st.session += 1;
    setState('connecting', 'Connecting…');
    capEl.textContent = '';
    const eng = connect(handlersFor(st.session), { resume: mem.savedFields(), context: mem.resumeContext() });
    st.eng = eng;
    eng.setMuted(st.muted);
    const ok = await eng.startMic();
    if (ok && st.eng === eng) goLive(); // on failure, onError (mic_denied) already reset the pill
  }

  main.addEventListener('click', start);
  $('.vd-dock-end').addEventListener('click', () => { endSession(); main.focus(); });
  soundBtn.addEventListener('click', () => {
    st.muted = !st.muted;
    st.eng?.setMuted(st.muted);
    soundBtn.setAttribute('aria-pressed', String(!st.muted));
    soundBtn.setAttribute('aria-label', st.muted ? "Donna's sound is off" : "Donna's sound is on");
  });
  dock.addEventListener('keydown', (e) => { if (e.key === 'Escape' && st.eng) { endSession(); main.focus(); } });

  // One mic at a time: pressing a demo card's start/orb ends Donna's session first (capture phase, before the card's handler).
  document.addEventListener('click', (e) => {
    if (st.eng && e.target.closest?.('.demo-card-orb-wrap, .demo-card-btn-start')) endSession();
  }, true);
  addEventListener('pagehide', () => endSession());
  document.addEventListener('visibilitychange', () => { if (document.hidden && st.eng) endSession(); });

  await cssReady; // appending earlier flashes an unstyled button
  document.body.append(dock);
}
