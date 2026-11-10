// Engine layer for the Ask Donna hero. ?engine=mock (default) | relay.
//
// connect(handlers, { relay, resume, context }) -> { sendText(text), editField(field, value), stop(), startMic(), setMuted(on) }
//   handlers: onState(state)            state: "listening" | "thinking" | "speaking"
//             onAudioLevel(0..1)
//             onCaption({ who, text, final })   text is a DELTA to append; { text: "", final: true } closes that speaker's turn
//             onField(field, value)
//             onNavigate(route, url, demo)   demo: catalogue slug when a demo was deep-linked
//             onIntakeComplete(lead, next)   next: subset of ["plan","demo","call"]
//             onError({ code, message })
//             onEnded(reason)
// startMic() and setMuted() are additions to the brief's contract: the session opens without the mic,
// and the mic is only captured when the visitor presses "Talk to Donna".
import { makeAnalyser, readLevel, int16ToB64, b64ToInt16, startMicPcm, PcmPlayer } from './audio.js?v=20261106g';

export const ROUTES = {
  demos: '/demos.html',
  pricing: '/ai-voice-agents.html#pricing',
  voice_agents: '/ai-voice-agents.html',
  jewellers: '/jewellers.html',
  ecommerce: '/ai-agents-for-ecommerce.html',
  book_call: '#contact',
  book_meeting: 'https://tidycal.com/rajsuyash/discovery-call-for-ai-voice-agent',
};

const DEFAULT_RELAY = 'https://oracle-relay-459772152494.us-central1.run.app';

export function connect(handlers, opts = {}) {
  const params = new URLSearchParams(location.search);
  const kind = params.get('engine') === 'mock' ? 'mock' : 'relay';
  const relay = params.get('relay') || opts.relay || DEFAULT_RELAY;
  return kind === 'relay' ? relayEngine(handlers, relay, opts.resume, opts.context) : mockEngine(handlers, opts.resume, opts.context);
}

// ---------------------------------------------------------------- mock

const LEAD = {
  name: 'Priya Nair',
  email: 'priya@lumierejewels.example',
  company: 'Lumière Jewels',
  website: 'lumierejewels.example',
  industry: 'Jewellery retail',
  problem: 'Missed calls after 6pm, team buried in booking enquiries',
  volume: '~200 calls a month',
};

const WORD_MS = 150;

function mockEngine(h, resume, context) {
  let timers = [];
  let level = 0;
  let state = 'listening';
  let stopped = false;
  const started = performance.now();

  const later = (ms, fn) => { timers.push(setTimeout(() => { if (!stopped) fn(); }, ms)); };
  const setState = (s) => { state = s; h.onState(s); };
  const levelTimer = setInterval(() => {
    const t = (performance.now() - started) / 1000;
    const target = state === 'speaking' ? 0.4 + 0.4 * Math.abs(Math.sin(t * 9)) * (0.6 + Math.random() * 0.4)
      : state === 'listening' && micOn ? 0.08 + 0.3 * Math.max(0, Math.sin(t * 5)) * Math.random()
      : 0;
    level += (target - level) * 0.35;
    h.onAudioLevel(level);
  }, 50);
  let micOn = false;

  // Streams `text` word by word starting at `at`; returns the time it finishes.
  function utter(at, who, text) {
    const words = text.split(' ');
    words.forEach((w, i) => later(at + i * WORD_MS, () => h.onCaption({ who, text: i ? ' ' + w : w, final: false })));
    later(at + words.length * WORD_MS, () => h.onCaption({ who, text: '', final: true }));
    return at + words.length * WORD_MS;
  }
  function fill(at, fields, gap = 950) {
    fields.forEach((f, i) => later(at + i * gap, () => h.onField(f, LEAD[f])));
    return at + fields.length * gap;
  }

  function script() {
    let t = 400;
    later(t, () => setState('speaking'));
    t = utter(t, 'donna', resume?.name
      ? `Welcome back, ${resume.name.split(' ')[0]}. ${context?.lastDemo ? 'How did that demo land?' : 'I’ve kept what you told me. Pick up where we left off.'}`
      : 'Hello, I’m Donna. Tell me what’s eating your week and I’ll tell you what to automate first.');
    t += 300; later(t, () => setState('listening'));
    t += 700;
    t = utter(t, 'user', 'We miss half our calls after six. My team spends the day on booking enquiries.');
    t += 300; later(t, () => setState('thinking'));
    t += 900; later(t, () => setState('speaking'));
    const said = utter(t, 'donna', 'After-hours calls. That’s the leak. Every missed one is a booking walking to someone else.');
    fill(t + 500, ['problem', 'volume', 'industry']);
    t = said + 400;
    t = utter(t, 'donna', 'Proof. Here’s a jeweller’s line, handled at two in the morning.');
    later(t - 700, () => h.onNavigate('jewellers', ROUTES.jewellers));
    t += 400; later(t, () => setState('listening'));
    t += 800;
    const heard = utter(t, 'user', 'I’m Priya Nair, priya@lumierejewels.example. Lumière Jewels, lumierejewels.example.');
    fill(t + 700, ['name', 'email', 'company', 'website'], 1000);
    t = heard + 800; later(t, () => setState('thinking'));
    t += 800; later(t, () => setState('speaking'));
    t = utter(t, 'donna', 'Got it, Priya. Fix the after-hours calls first. Want me to open your automation plan, show a live demo, or book a call with the team?');
    t += 300; later(t, () => setState('listening'));
    t += 700;
    t = utter(t, 'user', 'Open the plan.');
    t += 300; later(t, () => setState('thinking'));
    t += 800; later(t, () => setState('speaking'));
    t = utter(t, 'donna', 'Done. Opening your automation plan.');
    later(t + 300, () => h.onIntakeComplete({ ...LEAD }, ['plan']));
    later(t + 1500, () => { setState('listening'); h.onEnded('intake_complete'); stop(); });
  }

  function reply(text) {
    const q = text.toLowerCase();
    const route = /pric|cost|plan|how much/.test(q) ? 'pricing'
      : /demo|hear|show/.test(q) ? 'demos'
      : /jewel/.test(q) ? 'jewellers'
      : /shop|store|ecommerce|e-commerce/.test(q) ? 'ecommerce'
      : /book|call me|talk to/.test(q) ? 'book_call'
      : /agent|automate|first/.test(q) ? 'voice_agents'
      : null;
    const lines = {
      pricing: 'Pricing. A setup fee, then calls at a fixed rate. No surprises.',
      demos: 'Demos. Pick one and hear it handle a real call.',
      jewellers: 'Jewellers. Gift advice, appointments, after-hours.',
      ecommerce: 'Ecommerce. Order status and returns, answered before the customer sighs.',
      book_call: 'Booking a call. Pick a time and I’ll hold it.',
      voice_agents: 'Start with the calls you miss. That’s where the money leaks.',
    };
    timers.forEach(clearTimeout); timers = [];
    h.onCaption({ who: 'user', text, final: false });
    h.onCaption({ who: 'user', text: '', final: true });
    later(250, () => setState('thinking'));
    later(900, () => {
      // Same order as the live relay: navigate, then an immediate listening, then she speaks.
      if (route) { h.onNavigate(route, ROUTES[route]); setState('listening'); }
      later(route ? 400 : 0, () => {
        setState('speaking');
        const end = utter(0, 'donna', route ? lines[route] : 'Tell me the problem. Calls, bookings, follow-up. I’ll take it from there.');
        later(end + 300, () => setState('listening'));
      });
    });
  }

  function stop() {
    if (stopped) return;
    stopped = true;
    clearInterval(levelTimer);
    timers.forEach(clearTimeout);
    timers = [];
    h.onAudioLevel(0);
  }

  return {
    startMic: async () => { micOn = true; setState('listening'); later(0, script); return true; },
    setMuted() {},
    sendText: reply,
    editField() {}, // ponytail: mock keeps no state; the relay owns the lead.
    stop,
  };
}

// ---------------------------------------------------------------- relay

function relayEngine(h, base, resume, context) {
  const root = base.replace(/\/$/, '');
  const outbox = [];
  let ws = null;
  let ctx = null;
  let gain = null;
  let outAnalyser = null;
  let micAnalyser = null;
  let player = null;
  let micStop = null;
  let micStream = null;
  let raf = 0;
  let state = 'listening';
  let muted = false;
  let closed = false;
  let ended = false;

  const send = (obj) => {
    const raw = JSON.stringify(obj);
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(raw);
    else if (!closed) outbox.push(raw);
  };

  function fail(code, message) {
    if (closed) return;
    h.onError({ code, message });
    stop();
  }

  function finish(reason) {
    if (ended) return;
    ended = true;
    h.onEnded(reason);
    stop();
  }

  function levelLoop() {
    if (closed) return;
    const a = state === 'speaking' ? outAnalyser : micAnalyser;
    h.onAudioLevel(a ? readLevel(a) : 0);
    raf = requestAnimationFrame(levelLoop);
  }

  function onMessage(ev) {
    let m;
    try { m = JSON.parse(ev.data); } catch { return; }
    switch (m.type) {
      case 'state': state = m.state; h.onState(m.state); break;
      case 'audio': if (player && m.data) player.push(b64ToInt16(m.data)); break;
      case 'interrupted': if (player) player.flush(); break;
      case 'caption': h.onCaption({ who: m.who, text: m.text, final: !!m.final }); break;
      case 'field': h.onField(m.field, m.value); break;
      case 'navigate': h.onNavigate(m.route, m.url, m.demo); break;
      case 'intake_complete': h.onIntakeComplete(m.lead || {}, Array.isArray(m.next) ? m.next : []); break;
      case 'error': fail(m.code || 'relay_error', m.message || 'The relay reported an error.'); break;
      case 'ended': finish(m.reason || 'ended'); break;
      default: break; // "ready" and unknown types carry nothing the UI needs
    }
  }

  function setupAudio() {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    ctx = new AC();
    ctx.resume?.();
    gain = ctx.createGain();
    outAnalyser = makeAnalyser(ctx);
    outAnalyser.connect(gain);
    gain.connect(ctx.destination);
    player = new PcmPlayer(ctx, [outAnalyser], 24000);
  }

  async function open() {
    try {
      const res = await fetch(root + '/ticket', { method: 'POST' });
      if (!res.ok) throw new Error('ticket ' + res.status);
      const { ticket, wsUrl } = await res.json();
      if (!ticket || !wsUrl) throw new Error('bad ticket');
      if (closed) return;
      ws = new WebSocket(wsUrl); // wsUrl already carries ?ticket=
      // Must be the first frame: the relay holds its greeting briefly so it can mention what is already saved.
      ws.onopen = () => { if (resume || context) ws.send(JSON.stringify({ type: 'resume', ...(resume && { fields: resume }), ...(context && { context }) })); while (outbox.length) ws.send(outbox.shift()); };
      ws.onmessage = onMessage;
      ws.onerror = () => fail('relay_unreachable', 'The line to Donna dropped.');
      ws.onclose = () => finish('closed');
    } catch {
      fail('relay_unreachable', 'Could not reach the relay.');
    }
  }

  function stop() {
    if (closed) return;
    closed = true;
    cancelAnimationFrame(raf);
    try { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'stop' })); } catch {}
    try { ws && ws.close(); } catch {}
    if (micStop) micStop();
    if (micStream) micStream.getTracks().forEach((t) => t.stop());
    if (player) player.flush();
    if (ctx) ctx.close().catch(() => {});
    h.onAudioLevel(0);
  }

  setupAudio();
  raf = requestAnimationFrame(levelLoop);
  open();

  return {
    async startMic() {
      if (closed) return false;
      try {
        if (!ctx) throw new Error('no audio context');
        micStream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true } });
        const src = ctx.createMediaStreamSource(micStream);
        micAnalyser = makeAnalyser(ctx);
        src.connect(micAnalyser);
        micStop = await startMicPcm(ctx, src, 16000, (i16) => {
          if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'audio', data: int16ToB64(i16) }));
        });
        return true;
      } catch {
        h.onError({ code: 'mic_denied', message: 'Microphone unavailable.' });
        return false;
      }
    },
    setMuted(on) { muted = on; if (gain) gain.gain.value = muted ? 0 : 1; },
    sendText: (text) => send({ type: 'text', text }),
    editField: (field, value) => send({ type: 'field_edit', field, value }),
    stop,
  };
}
