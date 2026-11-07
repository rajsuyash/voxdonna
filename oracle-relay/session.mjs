import WebSocket from 'ws';
import { FIELDS, TOOL_DECLARATIONS, createLead, handleToolCall, validateField } from './tools.mjs';

const MAX_TEXT = 500;
const MAX_AUDIO_B64 = 200_000;
const SETUP_TIMEOUT_MS = 15_000;
const RESUME_WAIT_MS = 400;
const SILENCE_NUDGE = '[system note: the visitor has been silent for 10 seconds. Ask in one short line if they are still there. Do not repeat earlier questions.]';
const WRAP_UP_PROMPT = 'Time is nearly up. Wrap up in one sentence and say goodbye.';

// One visitor <-> one upstream Gemini Live socket. Never logs audio, transcripts, emails or tokens.
export function startSession({ client, config, sessionId, onEnd }) {
  const startedAt = Date.now();
  const lead = createLead();
  const log = (event, extra = {}) => config.log({ event, sessionId, ...extra });

  let up = null;
  let ready = false;
  let ended = false;
  let wrapping = false;
  let state = null;
  let userOpen = false;
  let heard = ''; // visitor's latest utterance, fed to the navigate guard
  let heardClosed = true;
  let usage = null;
  let nudged = false; // one nudge per silence episode; any visitor activity resets it
  let seeded = [];
  let sawFrame = false;
  let upstreamStarted = false;
  let capTimer; let idleTimer; let graceTimer; let setupTimer; let silenceTimer; let resumeTimer;

  const toClient = (o) => { if (client.readyState === WebSocket.OPEN) client.send(JSON.stringify(o)); };
  const toUp = (o) => { if (up?.readyState === WebSocket.OPEN) up.send(JSON.stringify(o)); };
  const fail = (code, message) => toClient({ type: 'error', code, message });
  // Turn boundaries pass force=true: clients wait for a fresh "listening" after every turn, even if state never left it.
  const setState = (s, force = false) => { if (force || s !== state) { state = s; toClient({ type: 'state', state: s }); } };

  const end = (reason) => {
    if (ended) return;
    ended = true;
    [capTimer, idleTimer, graceTimer, setupTimer, silenceTimer, resumeTimer].forEach(clearTimeout);
    toClient({ type: 'ended', reason });
    log('session_end', { reason, durationMs: Date.now() - startedAt, intakeComplete: lead.completed, usage });
    try { client.close(1000, reason); } catch { /* already closed */ }
    try { up?.terminate(); } catch { /* already closed */ }
    onEnd();
  };

  // ponytail: idle = no client audio/text frames. A client that streams silence forever never idles out;
  // the front end should stop sending while muted. The hard cap still bounds the session.
  const touch = () => {
    if (wrapping || ended) return;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => end('idle'), config.idleSeconds * 1000);
  };

  // Speech-based silence: runs only while it is the visitor's turn (after Donna finishes), cleared by any visitor
  // speech/text/field edit or by Donna starting to talk. The frame-based idle above stays as a backstop.
  // Two stages: first expiry nudges Donna to ask if the visitor is still there; a second quiet window ends the call.
  const stopSilence = () => clearTimeout(silenceTimer);
  const visitorActive = () => { stopSilence(); nudged = false; };
  const armSilence = () => {
    if (wrapping || ended) return;
    clearTimeout(silenceTimer);
    if (nudged) { silenceTimer = setTimeout(() => end('silence'), config.silenceGraceSeconds * 1000); return; }
    silenceTimer = setTimeout(() => {
      nudged = true;
      toUp({ realtimeInput: { text: SILENCE_NUDGE } });
      armSilence(); // grace runs from the nudge; Donna speaking clears it and her turnComplete re-arms it
    }, config.silenceSeconds * 1000);
  };

  const wrapUp = () => {
    wrapping = true;
    clearTimeout(idleTimer);
    stopSilence();
    toUp({ realtimeInput: { text: WRAP_UP_PROMPT } });
    graceTimer = setTimeout(() => end('cap'), config.graceSeconds * 1000);
  };

  const oneLine = (v, n = 120) => v.replace(/[\[\]\r\n]+/g, ' ').slice(0, n);
  const greeting = () => {
    if (!seeded.length) return 'Hello';
    const snap = lead.snapshot();
    const known = seeded.map((f) => `${f}=${oneLine(snap[f])}`).join(', ');
    const missing = FIELDS.filter((f) => !snap[f]);
    const rest = missing.length ? `continue with what is missing: ${missing.join(', ')}` : 'everything is saved; ask if anything needs changing, otherwise finish';
    return `[system note: returning visitor; already saved: ${known}. Greet them by name briefly, do not ask for these again, ${rest}]`;
  };

  const onReady = () => {
    clearTimeout(setupTimer);
    ready = true;
    toClient({ type: 'ready', maxSeconds: config.maxSessionSeconds });
    setState('listening');
    toUp({ realtimeInput: { text: greeting() } }); // Gemini waits for input; this makes Donna greet first
    capTimer = setTimeout(wrapUp, config.maxSessionSeconds * 1000);
    touch();
  };

  const closeUserCaption = () => {
    if (userOpen) { userOpen = false; toClient({ type: 'caption', who: 'user', text: '', final: true }); }
  };

  const onToolCalls = (calls) => {
    stopSilence();
    setState('thinking');
    const functionResponses = [];
    for (const fc of calls) {
      const { response, events } = handleToolCall(lead, fc);
      events.forEach(toClient);
      functionResponses.push({ id: fc.id, name: fc.name, response });
    }
    toUp({ toolResponse: { functionResponses } });
  };

  const onUpstream = (msg) => {
    if (msg.usageMetadata) usage = msg.usageMetadata;
    if (msg.setupComplete) return onReady();

    const sc = msg.serverContent;
    if (sc?.interrupted) {
      toClient({ type: 'interrupted' });
      toClient({ type: 'caption', who: 'donna', text: '', final: true });
      setState('listening', true);
    }
    for (const part of sc?.modelTurn?.parts ?? []) {
      if (part.inlineData?.data) {
        closeUserCaption();
        stopSilence();
        setState('speaking');
        toClient({ type: 'audio', data: part.inlineData.data });
      }
    }
    // Transcriptions arrive top-level or inside serverContent.
    const inT = sc?.inputTranscription ?? msg.inputTranscription;
    const outT = sc?.outputTranscription ?? msg.outputTranscription;
    if (inT?.text) {
      heard = heardClosed ? inT.text : heard + inT.text;
      heardClosed = false;
      lead.hear(heard);
      visitorActive();
      userOpen = true;
      if (state !== 'speaking') setState('thinking');
      toClient({ type: 'caption', who: 'user', text: inT.text, final: false });
    }
    if (outT?.text) {
      closeUserCaption();
      toClient({ type: 'caption', who: 'donna', text: outT.text, final: false });
    }
    if (sc?.turnComplete) {
      heardClosed = true;
      closeUserCaption();
      toClient({ type: 'caption', who: 'donna', text: '', final: true });
      setState('listening', true);
      armSilence();
    }
    if (msg.toolCall) onToolCalls(msg.toolCall.functionCalls ?? []);
    if (msg.goAway) log('upstream_go_away');
  };

  const onClient = (data, isBinary) => {
    if (ended) return;
    if (isBinary) return fail('bad_message', 'Binary frames are not supported.');
    let m;
    try { m = JSON.parse(data.toString()); } catch { return fail('bad_json', 'Message is not valid JSON.'); }
    if (!m || typeof m !== 'object' || typeof m.type !== 'string') return fail('bad_message', 'Message needs a string "type".');

    const first = !sawFrame;
    sawFrame = true;
    if (first && m.type !== 'resume') startUpstream();

    switch (m.type) {
      case 'resume': {
        if (!first || !m.fields || typeof m.fields !== 'object' || Array.isArray(m.fields)) return; // only honoured as the first frame
        for (const f of FIELDS) {
          const r = validateField(f, m.fields[f]);
          if (!r.ok) continue;
          lead.set(f, r.value);
          seeded.push(f);
          toClient({ type: 'field', field: f, value: r.value });
        }
        return startUpstream();
      }
      case 'audio':
        if (typeof m.data !== 'string' || !m.data || m.data.length > MAX_AUDIO_B64) return fail('bad_audio', 'Audio needs a non-empty base64 string of reasonable size.');
        if (!ready) return; // audio before "ready" is expected from a live mic; dropped by design
        touch();
        return toUp({ realtimeInput: { audio: { data: m.data, mimeType: 'audio/pcm;rate=16000' } } });
      case 'text': {
        const text = typeof m.text === 'string' ? m.text.trim() : '';
        if (!text || text.length > MAX_TEXT) return fail('bad_text', `Text must be 1 to ${MAX_TEXT} characters.`);
        if (!ready) return fail('not_ready', 'Wait for "ready" before sending.');
        touch();
        visitorActive();
        heardClosed = true;
        lead.hear(text);
        setState('thinking');
        return toUp({ realtimeInput: { text } });
      }
      case 'field_edit': {
        const r = validateField(m.field, m.value);
        if (!r.ok) return fail('invalid_field', r.error);
        if (!ready) return fail('not_ready', 'Wait for "ready" before sending.');
        touch();
        visitorActive();
        lead.set(m.field, r.value);
        toClient({ type: 'field', field: m.field, value: r.value });
        return toUp({ realtimeInput: { text: `[The visitor corrected the ${m.field} field on screen to: ${r.value}. Acknowledge in a few words. Do not ask for it again.]` } });
      }
      case 'stop':
        return end('stop');
      default:
        return fail('unknown_type', `Unknown message type: ${m.type.slice(0, 40)}`);
    }
  };

  client.on('message', onClient);
  client.on('close', () => end('stop'));
  client.on('error', () => end('stop'));

  const startUpstream = () => {
    if (upstreamStarted || ended) return;
    upstreamStarted = true;
    clearTimeout(resumeTimer);
    connectUpstream();
  };

  const connectUpstream = async () => {
    const headers = {};
    try {
      const token = await config.getToken();
      if (token) headers.Authorization = `Bearer ${token}`;
    } catch (e) {
      log('auth_failed', { error: e.name });
      fail('upstream_auth', 'Could not authenticate to the voice engine.');
      return end('error');
    }
    if (ended) return;

    up = new WebSocket(config.upstreamUrl, { headers });
    setupTimer = setTimeout(() => { fail('upstream_timeout', 'The voice engine did not respond.'); end('error'); }, SETUP_TIMEOUT_MS);
    up.on('open', () => toUp({
      setup: {
        model: config.modelPath,
        generationConfig: {
          responseModalities: ['AUDIO'],
          speechConfig: {
            voiceConfig: { prebuiltVoiceConfig: { voiceName: config.voiceName } },
            languageCode: config.voiceLanguage,
          },
        },
        systemInstruction: { parts: [{ text: config.instructions }] },
        tools: [{ functionDeclarations: TOOL_DECLARATIONS }],
        inputAudioTranscription: {},
        outputAudioTranscription: {},
      },
    }));
    up.on('message', (data) => {
      let msg;
      try { msg = JSON.parse(data.toString()); } catch { return log('upstream_bad_json'); }
      if (msg && typeof msg === 'object') onUpstream(msg);
    });
    up.on('error', (e) => log('upstream_error', { error: e.name, code: e.code }));
    up.on('close', (code, reason) => {
      if (ended) return;
      log('upstream_closed', { code, reason: reason.toString().slice(0, 120) });
      fail('upstream_closed', 'The voice engine disconnected.');
      end('error');
    });
  };

  log('session_start');
  // Hold the upstream setup briefly so a "resume" frame can seed the greeting; the first frame of any kind releases it.
  resumeTimer = setTimeout(startUpstream, RESUME_WAIT_MS);
  return { end };
}
