import { once } from 'node:events';
import { WebSocketServer } from 'ws';

const SETUP_KEYS = new Set(['model', 'generationConfig', 'systemInstruction', 'tools', 'inputAudioTranscription', 'outputAudioTranscription']);
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);

// Strict by design: anything the real API would not accept closes the socket with 1008 and a reason.
function checkSetup(m) {
  if (Object.keys(m).join() !== 'setup' || !isObj(m.setup)) return 'first message must be exactly {setup}';
  const s = m.setup;
  for (const k of Object.keys(s)) if (!SETUP_KEYS.has(k)) return `unknown setup field: ${k}`;
  if (!/^projects\/[^/]+\/locations\/[^/]+\/publishers\/google\/models\/[^/]+$/.test(s.model ?? '')) return 'bad model path';
  const g = s.generationConfig;
  if (!g?.responseModalities?.includes('AUDIO')) return 'setup needs AUDIO modality';
  for (const k of Object.keys(g)) if (!['responseModalities', 'speechConfig'].includes(k)) return `unknown generationConfig field: ${k}`;
  const sp = g.speechConfig;
  if (sp !== undefined) {
    for (const k of Object.keys(sp)) if (!['voiceConfig', 'languageCode'].includes(k)) return `unknown speechConfig field: ${k}`;
    if (sp.voiceConfig && typeof sp.voiceConfig.prebuiltVoiceConfig?.voiceName !== 'string') return 'voiceConfig needs prebuiltVoiceConfig.voiceName';
    if (sp.languageCode !== undefined && typeof sp.languageCode !== 'string') return 'languageCode must be a string';
  }
  if (!s.systemInstruction?.parts?.[0]?.text) return 'setup needs systemInstruction text';
  const names = (s.tools?.[0]?.functionDeclarations ?? []).map((d) => d.name);
  for (const n of ['save_field', 'navigate', 'finish_intake']) if (!names.includes(n)) return `missing tool ${n}`;
  return null;
}

function checkLater(m) {
  const keys = Object.keys(m);
  if (keys.length !== 1) return 'exactly one top-level key expected';
  if (keys[0] === 'realtimeInput') {
    const r = m.realtimeInput;
    if (!isObj(r) || Object.keys(r).length !== 1) return 'realtimeInput needs exactly one of audio/text';
    if ('audio' in r) {
      if (typeof r.audio?.data !== 'string' || !r.audio.data) return 'audio.data must be a non-empty string';
      if (r.audio.mimeType !== 'audio/pcm;rate=16000') return 'audio.mimeType must be audio/pcm;rate=16000';
      return null;
    }
    if ('text' in r) return typeof r.text === 'string' && r.text ? null : 'text must be a non-empty string';
    return 'unknown realtimeInput member';
  }
  if (keys[0] === 'toolResponse') {
    const fr = m.toolResponse?.functionResponses;
    if (!Array.isArray(fr) || !fr.length) return 'functionResponses must be a non-empty array';
    for (const f of fr) {
      if (typeof f.id !== 'string' || typeof f.name !== 'string' || !isObj(f.response)) return 'functionResponse needs id, name, response object';
    }
    return null;
  }
  return `unknown message: ${keys[0]}`;
}

export async function startFakeUpstream() {
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  await once(wss, 'listening');
  const f = {
    url: `ws://127.0.0.1:${wss.address().port}/ws`,
    received: [],
    violations: [],
    headers: [],
    sockets: new Set(),
  };

  wss.on('connection', (ws, req) => {
    f.headers.push(req.headers);
    f.sockets.add(ws);
    let gotSetup = false;
    ws.on('close', () => f.sockets.delete(ws));
    ws.on('message', (data) => {
      let m;
      let why;
      try { m = JSON.parse(data.toString()); } catch { why = 'not json'; }
      why ??= isObj(m) ? (gotSetup ? checkLater(m) : checkSetup(m)) : 'not an object';
      if (why) {
        f.violations.push(why);
        return ws.close(1008, why.slice(0, 100));
      }
      f.received.push(m);
      if (!gotSetup) { gotSetup = true; ws.send(JSON.stringify({ setupComplete: {} })); }
    });
  });

  f.send = (obj) => [...f.sockets].at(-1).send(JSON.stringify(obj));
  f.closeAll = (code = 1011, reason = 'fake closing') => f.sockets.forEach((s) => s.close(code, reason));
  f.waitFor = async (pred, ms = 3000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const hit = f.received.find(pred);
      if (hit) return hit;
      await new Promise((r) => setTimeout(r, 10));
    }
    throw new Error(`fake upstream: no matching message within ${ms}ms (got ${f.received.length}, violations: ${f.violations.join('; ') || 'none'})`);
  };
  f.close = () => new Promise((resolve) => {
    f.sockets.forEach((s) => s.terminate());
    wss.close(() => resolve());
  });
  return f;
}
