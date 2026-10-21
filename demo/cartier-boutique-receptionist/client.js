// Cartier boutique receptionist demo: browser client for the ElevenLabs Conversational AI websocket (French + English).
// Hand-written, not built. The server (api.php) returns a signed URL and the dynamic variables for the session.

const workletSource = `
class Capture extends AudioWorkletProcessor {
  constructor(options) {
    super(); this.target = options.processorOptions.rate;
    this.chunk = new Int16Array(this.target * 0.08); this.index = 0;
    this.phase = 0; this.sum = 0; this.count = 0;
  }
  process(inputs) {
    const input = inputs[0]?.[0];
    if (!input) return true;
    for (const value of input) {
      this.sum += value; this.count++; this.phase += this.target;
      if (this.phase >= sampleRate) {
        const sample = Math.max(-1, Math.min(1, this.sum / this.count));
        this.chunk[this.index++] = Math.round(sample * (sample < 0 ? 32768 : 32767));
        this.phase -= sampleRate; this.sum = 0; this.count = 0;
        if (this.index === this.chunk.length) {
          this.port.postMessage(this.chunk, [this.chunk.buffer]);
          this.chunk = new Int16Array(this.target * 0.08); this.index = 0;
        }
      }
    }
    return true;
  }
}
registerProcessor('cartier-capture', Capture);
`;

const TEXT = {
  fr: {
    provider: 'Voix française',
    hintName: 'Indiquez votre prénom pour commencer.',
    hintReady: 'Choisissez une langue, puis lancez la conversation.',
    mic: 'Autorisez le micro pour commencer.',
    connecting: 'Connexion de la voix. La première fois, ça peut prendre un instant.',
    ready: 'Vous pouvez parler. Camille vous écoute.',
    muted: 'Votre micro est coupé.',
    unmuted: 'Votre micro est actif.',
    mute: 'Couper le micro',
    unmute: 'Réactiver le micro',
    idle: 'Prêt quand vous l’êtes',
    live: 'Conversation en cours',
    ended: 'Conversation terminée. Vous pouvez recommencer.',
    thanks: 'Conversation terminée. Merci de votre visite.',
    limit: 'Votre démo de cinq minutes est terminée. Vous pouvez relancer une conversation.',
    you: 'Vous',
  },
  en: {
    provider: 'English voice',
    hintName: 'Enter your name to start.',
    hintReady: 'Choose a language, then press Start conversation.',
    mic: 'Allow microphone access to begin.',
    connecting: 'Connecting your voice. The first connection can take a moment.',
    ready: 'You can speak naturally. Camille is listening.',
    muted: 'Your microphone is muted.',
    unmuted: 'Your microphone is on.',
    mute: 'Mute mic',
    unmute: 'Unmute mic',
    idle: 'Ready when you are',
    live: 'Conversation connected',
    ended: 'Conversation ended. You can start again.',
    thanks: 'Conversation ended. Thank you for visiting.',
    limit: 'Your five-minute demo has ended. You can start a new conversation.',
    you: 'You',
  },
};
const SPEAKER = 'Camille';

function toBase64(pcm) {
  const bytes = new Uint8Array(pcm.length * 2);
  const view = new DataView(bytes.buffer);
  for (let i = 0; i < pcm.length; i++) view.setInt16(i * 2, pcm[i], true);
  return btoa(String.fromCharCode(...bytes));
}

function fromBase64(text) {
  const bytes = Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
  if (bytes.length % 2) throw new Error('Invalid audio frame.');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return Float32Array.from({ length: bytes.length / 2 }, (_, i) => view.getInt16(i * 2, true) / 32768);
}

function mountDemo(doc = document) {
  const byId = (id) => doc.getElementById(id);
  const status = byId('status');
  const captions = byId('captions');
  const label = byId('connection-label');
  const nameField = byId('name');
  let language = 'fr';
  let active = null;
  let configured = { frenchConfigured: true, englishConfigured: true };

  const t = () => TEXT[language];
  const message = (text, error = false) => {
    status.textContent = text;
    status.classList.toggle('error', error);
  };
  const visitorName = () => nameField.value.trim().slice(0, 60);
  const available = () => Boolean(configured[language === 'fr' ? 'frenchConfigured' : 'englishConfigured']);
  const hint = () => {
    if (active || !available()) return;
    message(visitorName() ? t().hintReady : t().hintName);
  };
  const controls = () => {
    byId('start').hidden = Boolean(active);
    byId('start').disabled = !available() || !visitorName();
    nameField.disabled = Boolean(active);
    byId('stop').hidden = !active;
    byId('mute').hidden = !active?.ready;
    byId('french').disabled = Boolean(active);
    byId('english').disabled = Boolean(active);
  };
  const select = (value) => {
    if (active) return;
    language = value;
    byId('french').setAttribute('aria-pressed', String(value === 'fr'));
    byId('english').setAttribute('aria-pressed', String(value === 'en'));
    byId('provider').textContent = t().provider;
    label.textContent = t().idle;
    doc.documentElement.lang = value;
    if (available()) hint();
    else message('This voice needs server configuration.', true);
    controls();
  };

  const clearPlayback = (session) => {
    for (const source of session.sources) {
      try { source.stop(); } catch { /* already stopped */ }
    }
    session.sources.clear();
    session.playAt = 0;
  };

  const end = (text = t().ended, error = false) => {
    const session = active;
    active = null;
    if (session) {
      session.abort.abort();
      clearTimeout(session.timeout);
      clearTimeout(session.firstAudio);
      clearInterval(session.clock);
      session.ws?.close();
      session.stream?.getTracks().forEach((track) => track.stop());
      session.capture?.disconnect();
      session.input?.disconnect();
      clearPlayback(session);
      session.context?.close().catch(() => {});
    }
    doc.body.dataset.state = 'idle';
    label.textContent = t().idle;
    controls();
    message(text, error);
  };

  const transcript = (who, text) => {
    if (!text) return;
    const paragraph = doc.createElement('p');
    const name = doc.createElement('strong');
    name.textContent = `${who}  `;
    const body = doc.createElement('span');
    body.textContent = text.slice(-5000);
    paragraph.append(name, body);
    captions.append(paragraph);
    while (captions.children.length > 100) captions.firstElementChild.remove();
    captions.scrollTop = captions.scrollHeight;
  };

  const play = (session, encoded) => {
    const pcm = fromBase64(encoded);
    if (!pcm.length) return;
    clearTimeout(session.firstAudio);
    const ctx = session.context;
    if (session.playAt - ctx.currentTime > 30) throw new Error('Audio is falling behind. Please restart the conversation.');
    const buffer = ctx.createBuffer(1, pcm.length, session.outputRate);
    buffer.copyToChannel(pcm, 0);
    const source = ctx.createBufferSource();
    source.buffer = buffer;
    source.connect(ctx.destination);
    const at = Math.max(ctx.currentTime + 0.03, session.playAt);
    session.sources.add(source);
    source.onended = () => session.sources.delete(source);
    source.start(at);
    session.playAt = at + buffer.duration;
  };

  const start = async () => {
    if (active || !available() || !visitorName()) return;
    const session = {
      abort: new AbortController(), sources: new Set(), muted: false, ready: false, playAt: 0,
      ws: null, stream: null, context: null, capture: null, input: null,
      clock: undefined, timeout: undefined, firstAudio: undefined, outputRate: 16000, lastInterruption: -1,
      name: visitorName(), language,
    };
    active = session;
    controls();
    message(t().mic);
    captions.replaceChildren();
    byId('timer').textContent = '00:00';
    label.textContent = '…';
    try {
      if (!navigator.mediaDevices?.getUserMedia || !window.AudioContext) throw new Error('Use a browser with microphone support on localhost or HTTPS.');
      const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true, channelCount: 1 } });
      if (active !== session) { stream.getTracks().forEach((track) => track.stop()); return; }
      session.stream = stream;
      const ctx = new AudioContext();
      session.context = ctx;
      await ctx.resume();
      message(t().connecting);
      const response = await fetch(`api/session?language=${session.language}`, {
        method: 'POST',
        headers: { 'X-Demo-Request': '1', 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: session.name }),
        signal: session.abort.signal,
      });
      const config = await response.json();
      if (!response.ok) throw new Error(config.error || 'Unable to connect.');
      if (active !== session) return;
      session.outputRate = config.sampleRate;
      const workletUrl = URL.createObjectURL(new Blob([workletSource], { type: 'text/javascript' }));
      try { await ctx.audioWorklet.addModule(workletUrl); } finally { URL.revokeObjectURL(workletUrl); }
      if (active !== session) return;
      const capture = new AudioWorkletNode(ctx, 'cartier-capture', { processorOptions: { rate: config.sampleRate } });
      session.capture = capture;
      const input = ctx.createMediaStreamSource(stream);
      session.input = input;
      input.connect(capture);
      capture.connect(ctx.destination);
      const ws = new WebSocket(config.url);
      session.ws = ws;
      ws.binaryType = 'arraybuffer';
      session.timeout = setTimeout(() => {
        if (active === session) end('Connection timed out. Please try again.', true);
      }, 25000);
      capture.port.onmessage = (event) => {
        if (active !== session || ws.readyState !== WebSocket.OPEN || !session.ready) return;
        if (ws.bufferedAmount > 96000) { end('Connection is too slow for live audio. Please restart.', true); return; }
        const pcm = session.muted ? new Int16Array(event.data.length) : event.data;
        ws.send(JSON.stringify({ user_audio_chunk: toBase64(pcm) }));
      };
      const ready = () => {
        if (active !== session || session.ready) return;
        clearTimeout(session.timeout);
        session.ready = true;
        controls();
        byId('mute').textContent = t().mute;
        doc.body.dataset.state = 'live';
        label.textContent = TEXT[session.language].live;
        message(TEXT[session.language].ready);
        const began = Date.now();
        session.clock = setInterval(() => {
          const seconds = Math.floor((Date.now() - began) / 1000);
          byId('timer').textContent = `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
          if (seconds >= config.maxSeconds) end(TEXT[session.language].limit);
        }, 1000);
        session.firstAudio = setTimeout(() => {
          if (active === session) end('The voice provider did not return audio. Please retry shortly.', true);
        }, 45000);
      };
      ws.onopen = () => {
        if (active !== session) { ws.close(); return; }
        ws.send(JSON.stringify({ type: 'conversation_initiation_client_data', dynamic_variables: config.dynamicVariables || {} }));
      };
      ws.onmessage = (event) => {
        if (active !== session) return;
        try {
          const data = JSON.parse(event.data);
          if (data.error) throw new Error('The voice provider reported an error. Please retry shortly.');
          if (data.type === 'conversation_initiation_metadata') {
            const meta = data.conversation_initiation_metadata_event;
            if (meta.user_input_audio_format !== 'pcm_16000' || meta.agent_output_audio_format !== 'pcm_16000') throw new Error('Voice agent audio format has changed. Check the agent configuration.');
            ready();
          } else if (data.type === 'audio') {
            if (data.audio_event.event_id > session.lastInterruption) play(session, data.audio_event.audio_base_64);
          } else if (data.type === 'interruption') {
            session.lastInterruption = data.interruption_event.event_id;
            clearPlayback(session);
          } else if (data.type === 'ping') ws.send(JSON.stringify({ type: 'pong', event_id: data.ping_event.event_id }));
          else if (data.type === 'agent_response') transcript(SPEAKER, data.agent_response_event.agent_response.replace(/\[[a-z ]+\]\s*/g, ''));
          else if (data.type === 'user_transcript') transcript(TEXT[session.language].you, data.user_transcription_event.user_transcript);
        } catch (error) {
          end(error instanceof Error ? error.message : 'Unable to decode audio.', true);
        }
      };
      ws.onerror = () => {
        if (active === session) end('Unable to connect to the voice provider. Please retry.', true);
      };
      ws.onclose = (event) => {
        if (active === session) end(event.code === 1000 ? TEXT[session.language].thanks : 'The voice connection closed unexpectedly. Please try again.', event.code !== 1000);
      };
    } catch (error) {
      if (active !== session) return;
      end(error.name === 'NotAllowedError' ? 'Microphone access was denied. Allow it in your browser settings and try again.' : error.message || 'Unable to start the conversation.', true);
    }
  };

  byId('french').onclick = () => select('fr');
  byId('english').onclick = () => select('en');
  byId('start').onclick = start;
  byId('stop').onclick = () => end();
  nameField.oninput = () => { controls(); hint(); };
  byId('mute').onclick = () => {
    if (!active) return;
    active.muted = !active.muted;
    active.stream?.getAudioTracks().forEach((track) => { track.enabled = !active.muted; });
    byId('mute').textContent = active.muted ? TEXT[active.language].unmute : TEXT[active.language].mute;
    message(active.muted ? TEXT[active.language].muted : TEXT[active.language].unmuted);
  };
  window.addEventListener('pagehide', () => end());

  const preselect = new URLSearchParams(doc.defaultView?.location.search).get('lang');
  select(preselect === 'en' ? 'en' : 'fr');
  fetch('api/config').then((r) => {
    if (!r.ok) throw new Error('config');
    return r.json();
  }).then((config) => {
    configured = { ...configured, ...config };
    controls();
    if (!available() && !active) message('This voice needs server configuration.', true);
  }).catch(() => message('Cannot reach the demo server. Please reload.', true));
  return { start, end };
}

if (typeof document !== 'undefined') mountDemo();
export { fromBase64, mountDemo, toBase64, workletSource };
