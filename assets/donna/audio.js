// Shared audio helpers: level meter, mic -> PCM16 worklet, gapless PCM16 playback queue.

export function makeAnalyser(ctx) {
  const a = ctx.createAnalyser();
  a.fftSize = 1024;
  a.smoothingTimeConstant = 0.5;
  a._buf = new Float32Array(a.fftSize);
  return a;
}

export function readLevel(a) {
  a.getFloatTimeDomainData(a._buf);
  let s = 0;
  for (let i = 0; i < a._buf.length; i++) s += a._buf[i] * a._buf[i];
  return Math.min(1, Math.sqrt(s / a._buf.length) * 4);
}

export function int16ToB64(i16) {
  const u8 = new Uint8Array(i16.buffer, i16.byteOffset, i16.byteLength);
  let bin = '';
  for (let i = 0; i < u8.length; i += 0x8000) bin += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(bin);
}

export function b64ToInt16(b64) {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length & ~1);
  for (let i = 0; i < u8.length; i++) u8[i] = bin.charCodeAt(i);
  return new Int16Array(u8.buffer);
}

// ponytail: box-average downsample, not a proper polyphase filter. Fine for speech; swap if input quality is suspect.
const WORKLET = `
class PcmCapture extends AudioWorkletProcessor {
  constructor(o) {
    super();
    this.ratio = sampleRate / o.processorOptions.target;
    this.n = Math.max(1, Math.round(this.ratio));
    this.chunk = Math.round(o.processorOptions.target * 0.04);
    this.tail = new Float32Array(0);
    this.p = 0;
    this.out = new Int16Array(this.chunk);
    this.k = 0;
  }
  process(inputs) {
    const ch = inputs[0] && inputs[0][0];
    if (!ch) return true;
    const buf = new Float32Array(this.tail.length + ch.length);
    buf.set(this.tail);
    buf.set(ch, this.tail.length);
    while (this.p + this.n < buf.length) {
      const i = Math.floor(this.p);
      let s = 0;
      for (let j = 0; j < this.n; j++) s += buf[i + j];
      const v = Math.max(-1, Math.min(1, s / this.n));
      this.out[this.k++] = v < 0 ? v * 0x8000 : v * 0x7fff;
      if (this.k === this.chunk) {
        this.port.postMessage(this.out.buffer, [this.out.buffer]);
        this.out = new Int16Array(this.chunk);
        this.k = 0;
      }
      this.p += this.ratio;
    }
    const used = Math.floor(this.p);
    this.tail = buf.slice(used);
    this.p -= used;
    return true;
  }
}
registerProcessor('pcm-capture', PcmCapture);
`;

// Streams mic as PCM16 LE at `rate` Hz via onChunk(Int16Array). Returns a stop function.
export async function startMicPcm(ctx, micSource, rate, onChunk) {
  const url = URL.createObjectURL(new Blob([WORKLET], { type: 'text/javascript' }));
  try {
    await ctx.audioWorklet.addModule(url);
  } finally {
    URL.revokeObjectURL(url);
  }
  const node = new AudioWorkletNode(ctx, 'pcm-capture', { processorOptions: { target: rate }, numberOfOutputs: 0 });
  node.port.onmessage = (e) => onChunk(new Int16Array(e.data));
  micSource.connect(node);
  return () => {
    try { micSource.disconnect(node); } catch {}
    node.port.onmessage = null;
    node.disconnect();
  };
}

// Gapless PCM16 playback. flush() stops everything queued (barge-in).
export class PcmPlayer {
  constructor(ctx, sinks, rate = 24000) {
    this.ctx = ctx;
    this.sinks = sinks;
    this.rate = rate;
    this.t = 0;
    this.srcs = new Set();
  }

  push(i16) {
    if (!i16.length) return;
    const f = new Float32Array(i16.length);
    for (let i = 0; i < i16.length; i++) f[i] = i16[i] / (i16[i] < 0 ? 0x8000 : 0x7fff);
    const buf = this.ctx.createBuffer(1, f.length, this.rate);
    buf.copyToChannel(f, 0);
    const src = this.ctx.createBufferSource();
    src.buffer = buf;
    for (const s of this.sinks) src.connect(s);
    const now = this.ctx.currentTime;
    if (this.t < now + 0.01) this.t = now + 0.06; // small jitter buffer after an underrun
    src.start(this.t);
    this.t += buf.duration;
    this.srcs.add(src);
    src.onended = () => { this.srcs.delete(src); src.disconnect(); };
  }

  flush() {
    for (const s of this.srcs) {
      s.onended = null;
      try { s.stop(); } catch {}
      s.disconnect();
    }
    this.srcs.clear();
    this.t = 0;
  }

  // Resolves when queued audio has finished playing (or after maxMs).
  async idle(maxMs = 8000) {
    const end = performance.now() + maxMs;
    while (this.t > this.ctx.currentTime && performance.now() < end) await new Promise((r) => setTimeout(r, 60));
  }
}
