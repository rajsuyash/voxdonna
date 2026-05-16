---
name: build-cartesia-browser-demo
description: Build a Cartesia voice agent browser demo — visitor clicks an orb, talks to the agent via mic, hears it respond, sees live transcript. Uses the WebSocket protocol at wss://api.cartesia.ai/agents/stream/{agentId}. Includes server-side token mint, Web Audio API plumbing, and the exact PCM-16 streaming protocol. Self-contained skill that ports to any static or server-rendered site.
---

# Build a Cartesia Voice Agent Browser Demo

End-to-end playbook for embedding a "click and talk to the agent" widget on a website. Battle-tested on `voxdonna.com/demo/joyalukkas-cartesia.html` and `bjp voice agent`'s Next.js app.

## When to use this skill

- User asks for a "browser voice demo" / "click and talk" / "mic-based agent demo" on Cartesia
- User has a Cartesia agent already provisioned and wants a public-facing voice demo
- Adding Cartesia to a project where ElevenLabs ConvAI is not the right fit (e.g., voice cloning, sub-1s latency, Indian-language quality)

## When NOT to use

- User wants a phone-callable demo only (use the phone number Cartesia auto-provisions per agent — no SDK needed)
- User wants to deploy the agent locally for dev testing (use `cartesia dev` CLI instead)
- User is on a self-hosted ElevenLabs/Vapi stack — wrong tool

## Architecture (3 pieces)

```
Browser                              Your server                     Cartesia
───────                              ───────────                     ────────
1. fetch('/cartesia-token')   ───►  mint token  ──────►  POST /access-token
                                                  ◄──────  {token, expires_in:300}
                              ◄────  {token, agentId}
2. new WebSocket(wss://api.cartesia.ai/agents/stream/{agentId}?access_token=...)
                                                        ──────►  open connection
3. send { event: 'start', config: { input_format: 'pcm_16000' } }
4. capture mic → downsample to 16kHz → send media_input frames (base64)
5. receive media_output frames (base64 PCM) → play via Web Audio API
6. receive transcript events → render captions
```

The browser holds the WebSocket directly to Cartesia. Your server only mints short-lived (5 min) tokens. **Never expose the API key to the browser.**

## Prerequisites

1. **Cartesia agent provisioned** — get the agent_id from the dashboard or via REST API. The agent must have `tts_voice`, `tts_language`, and `llm_system_prompt` set.
2. **Cartesia API key** (`sk_car_...`) — for the server-side token mint only.
3. **Server runtime** capable of making POST requests to Cartesia's `/access-token` endpoint. PHP, Node, Python, Cloudflare Worker — any of them work.
4. **HTTPS** — `getUserMedia` requires it. `localhost` is OK for local dev.
5. **CORS** — if the token endpoint is on a different origin from the page, configure CORS to allow the page's origin.

## Step 1 — Server-side token mint endpoint

The token endpoint signs short-lived access tokens. The browser uses these to open the WebSocket. **The Cartesia API key never leaves the server.**

### PHP (static-site friendly — e.g., Hostinger)

`cartesia-token.php` (drop in the web root):

```php
<?php
header('Access-Control-Allow-Origin: https://yourdomain.com');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'method_not_allowed']);
    exit;
}

function load_env($path) {
    $env = [];
    if (!file_exists($path)) return $env;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) $env[trim($parts[0])] = trim($parts[1]);
    }
    return $env;
}

$env = load_env(__DIR__ . '/.env');
$api_key = $env['CARTESIA_API_KEY'] ?? '';
$agent_id = $env['CARTESIA_AGENT_ID'] ?? '';

if (empty($api_key) || empty($agent_id)) {
    http_response_code(503);
    echo json_encode(['ok' => false, 'error' => 'not_configured']);
    exit;
}

// IP rate limit: 10 tokens per IP per 5 minutes (prevent token-mint abuse)
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$ip = explode(',', $ip)[0];
$cache_key = sys_get_temp_dir() . '/cart_rl_' . md5($ip);
$now = time();
$attempts = [];
if (file_exists($cache_key)) $attempts = json_decode(file_get_contents($cache_key), true) ?: [];
$attempts = array_filter($attempts, fn($t) => $t > $now - 300);
if (count($attempts) >= 10) {
    http_response_code(429);
    echo json_encode(['ok' => false, 'error' => 'rate_limited']);
    exit;
}
$attempts[] = $now;
file_put_contents($cache_key, json_encode($attempts));

$ch = curl_init('https://api.cartesia.ai/access-token');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => [
        'Authorization: Bearer ' . $api_key,
        'Cartesia-Version: 2025-04-16',
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS => json_encode([
        'grants' => ['tts' => true, 'stt' => true, 'agent' => true],
        'expires_in' => 300,
    ]),
    CURLOPT_TIMEOUT => 10,
]);
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($http_code !== 200) {
    http_response_code(502);
    echo json_encode(['ok' => false, 'error' => 'mint_failed', 'upstream' => $http_code]);
    exit;
}

$data = json_decode($response, true);
$token = $data['token'] ?? $data['access_token'] ?? null;
if (!$token) {
    http_response_code(502);
    echo json_encode(['ok' => false, 'error' => 'no_token']);
    exit;
}

echo json_encode([
    'ok' => true,
    'token' => $token,
    'agentId' => $agent_id,
    'version' => '2025-04-16',
]);
```

### Next.js (server-rendered)

`app/api/agent-token/route.ts`:

```typescript
import { NextResponse } from "next/server";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST() {
  const apiKey = process.env.CARTESIA_API_KEY;
  const agentId = process.env.CARTESIA_AGENT_ID;
  const version = process.env.CARTESIA_VERSION || "2025-04-16";

  if (!apiKey || !agentId) {
    return NextResponse.json({ ok: false, message: "Not configured" }, { status: 503 });
  }
  if (process.env.DEMO_ENABLED === "false") {
    return NextResponse.json({ ok: false, message: "Demo disabled" }, { status: 503 });
  }

  const res = await fetch("https://api.cartesia.ai/access-token", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Cartesia-Version": version,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      grants: { tts: true, stt: true, agent: true },
      expires_in: 300,
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    return NextResponse.json({ ok: false, message: text.slice(0, 200) }, { status: 502 });
  }

  const data = await res.json() as { token?: string; access_token?: string };
  const accessToken = data.token ?? data.access_token;
  if (!accessToken) {
    return NextResponse.json({ ok: false, message: "no token" }, { status: 502 });
  }
  return NextResponse.json({ ok: true, accessToken, agentId, version });
}
```

**Critical**: Accept both `token` and `access_token` in Cartesia's response — field name varies.

## Step 2 — Browser-side WebSocket client

This is the hard part. The protocol is undocumented in Cartesia's public docs but verified working.

### Constants

```js
const SAMPLE_RATE = 16000;  // input + output PCM rate
const OUTPUT_RATE = 16000;  // matches what we requested
```

### The WebSocket URL

```js
const url = `wss://api.cartesia.ai/agents/stream/${agentId}?cartesia_version=${encodeURIComponent(version)}&access_token=${encodeURIComponent(token)}`;
```

Token + version go in the query string, not headers (browsers can't set arbitrary WS headers).

### The protocol

| Direction | Event | Purpose |
|---|---|---|
| → server | `start` | Open the audio stream. Send `config: { input_format: 'pcm_16000' }` |
| → server | `media_input` | Mic audio chunk. Send `media: { payload: <base64 PCM-16 LE> }` |
| ← server | `media_output` | Agent audio chunk. Decode base64 → Int16 → Float32 → AudioBuffer |
| ← server | `transcript` | Live caption. `{ role: 'user' \| 'agent', text: '...' }` |
| ← server | `speech_started` / `speech_ended` | Mic activity hints (optional) |

### Full vanilla JS implementation

```js
const SAMPLE_RATE = 16000;
const OUTPUT_RATE = 16000;

let ws = null;
let audioCtx = null;
let stream = null;
let processor = null;
let source = null;
let starting = false;   // synchronous guard against rapid clicks
let playhead = 0;

function floatToPcm16(input) {
  const out = new Int16Array(input.length);
  for (let i = 0; i < input.length; i++) {
    const s = Math.max(-1, Math.min(1, input[i]));
    out[i] = s < 0 ? s * 0x8000 : s * 0x7fff;
  }
  return out;
}

function downsampleBuffer(buffer, fromRate, toRate) {
  if (fromRate === toRate) return buffer;
  const ratio = fromRate / toRate;
  const newLen = Math.round(buffer.length / ratio);
  const result = new Int16Array(newLen);
  let oR = 0, oB = 0;
  while (oR < newLen) {
    const nextOffset = Math.round((oR + 1) * ratio);
    let accum = 0, count = 0;
    for (let i = oB; i < nextOffset && i < buffer.length; i++) {
      accum += buffer[i]; count++;
    }
    result[oR] = count > 0 ? accum / count : 0;
    oR++; oB = nextOffset;
  }
  return result;
}

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + chunk)));
  }
  return btoa(binary);
}

function schedulePcmChunk(base64, ctx) {
  const bytes = atob(base64);
  const buf = new ArrayBuffer(bytes.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) view[i] = bytes.charCodeAt(i);
  const samples = new Int16Array(buf);
  const floats = new Float32Array(samples.length);
  for (let i = 0; i < samples.length; i++) floats[i] = samples[i] / 32768;
  const audioBuf = ctx.createBuffer(1, floats.length, OUTPUT_RATE);
  audioBuf.getChannelData(0).set(floats);
  const src = ctx.createBufferSource();
  src.buffer = audioBuf;
  src.connect(ctx.destination);
  const startAt = Math.max(playhead, ctx.currentTime);
  src.start(startAt);
  playhead = startAt + audioBuf.duration;
}

function cleanup() {
  try { ws && ws.close(); } catch (_) {}
  ws = null;
  if (processor) { try { processor.disconnect(); } catch (_) {} processor = null; }
  if (source)    { try { source.disconnect(); } catch (_) {} source = null; }
  if (stream)    { stream.getTracks().forEach(t => t.stop()); stream = null; }
  if (audioCtx)  { audioCtx.close().catch(() => {}); audioCtx = null; }
  starting = false;
}

async function start() {
  if (ws || starting) return;  // guard
  starting = true;

  // 1. Mic permission
  stream = await navigator.mediaDevices.getUserMedia({
    audio: { channelCount: 1, sampleRate: SAMPLE_RATE, echoCancellation: true, noiseSuppression: true },
  });

  // 2. Mint token
  const tokenRes = await fetch('/cartesia-token.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
  const { token, agentId, version } = await tokenRes.json();

  // 3. Open WebSocket
  const url = `wss://api.cartesia.ai/agents/stream/${agentId}?cartesia_version=${encodeURIComponent(version)}&access_token=${encodeURIComponent(token)}`;
  ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';
  playhead = 0;

  ws.onopen = () => {
    audioCtx = new AudioContext({ sampleRate: 44100 });
    playhead = audioCtx.currentTime;

    // 4. Send 'start' event
    ws.send(JSON.stringify({
      event: 'start',
      config: { input_format: `pcm_${SAMPLE_RATE}` },
    }));

    // 5. Wire up mic → WebSocket
    source = audioCtx.createMediaStreamSource(stream);
    processor = audioCtx.createScriptProcessor(2048, 1, 1);
    processor.onaudioprocess = (e) => {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      const data = e.inputBuffer.getChannelData(0);
      const pcm = floatToPcm16(data);
      const downsampled = downsampleBuffer(pcm, audioCtx.sampleRate, SAMPLE_RATE);
      const ab = new ArrayBuffer(downsampled.byteLength);
      new Uint8Array(ab).set(new Uint8Array(downsampled.buffer, downsampled.byteOffset, downsampled.byteLength));
      ws.send(JSON.stringify({
        event: 'media_input',
        media: { payload: arrayBufferToBase64(ab) },
      }));
    };
    source.connect(processor);
    processor.connect(audioCtx.destination);
    starting = false;
  };

  ws.onmessage = (msg) => {
    const data = typeof msg.data === 'string' ? JSON.parse(msg.data) : null;
    if (!data) return;
    if (data.event === 'media_output' && data.media && data.media.payload && audioCtx) {
      schedulePcmChunk(data.media.payload, audioCtx);
    } else if (data.event === 'transcript' && data.text) {
      // Render: data.role === 'user' | 'agent', data.text === '...'
      console.log('[transcript]', data.role, data.text);
    }
  };

  ws.onclose = () => cleanup();
  ws.onerror = (e) => { console.error('WS error', e); cleanup(); };
}

function end() { cleanup(); }
```

### Required HTML scaffold

```html
<button id="startBtn">🎙️ Talk to the agent</button>
<button id="endBtn" hidden>⏹ End call</button>
<p id="status">Click to start</p>
<ol id="transcript"></ol>
```

## Step 3 — Production-grade additions

### Synchronous guard against rapid clicks

This is non-negotiable. Without it, double-clicking the orb spawns parallel WebSockets and burns workspace concurrency.

```js
if (ws || starting) return;
starting = true;  // flip SYNCHRONOUSLY before any async work
```

Clear `starting = false` in the WS `onopen`, `onerror`, and `onclose` handlers, and in the `start()` function's `try/catch` error branch.

### Cleanup on page unload

```js
window.addEventListener('beforeunload', cleanup);
```

Without this, the WebSocket stays open if the user closes the tab mid-call — wastes Cartesia slots.

### Error messaging

Map common errors to friendly messages:

```js
function friendlyError(err) {
  if (!err) return 'Could not start.';
  const m = err.message || '';
  if (m.toLowerCase().includes('denied')) return 'Microphone permission denied. Allow mic access and try again.';
  if (m.toLowerCase().includes('not allowed')) return 'Microphone not allowed in this browser context.';
  if (m.toLowerCase().includes('not found')) return 'No microphone detected.';
  if (m.toLowerCase().includes('https')) return 'Voice calls require HTTPS.';
  return m;
}
```

### Visual state machine

```js
// State machine: idle → permission → connecting → live → ended | error
function setStatus(msg, cls) {
  statusEl.textContent = msg;
  statusEl.className = 'status ' + (cls || '');
}
// Toggle body.is-active to drive CSS animations
body.classList.toggle('is-active', isLive);
```

## Step 4 — Configuration

### .env (server)

```bash
CARTESIA_API_KEY=sk_car_...
CARTESIA_AGENT_ID=agent_...
CARTESIA_VERSION=2025-04-16
DEMO_ENABLED=true       # operator kill switch
```

### Agent setup (one-time, via REST API)

```bash
curl -X PATCH "https://api.cartesia.ai/agents/$AGENT_ID" \
  -H "Authorization: Bearer $CARTESIA_API_KEY" \
  -H "Cartesia-Version: 2025-04-16" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "your-agent-slug",
    "tts_voice": "<voice_id>",
    "tts_language": "hi",
    "llm_system_prompt": "...",
    "llm_introduce": "नमस्ते..."
  }'
```

**Gotcha**: `name` must match `^[a-z0-9_\-.]+$`. No uppercase.

## Step 5 — Verification

After deploying, test in this order:

1. **Token endpoint reachable**:
   ```bash
   curl -X POST https://yourdomain.com/cartesia-token.php \
     -H "Origin: https://yourdomain.com" \
     -H "Content-Type: application/json" -d '{}'
   # Expect: {"ok":true,"token":"eyJ...","agentId":"agent_...","version":"..."}
   ```

2. **Open the demo page in a browser** (HTTPS only).
3. **Click the orb** — mic permission prompt appears.
4. **Allow mic** — status flows: `connecting…` → `live · listening`.
5. **Agent's introduction plays** within 2-3 seconds.
6. **Speak** — agent should respond. Latency 500-1500ms total.
7. **Live transcript** updates as both sides speak.
8. **Click End** — call terminates cleanly, mic LED turns off.

## Common failure modes & fixes

| Symptom | Cause | Fix |
|---|---|---|
| Mic prompt never appears | Page is HTTP, not HTTPS | Deploy under HTTPS. localhost works for dev. |
| Token mint returns 503 `not_configured` | API key not on server | Check `.env` or hardcode for testing |
| Token mint returns 401 from Cartesia | Wrong auth header style | Use `Authorization: Bearer`, NOT `X-API-Key` |
| WebSocket opens then closes immediately | Token expired or invalid grants | Mint fresh token (5min expiry). Grants must include `agent: true` |
| Agent talks but you can't hear | AudioContext suspended (browser autoplay policy) | Resume `audioCtx.resume()` on user gesture |
| You speak but agent doesn't respond | Wrong sample rate or audio format | Verify `input_format: 'pcm_16000'`, mono, downsampled correctly |
| Agent responds in wrong language | `tts_language` not set on agent | PATCH agent with `tts_language: 'hi'` (or your target) |
| Choppy audio output | Playhead scheduling drift | Use the `Math.max(playhead, ctx.currentTime)` pattern shown above |
| Cuts off when you double-click | No `starting` flag guard | Add synchronous guard per Step 3 |

## Cost & concurrency

- **Cartesia plans** vary; check your tier's concurrent-stream cap.
- **Each browser open WebSocket = 1 active conversation slot** while connected.
- Monitor: `GET https://api.cartesia.ai/agents/{id}/calls?expand=transcript&limit=20` (server-side with API key).
- **Set `expires_in: 300`** on tokens (5 min). Long enough to start, short enough that a leaked token is useless.

## Security checklist

- [ ] API key on server only. Never in browser bundle / HTML.
- [ ] CORS locked to your origin (`Access-Control-Allow-Origin: https://yourdomain.com`)
- [ ] Token mint endpoint rate-limited (10 mints per IP per 5 min is a good default)
- [ ] HTTPS-only origin
- [ ] `expires_in: 300` on access tokens
- [ ] Grants scoped to what you need (`{tts: true, stt: true, agent: true}`)
- [ ] Operator kill switch (`DEMO_ENABLED=false` → 503 from mint endpoint)
- [ ] PHP/Node endpoint loads keys from `.env`, not committed to repo

## Reference implementation in this repo

- `cartesia-token.php` — PHP token mint endpoint (CORS, rate limit)
- `demo/joyalukkas-cartesia.html` — full vanilla JS browser demo (orb, transcript, error handling)
- `cartesia-call.php` — outbound phone call endpoint (alt path for phone-based demos)

## Reference implementation in BJP project

- `/Users/suyashraj/Downloads/07 Tech Projects/BJP Voice Agent/web/lib/cartesia.ts` — Node/TS outbound + transcript listing
- `/Users/suyashraj/Downloads/07 Tech Projects/BJP Voice Agent/web/app/api/agent-token/route.ts` — Next.js token endpoint
- `/Users/suyashraj/Downloads/07 Tech Projects/BJP Voice Agent/web/components/BrowserDemo.tsx` — React voice client (source of the patterns above)

## Recap (the things you'll forget in 3 months)

1. **WebSocket URL**: `wss://api.cartesia.ai/agents/stream/{agentId}?cartesia_version=...&access_token=...`. Token + version go in QUERY STRING, not headers.
2. **`start` event** opens the stream. Pass `config: { input_format: 'pcm_16000' }`.
3. **Audio in**: 16kHz mono PCM-16 LE, base64-encoded, in `media_input` event with `media.payload`.
4. **Audio out**: same format in `media_output` event. Decode → Int16 → Float32 / 32768 → AudioBuffer → schedule with `playhead = max(playhead, ctx.currentTime)`.
5. **Auth**: `Authorization: Bearer sk_car_...` (NOT `X-API-Key`). All Cartesia REST.
6. **Synchronous click guard**: `let starting = false; if (ws || starting) return; starting = true;`
7. **Token endpoint**: returns either `token` or `access_token` — accept both.
8. **HTTPS required** for `getUserMedia`. Don't waste time debugging on HTTP.
9. **Agent name must match `^[a-z0-9_\-.]+$`** when patching via REST.
10. **Cleanup on `beforeunload`** — otherwise tab close leaves WebSocket open.
