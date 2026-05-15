# Siya Voice Agent — aisewak.com Integration Handoff

Drop-in spec for embedding the Voxdonna **Siya** (Yatri Sahayak) Hindi voice agent on `aisewak.com`. Self-contained: a fresh Claude session in the aisewak.com folder can ship this end-to-end with no external context.

## Who is Siya?

Siya is the Hindi-first AI voice agent built by Voxdonna for the UP Transport Department pitch (Minister Daya Shankar Singh). She handles:

1. RTO — driving licence status, slot booking, renewal
2. RTO — vehicle registration, RC renewal, fitness certificate
3. UPSRTC — bus enquiry, fares, lost-and-found, refunds
4. E-challan — outstanding fines, dispute filing
5. Road safety / emergency — 24×7 intake, escalation to 112/108

She opens every call with a minister-praise framing (already baked into the agent):

> "नमस्ते, मैं सिया हूँ — उत्तर प्रदेश के परिवहन मंत्री श्री दया शंकर सिंह जी की नई पहल, ए आई यात्री सहायक..."

## Agent identity (lock these into your env)

```
ELEVENLABS_AGENT_ID = agent_0501krna5z08efybb2ptrs0whc5r
ELEVENLABS_VOICE_ID = C2S5J6WvmHnrQWjUu6Rg   (Hindi-native, user-selected)
ELEVENLABS_MODEL    = eleven_multilingual_v2
ELEVENLABS_LLM      = gpt-4o-mini
STABILITY           = 0.45
SIMILARITY_BOOST    = 0.75
LANGUAGE            = en (config-level; the multilingual model handles Hindi switching at runtime)
```

The agent is **already provisioned**. You do not need to re-create it. Just embed the SDK and pass the `agent_id`.

## ElevenLabs API key

If aisewak.com already has an `ELEVENLABS_API_KEY` env var, **you do not need it for the embed** — the ConvAI SDK opens a public WebRTC session against the agent_id directly. The API key is only needed for:

- Creating/updating agents (already done on Voxdonna side)
- Reading analytics (`/v1/convai/analytics/live-count`)
- KB uploads

For browser embed: **no API key needed in the frontend**. Safe to deploy on Railway public-facing.

## Drop-in embed (the canonical pattern)

This is the exact pattern we use on `voxdonna.com/demo/up-transport-yatri-sahayak.html`. Battle-tested. Includes the rapid-click race fix.

```html
<!-- 1. Markup: orb + start/end buttons + status -->
<div id="siya-stage">
  <button id="siya-orb" type="button" aria-label="Start the call with Siya"></button>
  <p id="siya-status">Click the orb to start the call</p>
  <button id="siya-start" type="button">Start the call</button>
  <button id="siya-end" type="button" hidden>End call</button>
</div>

<!-- 2. SDK + handler (ES module) -->
<script type="module">
  import { Conversation } from 'https://esm.sh/@elevenlabs/client@1.4.0?deps=livekit-client@2.11.4';

  const AGENT_ID = 'agent_0501krna5z08efybb2ptrs0whc5r';

  const orb      = document.getElementById('siya-orb');
  const startBtn = document.getElementById('siya-start');
  const endBtn   = document.getElementById('siya-end');
  const status   = document.getElementById('siya-status');

  let conv = null;
  let starting = false; // CRITICAL: guards against rapid double-clicks

  function setStatus(msg) { status.textContent = msg || ''; }
  function setActive(on) {
    document.body.classList.toggle('siya-active', on);
    startBtn.hidden = on;
    endBtn.hidden   = !on;
  }

  async function start() {
    // Guard against rapid clicks during the connecting window.
    if (conv || starting) return;
    starting = true;
    setActive(true);
    setStatus('connecting…');

    try {
      conv = await Conversation.startSession({
        agentId: AGENT_ID,
        onConnect:    () => setStatus('live · listening'),
        onDisconnect: () => {
          setActive(false);
          setStatus('call ended');
          conv = null;
          starting = false;
          setTimeout(() => setStatus('Click the orb to start the call'), 4000);
        },
        onError: (err) => {
          console.error('[Siya]', err);
          setStatus('error: ' + ((err && err.message) || 'failed'));
          setActive(false);
          conv = null;
          starting = false;
        },
        onModeChange: (m) => {
          const mode = (m && m.mode) || m;
          if (mode === 'speaking')  setStatus('live · Siya speaking');
          if (mode === 'listening') setStatus('live · listening');
        }
      });
      starting = false;
    } catch (err) {
      console.error('[Siya] start failed', err);
      setStatus('could not start — allow microphone and try again');
      setActive(false);
      starting = false;
    }
  }

  function end() {
    if (conv) { try { conv.endSession(); } catch (_) {} conv = null; }
    starting = false;
    setActive(false);
    setStatus('call ended');
    setTimeout(() => setStatus('Click the orb to start the call'), 4000);
  }

  orb.addEventListener('click', start);
  startBtn.addEventListener('click', start);
  endBtn.addEventListener('click', end);
  orb.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); start(); }
  });
</script>
```

**Critical**: the `starting` flag is non-negotiable. Without it, double-clicking the orb during the ~500ms connecting window spawns parallel sessions and burns the 5-concurrent ElevenLabs Creator tier cap.

## React / Next.js version

If aisewak.com is React:

```bash
npm install @elevenlabs/client@1.4.0 livekit-client@2.11.4
```

```tsx
'use client';
import { useState, useRef, useEffect } from 'react';
import { Conversation } from '@elevenlabs/client';

const AGENT_ID = 'agent_0501krna5z08efybb2ptrs0whc5r';

export function SiyaWidget() {
  const [status, setStatus] = useState('Click the orb to start the call');
  const [active, setActive] = useState(false);
  const convRef = useRef<any>(null);
  const startingRef = useRef(false);

  async function start() {
    if (convRef.current || startingRef.current) return;
    startingRef.current = true;
    setActive(true);
    setStatus('connecting…');

    try {
      convRef.current = await Conversation.startSession({
        agentId: AGENT_ID,
        onConnect:    () => setStatus('live · listening'),
        onDisconnect: () => {
          setActive(false);
          setStatus('call ended');
          convRef.current = null;
          startingRef.current = false;
          setTimeout(() => setStatus('Click the orb to start the call'), 4000);
        },
        onError: (err: any) => {
          console.error('[Siya]', err);
          setStatus('error: ' + (err?.message || 'failed'));
          setActive(false);
          convRef.current = null;
          startingRef.current = false;
        },
        onModeChange: (m: any) => {
          const mode = m?.mode || m;
          if (mode === 'speaking')  setStatus('live · Siya speaking');
          if (mode === 'listening') setStatus('live · listening');
        },
      });
      startingRef.current = false;
    } catch (err: any) {
      console.error('[Siya] start failed', err);
      setStatus('could not start — allow microphone and try again');
      setActive(false);
      startingRef.current = false;
    }
  }

  function end() {
    if (convRef.current) { try { convRef.current.endSession(); } catch (_) {} convRef.current = null; }
    startingRef.current = false;
    setActive(false);
    setStatus('call ended');
    setTimeout(() => setStatus('Click the orb to start the call'), 4000);
  }

  return (
    <div className={`siya-stage ${active ? 'active' : ''}`}>
      <button className="siya-orb" onClick={start} aria-label="Start the call with Siya" />
      <p className="siya-status">{status}</p>
      {!active ? (
        <button className="siya-btn primary" onClick={start}>Start the call</button>
      ) : (
        <button className="siya-btn danger" onClick={end}>End call</button>
      )}
    </div>
  );
}
```

## Integration options (pick what fits aisewak.com's UX)

### Option 1 — Full-page hero (cleanest, highest engagement)

A dedicated `/siya` or `/yatri-sahayak` route. Big orb in center, scenario prompt below, "Start the call" CTA. Same pattern as `voxdonna.com/demo/up-transport-yatri-sahayak.html`. Best for sales links sent to government stakeholders.

### Option 2 — Floating widget (lowest friction)

Bottom-right orb on every page. Click to expand into a call interface. Same pattern as Intercom chat. Good for citizen-facing flows where Siya is one of many tools.

### Option 3 — Button-trigger inline (best for content pages)

A "Talk to Siya about RTO" button embedded in a page about RTO services. Click → modal opens → orb appears. Contextual, ties Siya to the topic the user is reading.

**Recommendation for aisewak.com**: Option 1 first (dedicated page). It mirrors how the voxdonna demo is structured and gives a clean URL to share with the minister.

## Brand adaptation

Voxdonna's demo page is dark theme + copper accent (`#0a0a0c` bg, `#c17f59` copper). **Do not copy these tokens onto aisewak.com.** Use aisewak.com's existing design tokens.

**What to keep (concept-level):**
- The orb as the central interactive element (it's the affordance — users intuit "talk")
- The breathe + pulse-ring animation (makes the orb feel alive while idle)
- "Start the call" + "End call" button pattern (don't reinvent — users understand it)
- The `connecting…` → `live · listening` → `live · Siya speaking` status flow (manages expectations)

**What to swap:**
- Colors: use aisewak.com's palette (likely blue/saffron/white given govt-India theme — pull from `tailwind.config.js` or design-tokens file in the repo).
- Typography: match aisewak.com's font stack.
- Page layout: match aisewak.com's header/nav/footer.

**Minimum CSS to make the orb work** (adapt colors to your palette):

```css
.siya-orb {
  width: 200px;
  height: 200px;
  border-radius: 50%;
  border: none;
  cursor: pointer;
  background: radial-gradient(circle at 30% 30%,
    /* highlight */   var(--orb-light, #f3d4a8) 0%,
    /* mid */         var(--orb-mid, #c17f59) 25%,
    /* dark */        var(--orb-dark, #5b8aa8) 60%,
    /* edge */        var(--orb-edge, #1c2e4a) 90%);
  box-shadow:
    0 0 40px var(--orb-glow, rgba(193, 127, 89, 0.3)),
    inset -15px -20px 40px rgba(0, 0, 0, 0.5);
  animation: siya-breathe 7s ease-in-out infinite;
  transition: transform 0.3s;
}
.siya-orb:hover { transform: scale(1.05); }

body.siya-active .siya-orb {
  animation: siya-active 1.6s ease-in-out infinite;
}

@keyframes siya-breathe {
  0%, 100% { transform: scale(1); filter: brightness(1); }
  50%      { transform: scale(1.04); filter: brightness(1.15); }
}
@keyframes siya-active {
  0%, 100% { box-shadow: 0 0 70px var(--orb-glow), 0 0 140px var(--orb-glow); }
  50%      { box-shadow: 0 0 100px var(--orb-glow), 0 0 200px var(--orb-glow); }
}
```

For an Indian-government palette, set these CSS variables on `:root`:

```css
:root {
  --orb-light: #ffd089;   /* warm saffron highlight */
  --orb-mid:   #ff9933;   /* India flag saffron */
  --orb-dark:  #138808;   /* India flag green (deep) */
  --orb-edge:  #0a3d1f;
  --orb-glow:  rgba(255, 153, 51, 0.35);
}
```

## First message (already locked in the agent)

> "नमस्ते, मैं सिया हूँ — उत्तर प्रदेश के परिवहन मंत्री श्री दया शंकर सिंह जी की नई पहल, ए आई यात्री सहायक। यह सेवा आपके transport से जुड़े काम — driving licence, vehicle registration, UPSRTC bus, e-challan — को आसान बनाएगी। बताइए, मैं आपकी कैसे सहायता कर सकती हूँ?"

You cannot change this from aisewak.com — it's set on the ElevenLabs agent. If aisewak.com is **not** specifically a UP Transport pitch (e.g., it's a broader Indian-govt AI Sewak service), you have two options:

1. **Use the existing Siya as-is**. She introduces herself as the UP Transport minister's initiative — fine if aisewak.com is positioning itself as a UP Transport service.
2. **Create a new agent for aisewak.com** with a different opener (e.g., "नमस्ते, मैं सिया हूँ — AI Sewak की voice सहायक"). Use the build pattern in `voxdonna/docs/build-elevenlabs-agent.md` or the slash command `/build-elevenlabs-agent`. You'll need the ElevenLabs API key on the aisewak.com side.

Recommended: if aisewak.com is a multi-department AI service, **create a new agent** with a generic opener so it doesn't tie to UP Transport specifically.

## Hard rules (already in the agent's system prompt)

Even if you change the wrapper UX, these behaviors are baked into Siya — don't try to override them from the frontend:

- Always declares herself as AI at start
- Never collects Aadhaar, card, UPI, or bank details
- Never claims to be a human government official, IAS officer, RTO employee, or the minister himself
- Never quotes guaranteed timelines (uses "सरकारी प्रक्रिया के अनुसार X दिन के अंदर")
- For injury / fire / threat → instructs caller to dial 112 and ends call
- Responds in Devanagari script (English allowed for technical terms like "driving licence", "RTO", "RC")

## Concurrency limit reminder

ElevenLabs Creator tier = **5 concurrent TTS slots**. For Siya's use pattern (~30-40% AI talk time, rest is human), this supports ~100 simultaneous calls. With bursting enabled on the agent (already done), 3× burst at 2× rate is available.

If you expect high traffic on aisewak.com:
- Monitor active calls: `GET https://api.elevenlabs.io/v1/convai/analytics/live-count?agent_id=agent_0501krna5z08efybb2ptrs0whc5r` (requires API key)
- Plan upgrade path to ElevenLabs Pro/Scale tier before any media push

## Production migration path (Bhashini)

This is what to pitch in your "production" message on aisewak.com:

> "Demo runs on ElevenLabs for voice quality. Production deploys on **Bhashini** — MeitY's National Language Translation Mission — for data sovereignty, GeM procurement listing, and zero foreign-cloud dependency. Voxdonna's orchestration layer (KB, escalation rules, dialogue logic) sits on top, independent of the voice provider."

Bhashini info: https://bhashini.gov.in

## Files to create on aisewak.com

Minimum viable integration:

```
aisewak.com/
├── app/siya/page.tsx          (or pages/siya.tsx)         # Option 1 full-page
├── components/SiyaWidget.tsx                              # The widget component
├── styles/siya.module.css                                 # Orb + buttons styles
└── .env.local
    NEXT_PUBLIC_SIYA_AGENT_ID=agent_0501krna5z08efybb2ptrs0whc5r
```

If aisewak.com is not Next/React, adapt the markup + script from the vanilla JS section above.

## Verification checklist

After the fresh Claude wires this up:

- [ ] `npm install @elevenlabs/client livekit-client` (if React)
- [ ] Page loads at `aisewak.com/siya` (or wherever)
- [ ] Click the orb → opens microphone permission → connects in <2s
- [ ] First message plays in clean Devanagari Hindi
- [ ] Rapid double-click does NOT spawn parallel sessions (check ElevenLabs live-count stays at 1)
- [ ] End call button cleanly terminates
- [ ] Status text cycles: "Click the orb…" → "connecting…" → "live · listening" → "live · Siya speaking" → "call ended"
- [ ] Mic permission denial shows clear error: "could not start — allow microphone and try again"
- [ ] On mobile (iOS Safari + Android Chrome) the orb is tappable and the call works
- [ ] Network throttling test (slow 3G) — connection still succeeds within ~5s

## Quick-test URL

While building, you can test the existing Voxdonna demo to confirm the agent works:

**https://voxdonna.com/demo/up-transport-yatri-sahayak.html**

If that page works, the agent is live. Then the aisewak.com integration is purely a UX wrapper.

## Questions for the fresh Claude session

1. What is aisewak.com built with? (Next.js / Astro / vanilla / WordPress / Streamlit / something else)
2. What's the existing design system? (Tailwind config / CSS variables / theme tokens)
3. Should Siya be the only agent, or one of several on the site?
4. Is the UP Transport minister angle in the opening message correct for aisewak.com's positioning, or should we create a separate agent?
5. Mobile-first or desktop-first?

Answer those first, then implement.

## Voxdonna-side contact

If you hit a blocker that requires changes on the agent itself (system prompt, voice, KB), come back to the Voxdonna repo and use the `/build-elevenlabs-agent` skill or follow `docs/build-elevenlabs-agent.md`. Do not try to recreate the agent from aisewak.com side without an ElevenLabs API key.
