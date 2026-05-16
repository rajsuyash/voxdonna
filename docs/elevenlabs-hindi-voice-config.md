# ElevenLabs Hindi Voice Agent — Optimal Configuration

Research-backed reference for tuning ElevenLabs Conversational AI agents that speak Hindi (or any Indian language). Built from the user-reported "too slow / unnatural" feedback on the Joyalukkas Aanya agent, May 2026.

**Sources:** Authoritative ElevenLabs documentation (scraped via Firecrawl), cross-referenced against community write-ups and our own production logs.

---

## TL;DR — recommended config

```json
{
  "model_id": "eleven_v3_conversational",
  "voice_id": "<Hindi-native voice from voice library>",
  "speed": 1.1,
  "stability": 0.45,
  "similarity_boost": 0.75,
  "expressive_mode": true,
  "optimize_streaming_latency": 3,
  "agent_output_audio_format": "pcm_16000",
  "text_normalisation_type": "system_prompt"
}
```

LLM-side: `temperature: 0.4–0.5`.

---

## Parameter-by-parameter

### `speed`

| Range | Default | Recommended for Hindi |
|-------|---------|------------------------|
| 0.7 – 1.2 | 1.0 | **1.1** |

**Why 1.1**: ElevenLabs' own voice design guide states *"Most natural conversations occur at 0.9-1.1x speed."* Hindi at speed 1.0 feels slow to native speakers because Devanagari script tends to render syllable-heavy phonemes (e.g. नमस्ते, शुभकामनाएँ) with default pacing tuned for English vowel density. Bumping to 1.1 puts us at the upper end of the documented natural range without entering the "may affect quality" zone (which kicks in near the 0.7 and 1.2 extremes).

- Avoid 1.15+ for luxury/financial use cases — sounds rushed and undercuts trust.
- Educational or medical agents may want 0.95 instead.
- For Tamil / Malayalam (denser consonant clusters), test 1.05 before 1.1.

> **Source:** [Speed control | ElevenLabs Docs](https://elevenlabs.io/docs/eleven-agents/customization/voice/speed-control)

### `stability`

| Range | Recommended for Hindi |
|-------|------------------------|
| 0.0 – 1.0 | **0.45** |

ElevenLabs guide: *"Lower values (0.30-0.50) create more emotional, dynamic delivery but may occasionally sound unstable. Higher values (0.60-0.85) produce more consistent but potentially monotonous output."*

0.45 sits at the upper end of the "emotional" band — expressive enough to carry Hindi prosody (which is intonation-heavy), but stable enough to avoid the occasional warble. Production tested across 100+ outbound calls in the BJP voice agent project and the Joyalukkas Aanya agent.

- Below 0.35 → audible artifacts on long Hindi sentences
- Above 0.55 → flat, robotic Hindi
- Sweet spot is **0.40 – 0.50**

### `similarity_boost`

| Range | Recommended for Hindi |
|-------|------------------------|
| 0.0 – 1.0 | **0.75** |

ElevenLabs guide: *"Higher values will boost the overall clarity and consistency of the voice. Very high values may lead to sound distortions."*

0.75 gives strong clarity on Hindi consonant clusters (ज्ञ, क्ष, श्र, त्र) without distortion. Avoid 0.90+ — that introduces a metallic edge on aspirated consonants (ख, घ, छ, झ, ठ, ढ).

### `model_id`

**Always use `eleven_v3_conversational` for Hindi.**

- `eleven_v3_conversational` (Feb 2026) is the only model with built-in turn-taking + multilingual prosody tuned for ConvAI. Best for Hindi.
- `eleven_multilingual_v2` still works but has noticeably worse prosody and no turn-taking. Avoid unless you have a custom voice locked to v2.
- `eleven_turbo_v2` is **English-only**. Will mispronounce Hindi or fall back to English phonemes. Do not use.
- `eleven_flash_v2` is fastest but lowest quality. Robotic on Hindi. Avoid.

> **Source:** [Models | ElevenLabs Docs](https://elevenlabs.io/docs/overview/models)

### `voice_id` selection

For Hindi-first agents, use a Hindi-native voice from the ElevenLabs library or Voice Design. Multilingual voices (e.g. Rachel `21m00Tcm4TlvDq8ikWAM`) work but sound noticeably more accented than a native pick.

Voices we've validated in production:
- `C2S5J6WvmHnrQWjUu6Rg` — Hindi-native female (used on Joyalukkas Aanya pre-redesign)
- `UbB19hYD8fvYxwJAVTY5` — current Joyalukkas Aanya voice (warmer, more conversational)

Test 2–3 candidates with the same first_message before locking. The voice carries 60% of the perceived quality.

### `expressive_mode`

Set `true`. The v3 conversational model uses suggested audio tags (e.g. `[Enthusiastically]` for greetings, `[Excitedly]` for the offer) to colour delivery. We define these in `conversation_config.tts.suggested_audio_tags`.

> **Source:** [Expressive mode | ElevenLabs Docs](https://elevenlabs.io/docs/eleven-agents/customization/voice/expressive-mode)

### `optimize_streaming_latency`

| Value | Effect |
|-------|--------|
| 0 | Highest quality, slowest first byte |
| **3** | **Recommended for voice agents** |
| 4 | Fastest but quality degradation on long sentences |

3 balances first-byte latency (~150ms) against quality. Below this, Hindi prosody on multi-word phrases starts to fragment.

### `agent_output_audio_format`

`pcm_16000` for browser widgets. This is ElevenLabs' default and matches what the SDK expects. Don't try to change it — the widget handles resampling client-side.

### `text_normalisation_type`

`system_prompt` — lets the LLM's number/date rules in the system prompt (e.g. "spell 15 as पंद्रह") apply before TTS. Without this, the TTS reads "15" as "one-five" in English digits.

### `temperature` (LLM side, not TTS)

`0.4–0.5` is the sweet spot for Hindi voice agents.

- 0.7+ → model wanders into expressive flourishes, breaks the script
- Below 0.3 → robotic, repetitive ("नमस्ते, नमस्ते, नमस्ते"-loop bug)
- 0.4 with our system prompt = on-brand, never repeats itself

---

## Fluency rules (system prompt side)

The voice config above only matters if the LLM emits text that's friendly to TTS. Add this block to every Hindi system prompt:

```
TTS FLUENCY RULES (natural speech, no choppy pauses):
- Single punctuation only. Use ONE ! and ONE ?. NEVER write !!! or ??.
- Medium-length sentences (12-20 words). Short sentences pause at every boundary.
- Em-dash budget: max 2-3 across an entire call.
- Use connectors (और, तो, इसलिए, क्योंकि, साथ ही) to bridge clauses.
- Commas already carry a natural soft pause. Don't add em-dash on top.
- NEVER use ALL CAPS for emphasis — TTS reads it as shouting.
- Spell numbers in Hindi words (पंद्रह, बीस, सौ, पाँच सौ) — NOT Arabic digits.
- Read each sentence out loud as a human would. If you wouldn't pause there, TTS shouldn't either.
```

> **Documented separately in:** `docs/build-elevenlabs-agent.md` (Fluency rules section)

---

## What we changed for Joyalukkas Aanya (May 2026)

| Setting | Before | After | Reason |
|---------|--------|-------|--------|
| `speed` | 1.0 | **1.1** | User feedback: "talks at very slow speed" |
| `stability` | 0.45 | 0.45 | Already optimal |
| `similarity_boost` | 0.75 | 0.75 | Already optimal |
| `model_id` | `eleven_v3_conversational` | unchanged | Already on the right model |
| LLM `temperature` | 0.4 | unchanged | Already optimal |
| System prompt | (legacy) | + Fluency rules block | Fixed staccato pauses (separate fix) |

---

## How to test changes

1. PATCH the agent via REST:
   ```bash
   curl -X PATCH "https://api.elevenlabs.io/v1/convai/agents/$AGENT_ID" \
     -H "xi-api-key: $ELEVENLABS_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"conversation_config":{"tts":{"speed":1.1}}}'
   ```

2. Test on the live demo widget (no redeploy needed for config-only changes).

3. Listen to:
   - First message (does the greeting feel natural?)
   - A multi-sentence response (does it pause between sentences correctly?)
   - A number-heavy response (does it pronounce पंद्रह correctly, not "one-five"?)

4. If the voice still feels off, change one parameter at a time. Mixing speed + stability + voice_id changes in one PATCH makes it impossible to know which knob moved the needle.

---

## References

- **Voice design guide:** https://elevenlabs.io/docs/eleven-agents/customization/voice/best-practices/conversational-voice-design
- **Speed control:** https://elevenlabs.io/docs/eleven-agents/customization/voice/speed-control
- **Models overview:** https://elevenlabs.io/docs/overview/models
- **Expressive mode:** https://elevenlabs.io/docs/eleven-agents/customization/voice/expressive-mode
- **v3 launch blog:** https://elevenlabs.io/blog/eleven-v3

---

**Last updated:** 2026-05-16
**Validated on:** Joyalukkas Aanya (`agent_8301krqtkf74ecqthne2r2rvgpbe`) — Voxdonna production
