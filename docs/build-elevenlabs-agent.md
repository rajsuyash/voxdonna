---
name: build-elevenlabs-agent
description: Build a new ElevenLabs Conversational AI demo agent for Voxdonna — write the KB, create the agent via API, wire it into demos.html. Use when the user asks to add a new voice agent demo, build a vertical-specific Donna, or create a product advisor agent for a new use case.
---

# Build an ElevenLabs Conversational AI Demo Agent

Self-contained playbook for adding a new Voxdonna voice agent to the demos gallery. Battle-tested on 14 production agents.

## When to use

- User says "add a new demo for X vertical / industry / use case"
- User says "build a voice agent for [scenario]"
- User says "create a new Donna for [thing]"
- User wants to clone an existing agent with a different KB + voice persona

## Prerequisites (verify before starting)

```bash
# 1. API key must be present
grep '^ELEVENLABS_API_KEY=' .env || echo "MISSING — ask user for key"

# 2. Voice IDs available
# Jessica (default English):  cgSgspJ2msm6clMCkdW9
# Rachel (multilingual / Hindi / FR / IT): 21m00Tcm4TlvDq8ikWAM

# 3. KB directory exists
mkdir -p kb scripts
```

## Step 1 — Author the knowledge base

Every agent needs a `.md` KB in `kb/<slug>.md`. Target 1200-1800 words. More than 1800 and the agent starts hallucinating product specs. Less than 1200 and it can't answer real questions.

### KB structure (mandatory sections)

```markdown
# <Brand Name> — Knowledge Base for Donna

Operational reference for Donna, the <role description> for <Brand>.

## What Donna Demonstrates Here

Critical: clarify what the agent IS and IS NOT. For product-advisor demos (most cases), state that Donna explains the platform to a prospect — she is NOT a real-world operator (not a real karyakarta, not a real celebrity, not a real doctor giving medical advice).

## Company / Product Overview
<5-8 bullets: founding, HQ, hours, certifications, key facts>

## Product Catalog / Services
<grouped by category, specific SKU/model names if applicable>

## Industries Served / Target Customers
<who buys this, what use cases>

## Pricing Model
<ranges, not exact quotes — defer specific pricing to human>

## Timeline
<typical kickoff to live duration>

## Compliance / Hard Rules (REQUIRED)
- Always declare yourself as AI at the start of the call.
- Never claim to be human or impersonate a named person.
- Never quote final pricing — defer to human team.
- Refuse: <specific verticals or asks that don't fit>
- Escalate: <safety topics, threats, illegal activity>

## Sample Opening
<the first message Donna says>

## Sample Talking Points
<3-5 sound-bite explanations of value>

## Out-of-Scope
<bullet list of what Donna does NOT do>
```

### KB authoring rules (learned the hard way)

- **No marketing fluff.** Donna reads this and hallucinates if you write "best-in-class" or "industry-leading." Use concrete numbers.
- **Specific SKUs, named products, exact hours.** Not "we have many products" — list them.
- **One KB per agent.** Do not share a KB across two agents — Donna picks the wrong context.
- **Banned words from CLAUDE.md still apply.** No "delve, robust, comprehensive, leverage, pivotal, intricate, vibrant."
- **Compliance section is mandatory.** Even for benign verticals — the demo is in front of prospects.

## Step 2 — Voice + model selection

| Use case | Voice | Model | Stability | Why |
|---|---|---|---|---|
| English-only B2B vertical | Jessica `cgSgspJ2msm6clMCkdW9` | `eleven_turbo_v2` | 0.35 | Default. Most demos. Warm, builder-tone. |
| Multilingual (Hindi/FR/IT/multi) | Rachel `21m00Tcm4TlvDq8ikWAM` | `eleven_multilingual_v2` | 0.35 | Handles language switching mid-call. |

**Hard rules from prior sessions:**
- Never use `eleven_flash_v2` — sounds robotic. Killed every demo we tested it on.
- Never set stability ≥0.5 — kills emotional variation. 0.35 is the sweet spot.
- Never set `similarity_boost` below 0.6 — voice starts drifting.
- Default `similarity_boost: 0.75`.

`expressive_mode` flag is silently ignored on English ConvAI agents (requires v3 model not available there). Do not set it — workaround is turbo_v2 + low stability.

## Step 3 — Create agent via API

Use this script pattern. Copy from `scripts/create-india-agents.sh` if it exists in the repo. Otherwise, here is the canonical version:

```bash
#!/bin/bash
# scripts/create-agent.sh — create one ElevenLabs ConvAI agent
set -e
cd "$(dirname "$0")/.."

API_KEY=$(grep '^ELEVENLABS_API_KEY=' .env | cut -d= -f2)
[ -z "$API_KEY" ] && { echo "ERROR: ELEVENLABS_API_KEY missing"; exit 1; }

# === CUSTOMIZE THESE ===
AGENT_NAME="Voxdonna <Vertical> Demo"
KB_FILE="<slug>.md"                                  # in kb/
VOICE_ID="cgSgspJ2msm6clMCkdW9"                      # Jessica (or Rachel for multilingual)
MODEL_ID="eleven_turbo_v2"                           # or eleven_multilingual_v2
FIRST_MSG="Hi, I am Donna from Voxdonna. <2-line opener customized to the vertical>"
SYSTEM_PROMPT="You are Donna, an AI product advisor for <product>. You explain how <product> works. You are NOT a real <operator>. Always declare yourself as AI at the start. Be direct, builder-tone, no fluff. Defer pricing to human team. Use attached KB for all facts. Keep responses under 60 seconds."
# === END CUSTOMIZE ===

# Step 3a: upload KB doc (content-type MUST be specified, or API rejects)
echo "Uploading KB: $KB_FILE"
KB_RESPONSE=$(curl -sS -X POST "https://api.elevenlabs.io/v1/convai/knowledge-base/file" \
  -H "xi-api-key: $API_KEY" \
  -F "name=$KB_FILE" \
  -F "file=@kb/$KB_FILE;type=text/markdown")

KB_ID=$(echo "$KB_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")
[ -z "$KB_ID" ] && { echo "ERROR: KB upload failed. Response: $KB_RESPONSE"; exit 1; }
echo "KB ID: $KB_ID"

# Step 3b: create agent with KB attached
AGENT_PAYLOAD=$(python3 -c "
import json, os
payload = {
  'name': '$AGENT_NAME',
  'conversation_config': {
    'agent': {
      'first_message': '''$FIRST_MSG''',
      'language': 'en',
      'prompt': {
        'prompt': '''$SYSTEM_PROMPT''',
        'llm': 'gpt-4o-mini',
        'temperature': 0.4,
        'max_tokens': 512,
        'knowledge_base': [{'type': 'file', 'name': '$KB_FILE', 'id': '$KB_ID', 'usage_mode': 'auto'}]
      }
    },
    'tts': {
      'voice_id': '$VOICE_ID',
      'model_id': '$MODEL_ID',
      'stability': 0.35,
      'similarity_boost': 0.75
    },
    'asr': {
      'quality': 'high',
      'provider': 'elevenlabs',
      'user_input_audio_format': 'pcm_16000',
      'keywords': []
    },
    'turn': {
      'turn_timeout': 10,
      'silence_end_call_timeout': 25,
      'mode': 'turn'
    }
  }
}
print(json.dumps(payload))
")

AGENT_RESPONSE=$(curl -sS -X POST "https://api.elevenlabs.io/v1/convai/agents/create" \
  -H "xi-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$AGENT_PAYLOAD")

AGENT_ID=$(echo "$AGENT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))")
[ -z "$AGENT_ID" ] && { echo "ERROR: Agent create failed. Response: $AGENT_RESPONSE"; exit 1; }

echo "AGENT_ID: $AGENT_ID"
echo "$AGENT_NAME=$AGENT_ID" >> scripts/agent-ids.txt
```

Run it:
```bash
chmod +x scripts/create-agent.sh
bash scripts/create-agent.sh
```

### Critical fix: file upload content-type

The ElevenLabs `/v1/convai/knowledge-base/file` endpoint rejects markdown files unless you explicitly set the MIME type in the multipart form:

```bash
# WRONG — returns 422 "Invalid file type"
-F "file=@kb/foo.md"

# RIGHT — explicit content-type
-F "file=@kb/foo.md;type=text/markdown"
```

Allowed MIME types: `application/epub+zip`, `application/pdf`, `application/vnd.openxmlformats-officedocument.wordprocessingml.document`, `text/plain`, `text/html`, `text/markdown`, `text/x-markdown`.

## Step 4 — Verify the agent

```bash
API_KEY=$(grep '^ELEVENLABS_API_KEY=' .env | cut -d= -f2)
curl -sS "https://api.elevenlabs.io/v1/convai/agents/$AGENT_ID" \
  -H "xi-api-key: $API_KEY" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('Name:', d.get('name'))
print('Voice:', d.get('conversation_config',{}).get('tts',{}).get('voice_id'))
print('Model:', d.get('conversation_config',{}).get('tts',{}).get('model_id'))
print('KB count:', len(d.get('conversation_config',{}).get('agent',{}).get('prompt',{}).get('knowledge_base',[])))
"
```

Expect: name set, voice ID matches, model matches, KB count ≥ 1.

## Step 5 — Wire into demos.html

Open `demos.html`. Find the last `<article class="demo-card" ...>` block before `</section>` and the demos-cta section. Insert a new `<article>` immediately before that closing `</section>`.

### Demo card template

```html
    <article class="demo-card" data-agent-id="AGENT_ID_FROM_STEP_3" data-language="en">
      <div class="demo-card-header">
        <span class="demo-card-tag">CATEGORY NAME</span>
        <span class="demo-card-lang">EN</span>
      </div>
      <h3 class="demo-card-title">SHORT SCENARIO TITLE</h3>
      <p class="demo-card-desc">One-sentence description of what Donna does in this demo. Use real verbs. Mention 2-3 concrete things she captures or actions she takes.</p>
      <div class="demo-card-scenario">"Quoted line a real caller might say to open the conversation."</div>
      <button class="demo-card-orb-wrap" type="button" aria-label="Start demo: TITLE">
        <div class="demo-card-orb"></div>
        <div class="demo-card-orb-pulse"></div>
      </button>
      <div class="demo-card-actions">
        <button type="button" class="demo-card-btn demo-card-btn-start">
          <span class="demo-card-btn-icon primary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.96.37 1.9.72 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.35 1.85.59 2.81.72A2 2 0 0 1 22 16.92z"/></svg>
          </span>
          <span>Try Demo</span>
        </button>
        <button type="button" class="demo-card-btn demo-card-btn-end">
          <span class="demo-card-btn-icon danger">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.68 13.31a16 16 0 0 0 3.41 2.6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7 2 2 0 0 1 1.72 2v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.42 19.42 0 0 1-3.33-2.67m-2.67-3.34a19.79 19.79 0 0 1-3.07-8.63A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91"/><line x1="23" y1="1" x2="1" y2="23"/></svg>
          </span>
          <span>End Call</span>
        </button>
      </div>
      <div class="demo-card-status"></div>
    </article>
```

### Replace tokens

- `AGENT_ID_FROM_STEP_3` → the `agent_id` your script printed.
- `CATEGORY NAME` → vertical tag (e.g., "Hospitality", "Manufacturing", "Elections India").
- `EN` → `EN`, `FR`, `IT`, or `EN/HI` etc.
- Title, desc, scenario quote → fill from the KB.

### Update demo count metadata

After adding the card:

```bash
# Count cards
NEW_COUNT=$(grep -c '<article class="demo-card"' demos.html)

# Update meta in demos.html
sed -i '' "s/[0-9]* live AI voice agents/${NEW_COUNT} live AI voice agents/g" demos.html
sed -i '' "s/[0-9]* Live AI Voice Agent Demos/${NEW_COUNT} Live AI Voice Agent Demos/g" demos.html
sed -i '' "s/\"numberOfItems\": [0-9]*/\"numberOfItems\": ${NEW_COUNT}/" demos.html

# Update home page
sed -i '' "s/[0-9]* live demos/${NEW_COUNT} live demos/g" index.html
sed -i '' "s/All [0-9]* demos/All ${NEW_COUNT} demos/g" index.html
```

## Step 6 — Commit + deploy

```bash
git add kb/<slug>.md scripts/create-agent.sh scripts/agent-ids.txt demos.html index.html
git commit -m "feat(demos): add <vertical> agent (<agent_id>)"
git push origin main
```

Hostinger webhook auto-deploys in ~10-30s. If it stalls:

```bash
# Option A: empty commit retrigger
git commit --allow-empty -m "chore: retrigger deploy webhook"
git push origin main

# Option B: SSH manual fallback (per CLAUDE.md)
# ssh into Hostinger and: git fetch origin && git merge --ff-only origin/main
```

Verify deploy:
```bash
curl -sS https://voxdonna.com/demos.html | grep -c '<article class="demo-card"'
# expect: matches NEW_COUNT from step 5
```

## Common gotchas (and fixes)

| Symptom | Root cause | Fix |
|---|---|---|
| KB upload returns 422 "Invalid file type" | curl multipart didn't set content-type | Add `;type=text/markdown` to `-F file=@...` |
| Agent sounds robotic | Wrong model (flash_v2) or stability too high | Switch to `eleven_turbo_v2` + stability 0.35 |
| Agent breaks character mid-call | KB has marketing fluff or system prompt too long | Trim KB to 1200-1500 words; keep system prompt under 800 chars |
| Agent hallucinates prices | "Pricing" section in KB has specific quotes | Replace exact numbers with ranges + "defer to human team" |
| Agent gives wrong product info | Two agents share one KB | One KB per agent — duplicate and customize |
| Multilingual agent doesn't switch to Hindi | Wrong model (turbo_v2 is English-only) | Use Rachel + `eleven_multilingual_v2` |
| Demo card on site but call fails | `data-agent-id` mismatch or typo | Re-check the agent ID from `scripts/agent-ids.txt` |
| Webhook doesn't deploy | Hostinger webhook flake | Empty commit retrigger, or SSH manual merge |

## Quick-start: clone an existing agent

If user says "build a [vertical] agent like the [existing one]":

```bash
# 1. Copy existing KB as starting point
cp kb/usha-martin-wire-rope.md kb/new-vertical-name.md
# 2. Edit kb/new-vertical-name.md — replace company facts, KB content, hard rules
# 3. Copy the create-agent.sh, change AGENT_NAME / KB_FILE / FIRST_MSG / SYSTEM_PROMPT
# 4. Run it — outputs new agent_id
# 5. Wire to demos.html via step 5 template
```

## What NOT to do

- **Do not** create voice agents that impersonate specific named real people (celebrity, leader, doctor) without written licensing. Voxdonna refuses these by policy.
- **Do not** use the same voice + persona for two adjacent demos. Visitors immediately spot the repeat.
- **Do not** skip the compliance section in the KB. Even benign verticals get tested by adversarial prospects.
- **Do not** edit the first 12 demo agents' configs without re-testing. They are production traffic.
- **Do not** ship a demo without doing one live call yourself from the deployed site. Voice quality bugs do not show up in API smoke tests.

## File map (what gets touched)

```
.env                                  # ELEVENLABS_API_KEY (read-only)
kb/<slug>.md                          # NEW — knowledge base for this agent
scripts/create-agent.sh               # script to call API
scripts/agent-ids.txt                 # appended with new agent ID
demos.html                            # new <article> card + updated meta count
index.html                            # updated demo count references
```

## Reference: working agents from this codebase

See `scripts/agent-ids.txt` for the live IDs. Key examples:

- `agent_9101krc72k02f339sd6qzhjsqxz8` — AI Karyakarta (Rachel multilingual, Indian elections)
- `agent_1401krc72nhnfz8aj1e3hvepj4fk` — Celebrity Voice Marketing (Rachel multilingual, Bollywood-inspired)
- 12 earlier agents (Jessica turbo_v2) covering hospitality, manufacturing, healthcare, supply chain

All use stability 0.35, similarity_boost 0.75, gpt-4o-mini for dialogue, temperature 0.4.
