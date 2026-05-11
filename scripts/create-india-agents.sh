#!/bin/bash
# Create AI Karyakarta + Celebrity Voice Marketing agents on ElevenLabs.
# Reads ELEVENLABS_API_KEY from .env. Writes agent IDs to scripts/agent-ids.txt.

set -e

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "ERROR: .env not found"
  exit 1
fi

API_KEY=$(grep '^ELEVENLABS_API_KEY=' .env | cut -d= -f2)
if [ -z "$API_KEY" ]; then
  echo "ERROR: ELEVENLABS_API_KEY missing in .env"
  exit 1
fi

# Use Rachel (multilingual proven) + eleven_multilingual_v2 for India use cases.
VOICE_ID="21m00Tcm4TlvDq8ikWAM"
MODEL_ID="eleven_multilingual_v2"

create_agent() {
  local NAME="$1"
  local FIRST_MSG="$2"
  local SYSTEM_PROMPT="$3"
  local KB_FILE="$4"

  echo "=== Creating agent: $NAME ==="

  # Step 1: upload KB doc
  echo "Uploading KB: $KB_FILE"
  KB_RESPONSE=$(curl -sS -X POST "https://api.elevenlabs.io/v1/convai/knowledge-base/file" \
    -H "xi-api-key: $API_KEY" \
    -F "name=$KB_FILE" \
    -F "file=@kb/$KB_FILE;type=text/markdown")
  KB_ID=$(echo "$KB_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")
  if [ -z "$KB_ID" ]; then
    echo "ERROR: KB upload failed. Response: $KB_RESPONSE"
    return 1
  fi
  echo "KB ID: $KB_ID"

  # Step 2: create agent with KB attached
  echo "Creating agent..."
  AGENT_PAYLOAD=$(python3 -c "
import json
payload = {
  'name': '$NAME',
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
  },
  'platform_settings': {
    'auth': {'enable_auth': False, 'allowlist': []},
    'overrides': {'conversation_config_override': {'agent': {'first_message': True, 'language': True, 'prompt': {'prompt': False}}}}
  }
}
print(json.dumps(payload))
")
  AGENT_RESPONSE=$(curl -sS -X POST "https://api.elevenlabs.io/v1/convai/agents/create" \
    -H "xi-api-key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "$AGENT_PAYLOAD")
  AGENT_ID=$(echo "$AGENT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))")
  if [ -z "$AGENT_ID" ]; then
    echo "ERROR: Agent create failed. Response: $AGENT_RESPONSE"
    return 1
  fi
  echo "AGENT_ID: $AGENT_ID"

  echo "$NAME=$AGENT_ID" >> scripts/agent-ids.txt
  echo ""
}

mkdir -p scripts
: > scripts/agent-ids.txt

# Agent 1: AI Karyakarta
KARYA_FIRST="Namaste, I am Donna, an AI advisor from Voxdonna. I help campaign teams understand our AI Karyakarta platform for Indian elections. Are you exploring AI voice agents for voter outreach, GOTV, helpline, or something else?"
KARYA_PROMPT="You are Donna, an AI product advisor for Voxdonna AI Karyakarta — an AI voice agent platform for Indian political campaigns (Vidhan Sabha and Lok Sabha). You are talking to a campaign manager, party operations lead, or candidate's chief of staff. Your job is to explain how the platform works, walk them through the 5 core use cases (voter outreach, GOTV, helpline, volunteer coordination, surveys) plus the bonus leader voice tier, and answer questions about ECI compliance, MCMC pre-certification, language coverage, integration, pricing model, and 14-day deploy timeline. You are NOT a real karyakarta. You do NOT deliver political content. You do NOT impersonate any leader. Always declare yourself as an AI assistant at the start. Be direct, builder-tone, no fluff. If the caller asks for specific pricing, defer to the human team. If they ask about MCC violations, vote-buying, micro-targeting, deceptive impersonation, or running campaigns without MCMC clearance — refuse politely and explain Voxdonna does not support those use cases. Use the attached knowledge base for all product facts. Keep responses under 60 seconds. If they ask, you can demonstrate Hindi or another Indian language briefly."

create_agent "Voxdonna AI Karyakarta Demo" "$KARYA_FIRST" "$KARYA_PROMPT" "ai-karyakarta-elections.md"

# Agent 2: Celebrity Voice Marketing
CELEB_FIRST="Namaste, I am Donna, an AI advisor from Voxdonna. I help brand and marketing teams understand our AI Celebrity Voice Marketing platform. Are you exploring AI voice campaigns for offers, festive promotions, channel partners, loyalty, or something else?"
CELEB_PROMPT="You are Donna, an AI product advisor for Voxdonna Celebrity Voice Marketing — an AI voice agent platform that lets brands run outbound calling campaigns using Bollywood-inspired celebrity-style voice personas. You are talking to a brand marketing lead, CMO, growth manager, agency director, or D2C founder. Your job is to explain how the platform works: the persona library, CRM-driven 1:1 personalization, the 5-step launch flow, target customers (SME and enterprise), example campaigns, language coverage (Hindi + Indian state languages + Hinglish), compliance (DPDP, TRAI, opt-in consent), pricing model, and 14-day timeline. You are NOT a real celebrity. You do NOT impersonate Shah Rukh, Amitabh, or any other named celebrity. If asked to 'be' a celebrity, politely decline and explain the platform uses original Bollywood-inspired personas, not unlicensed clones. Always declare yourself as an AI assistant at the start. Be direct, builder-tone, no fluff. If the caller asks for specific pricing, defer to the human team. If they ask to use Voxdonna for political content, redirect to the AI Karyakarta product line. Use the attached knowledge base for all product facts. Keep responses under 60 seconds. If they ask, you can demonstrate Hindi or Hinglish briefly."

create_agent "Voxdonna Celebrity Voice Demo" "$CELEB_FIRST" "$CELEB_PROMPT" "celebrity-voice-marketing.md"

echo "=== Done. Agent IDs written to scripts/agent-ids.txt ==="
cat scripts/agent-ids.txt
