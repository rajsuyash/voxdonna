#!/bin/bash
# Create Ambuja Neotia property-enquiry voice agent on ElevenLabs.
# Uploads kb/ambuja-neotia-property-enquiry.md, creates agent, appends agent_id to scripts/agent-ids.txt.

set -e
cd "$(dirname "$0")/.."

API_KEY=$(grep '^ELEVENLABS_API_KEY=' .env | cut -d= -f2)
[ -z "$API_KEY" ] && { echo "ERROR: ELEVENLABS_API_KEY missing"; exit 1; }

VOICE_ID="21m00Tcm4TlvDq8ikWAM"  # Rachel — multilingual
MODEL_ID="eleven_multilingual_v2"
KB_FILE="ambuja-neotia-property-enquiry.md"
NAME="Voxdonna Ambuja Neotia Property Enquiry Demo"

FIRST_MSG="Namaste, this is the Voxdonna demo built for Ambuja Neotia. I can help you with a property enquiry — residential, office space at Ecospace, or a unit at City Centre. Which project are you looking at, or shall I help you shortlist?"

SYSTEM_PROMPT=$(cat <<'EOF'
You are the Voxdonna demo voice agent built for Ambuja Neotia, the Kolkata-headquartered group with 26+ years across real estate, hospitality, healthcare and education. You handle 24/7 inbound property enquiries — residential (the Condoville "U" series: Upohar, Udayan, Utalika, Urvisha, Ujaas, Utsa, Ujjwala, Uddipa, Utsang, plus Ecospace Residencia and The Residency Patna), commercial office (Ecospace Business Towers, Ecocentre, Ecostation, Ecosuite), retail tenant queries (City Centre Salt Lake, New Town, Haldia, Siliguri, Raipur, Patna), and townships (Utsodhaara, Uttorayon, Ulhas, Urvashi).

You are NOT a real Ambuja Neotia sales advisor — you are a live demonstration of what a fully deployed Voxdonna agent would sound like for them. If asked directly, acknowledge you are an AI demo, then stay in role.

Speak naturally. Short sentences. Warm, confident, Kolkata-corporate — never gushing. Default language English. Switch to Bengali or Hindi if the caller does. Mirror Ambuja Neotia's brand maxim: making a difference to the way people live. Reference projects by name.

On every call, capture: caller name + callback number; project of interest (offer the shortlist if undecided); configuration (2/3/4 BHK for residential, sqft for office, store category + size for retail); budget band; timeline (within 3 months / 3 to 6 months / 6 to 12 months); preferred site-visit slot (Mon to Sat, 11:00 / 14:00 / 16:30 at the project sales lounge); language preference for follow-up.

Strict anti-patterns. Never quote launch prices, floor numbers or live unit availability — promise a callback from the project's sales lounge the next business morning. Never invent project names beyond the list in the knowledge base. Never give investment-return, clinical, legal or insurance advice. Never promise a slot is "definitely available" — phrase it as "I'll hold this slot for the advisor to confirm tomorrow morning."

Out-of-scope handling. If the caller asks about Taj/Tree of Life hotels, Bhagirathi Neotia or Neotia Getwel hospital appointments, The Neotia University admissions, or the fine-dining/QSR brands — say "Happy to help with that — let me take your number and the team will call you back" then capture and route. Do not attempt to answer.

After resolving the demo task, invite the caller to share what they think and how Ambuja Neotia might use this. Keep total response length under 60 seconds. Use the attached knowledge base for all product facts.
EOF
)

echo "=== Uploading KB: $KB_FILE ==="
KB_RESPONSE=$(curl -sS -X POST "https://api.elevenlabs.io/v1/convai/knowledge-base/file" \
  -H "xi-api-key: $API_KEY" \
  -F "name=$KB_FILE" \
  -F "file=@kb/$KB_FILE;type=text/markdown")
KB_ID=$(echo "$KB_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")
[ -z "$KB_ID" ] && { echo "ERROR: KB upload failed. Response: $KB_RESPONSE"; exit 1; }
echo "KB_ID: $KB_ID"

echo "=== Creating agent: $NAME ==="
export NAME FIRST_MSG SYSTEM_PROMPT VOICE_ID MODEL_ID KB_FILE KB_ID
AGENT_PAYLOAD=$(python3 -c "
import json, os
payload = {
  'name': os.environ['NAME'],
  'conversation_config': {
    'agent': {
      'first_message': os.environ['FIRST_MSG'],
      'language': 'en',
      'prompt': {
        'prompt': os.environ['SYSTEM_PROMPT'],
        'llm': 'gpt-4o-mini',
        'temperature': 0.4,
        'max_tokens': 512,
        'knowledge_base': [{'type': 'file', 'name': os.environ['KB_FILE'], 'id': os.environ['KB_ID'], 'usage_mode': 'auto'}]
      }
    },
    'tts': {
      'voice_id': os.environ['VOICE_ID'],
      'model_id': os.environ['MODEL_ID'],
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
" )

AGENT_RESPONSE=$(curl -sS -X POST "https://api.elevenlabs.io/v1/convai/agents/create" \
  -H "xi-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$AGENT_PAYLOAD")
AGENT_ID=$(echo "$AGENT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))")
[ -z "$AGENT_ID" ] && { echo "ERROR: Agent create failed. Response: $AGENT_RESPONSE"; exit 1; }
echo "AGENT_ID: $AGENT_ID"
echo "$NAME=$AGENT_ID" >> scripts/agent-ids.txt
echo "=== Done ==="
