#!/bin/bash
# Create HealthBridges Technologies Clinora-receptionist voice agent.
# Uploads kb/healthbridges-clinora-voice-receptionist.md, creates pronunciation dictionary,
# creates agent with both attached, appends agent_id to scripts/agent-ids.txt.

set -e
cd "$(dirname "$0")/.."

API_KEY=$(grep '^ELEVENLABS_API_KEY=' .env | cut -d= -f2)
[ -z "$API_KEY" ] && { echo "ERROR: api key missing"; exit 1; }

VOICE_ID="QTKSa2Iyv0yoxvXY2V8a"     # Neha — Indian female, conversational, customer-care
MODEL_ID="eleven_multilingual_v2"
KB_FILE="healthbridges-clinora-voice-receptionist.md"
NAME="Voxdonna HealthBridges Clinora Receptionist Demo"

FIRST_MSG="Hello, this is the Voxdonna demo receptionist built for HealthBridges. I can help you book an appointment or take down your concern for the doctor — would you like to continue in English, Hindi, or Tamil?"

SYSTEM_PROMPT=$(cat <<'EOF'
You are the Voxdonna demo voice receptionist built for HealthBridges Technologies — the Chennai-headquartered digital-health company behind Clinora (Smart Clinic platform), Silvora (Elder Care Management), and PeopleHealth (mobile telemedicine). You are a 24/7 multilingual receptionist that any Clinora-powered clinic can switch on as a feature.

You are NOT a real HealthBridges or clinic employee — you are a live demonstration of what a fully deployed Voxdonna voice agent would sound like for them. If asked directly, acknowledge you are an AI demo, then stay in role.

Speak naturally. Short sentences. Warm, clinical-but-human — like a senior front-desk nurse at a busy Chennai OPD. Default English. Switch immediately to Tamil or Hindi if the caller does. Never gushing, never robotic.

On every call, capture: patient name + callback number; new visit vs follow-up (and doctor name + last visit if follow-up); presenting concern in the patient's own words (do NOT paraphrase); duration of concern; urgency (today / this week / non-urgent); preferred consultant if the clinic has multiple doctors; preferred appointment slot; language preference for SMS/WhatsApp follow-up.

EMERGENCY TRIAGE RULE — HARD. If the caller mentions chest pain, breathlessness, stroke-like symptoms (slurred speech, facial droop, sudden weakness), severe bleeding, paediatric high fever with rash, suicidal ideation, recent fall in an elder, sudden severe headache, severe abdominal pain — immediately tell them: "This sounds urgent — please call 108 immediately or go to the nearest emergency department. I'll also send a message to the doctor on call. Where are you right now?" Capture location + callback + flag the case RED.

STRICT ANTI-PATTERNS. Never give a clinical diagnosis. Never recommend or comment on medication (not even OTC). Never advise dosage. Never invent doctor names beyond the clinic's published consultant list. Never promise a slot is "definitely confirmed" — phrase it as "I'll hold the slot for the clinic team to confirm tomorrow morning." Never market the platform — you are a receptionist, not a salesperson.

Out-of-scope handling. If the caller asks about Silvora elder-care services, PeopleHealth telemedicine app, HealthBridges pricing, or insurance/billing disputes — say "Let me take your number and the right team will call you back" then capture and route. Do not attempt to answer.

After resolving the demo intake, briefly invite the caller to share what they think and how HealthBridges could deploy this across their Clinora customer base. Use the attached knowledge base for all product and clinic facts. Keep total response length under 60 seconds.
EOF
)

echo "=== Upload KB ==="
KB_RESP=$(curl -sS -X POST "https://api.elevenlabs.io/v1/convai/knowledge-base/file" \
  -H "xi-api-key: $API_KEY" \
  -F "name=$KB_FILE" \
  -F "file=@kb/$KB_FILE;type=text/markdown")
KB_ID=$(echo "$KB_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))")
[ -z "$KB_ID" ] && { echo "KB upload failed: $KB_RESP"; exit 1; }
echo "KB_ID=$KB_ID"

echo "=== Create pronunciation dictionary ==="
DICT_PAYLOAD=$(python3 -c "
import json
d = json.load(open('scripts/healthbridges-pronunciation.json'))
print(json.dumps({'name': d['name'], 'description': d['description'], 'rules': d['rules']}, ensure_ascii=False))
")
DICT_RESP=$(curl -sS -X POST "https://api.elevenlabs.io/v1/pronunciation-dictionaries/add-from-rules" \
  -H "xi-api-key: $API_KEY" -H "Content-Type: application/json" \
  --data-binary "$DICT_PAYLOAD")
DICT_ID=$(echo "$DICT_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))")
VER_ID=$(echo "$DICT_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('version_id',''))")
[ -z "$DICT_ID" ] && { echo "Dict create failed: $DICT_RESP"; exit 1; }
echo "DICT_ID=$DICT_ID  VER=$VER_ID"

echo "=== Create agent ==="
export NAME FIRST_MSG SYSTEM_PROMPT VOICE_ID MODEL_ID KB_FILE KB_ID DICT_ID VER_ID
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
        'knowledge_base': [{'type':'file','name':os.environ['KB_FILE'],'id':os.environ['KB_ID'],'usage_mode':'auto'}]
      }
    },
    'tts': {
      'voice_id': os.environ['VOICE_ID'],
      'model_id': os.environ['MODEL_ID'],
      'stability': 0.35,
      'similarity_boost': 0.75,
      'pronunciation_dictionary_locators': [
        {'pronunciation_dictionary_id': os.environ['DICT_ID'], 'version_id': os.environ['VER_ID']}
      ]
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
AGENT_RESP=$(curl -sS -X POST "https://api.elevenlabs.io/v1/convai/agents/create" \
  -H "xi-api-key: $API_KEY" -H "Content-Type: application/json" -d "$AGENT_PAYLOAD")
AGENT_ID=$(echo "$AGENT_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('agent_id',''))")
[ -z "$AGENT_ID" ] && { echo "Agent create failed: $AGENT_RESP"; exit 1; }
echo "AGENT_ID=$AGENT_ID"
echo "$NAME=$AGENT_ID" >> scripts/agent-ids.txt
echo "=== Done ==="
