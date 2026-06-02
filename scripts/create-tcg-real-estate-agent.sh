#!/bin/bash
# Create TCG Real Estate Group pre-sales voice agent (Aanya) on ElevenLabs.
# Uploads kb/tcg-real-estate-presales.md, creates multilingual EN+HI agent,
# appends agent_id to scripts/agent-ids.txt.
# System prompt read from scripts/tcg-system-prompt.txt (bash 3.2 heredoc workaround).

set -e
cd "$(dirname "$0")/.."

API_KEY=$(grep '^ELEVENLABS_API_KEY=' .env | cut -d= -f2)
[ -z "$API_KEY" ] && { echo "ERROR: ELEVENLABS_API_KEY missing"; exit 1; }

VOICE_ID="21m00Tcm4TlvDq8ikWAM"
MODEL_ID="eleven_multilingual_v2"
KB_FILE="tcg-real-estate-presales.md"
NAME="Voxdonna TCG Real Estate Pre-Sales Demo"
PROMPT_FILE="scripts/tcg-system-prompt.txt"

FIRST_MSG="Hi, this is Aanya calling from TCG Real Estate Group about your enquiry for The 42 on Chowringhee, Kolkata. Is this a good time to talk for two minutes?"

[ ! -f "$PROMPT_FILE" ] && { echo "ERROR: $PROMPT_FILE missing"; exit 1; }
SYSTEM_PROMPT=$(cat "$PROMPT_FILE")

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
")

AGENT_RESPONSE=$(curl -sS -X POST "https://api.elevenlabs.io/v1/convai/agents/create" \
  -H "xi-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$AGENT_PAYLOAD")
AGENT_ID=$(echo "$AGENT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))")
[ -z "$AGENT_ID" ] && { echo "ERROR: Agent create failed. Response: $AGENT_RESPONSE"; exit 1; }
echo "AGENT_ID: $AGENT_ID"
echo "$NAME=$AGENT_ID" >> scripts/agent-ids.txt
echo "=== Done ==="
