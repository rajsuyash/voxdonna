#!/bin/bash
# scripts/create-american-ratings-agent.sh — create Sarah, A-I-R-S inbound sales qualifier
set -e
cd "$(dirname "$0")/.."

API_KEY=$(grep '^ELEVENLABS_API_KEY=' .env | cut -d= -f2)
[ -z "$API_KEY" ] && { echo "ERROR: ELEVENLABS_API_KEY missing"; exit 1; }

AGENT_NAME="Voxdonna American Ratings A-I-R-S Sales Qualifier Demo"
KB_FILE="american-ratings-airs.md"
VOICE_ID="cgSgspJ2msm6clMCkdW9"        # Jessica — warm English B2B
MODEL_ID="eleven_turbo_v2"
FIRST_MSG="Hi, this is Sarah from American Ratings, the team behind the A I R S Number. Just so you know, I'm an AI assistant on the team. How can I help you today?"

read -r -d '' SYSTEM_PROMPT <<'EOF' || true
You are Sarah, an AI inbound Sales Qualifier for American Ratings (ABN US), the company behind the A I R S Number (American Industry Rating Standard). Pronounce it as the letters "A I R S".

ROLE: Handle inbound callers who want to learn about or buy an A I R S Number. Greet warmly, understand why they called, qualify their interest, briefly explain A I R S when needed, and book a call with the human sales team when they're a good fit. You are the qualification-and-booking layer in front of sales, not the closer and not support.

OPENING: Always declare you are an AI assistant at the start. Never claim to be human.

QUALIFY (gather naturally, one question at a time, never as a checklist):
1. Individual or business?
2. Main goal / use case (credibility, lead magnet, partner/reseller, enterprise integration, personal branding).
3. If business: company name, size/industry, how they'll use the number.
4. Are they the decision maker?
5. Timeline: immediate, next few weeks, or exploring.
6. Have they seen the website or already know A I R S?

EXPLAIN WHEN ASKED: A I R S is a verified business and individual identity number, recognized in 150-plus countries, that signals trust to partners, clients, and enterprises. Verification takes 48 to 72 hours.

PRICING: Say exactly "Pricing starts at $599 for the Business plus Individual lifetime bundle. For enterprise or custom needs, our sales team provides personalized quotes." Quote NO other number. Defer everything else to sales.

BOOK A MEETING when the caller is a genuine fit: a business wanting to buy, bulk/lead-magnet interest, partner/reseller interest, enterprise/API needs, or a decision maker with a clear use case, or anyone wanting to buy now. Before booking, confirm name, company (if any), email, and best phone number, reading the email back to confirm. Then say "I'll book a quick discovery call with our team so they can give you all the details and answer any specific questions." If the caller is just curious with no intent, politely point them to the website and offer to send more information instead of booking.

GUARDRAILS:
- Never invent pricing, features, or processes. The only price you state is the $599 bundle.
- Never promise outcomes or timelines beyond the 48 to 72 hour verification window.
- Never collect card numbers, bank details, or passwords. You qualify and book only.
- If you don't know something, say "That's a great question. Let me connect you with our team who can give you the most accurate information."
- Refuse anything implying faked verification, impersonation, or fraud.
- Be patient and professional. Never pushy or aggressive.

STYLE: Warm, confident, concise — like a real sales professional. Use the caller's name once they give it. End every turn with either a relevant follow-up question or a move toward booking. Keep replies under 30 seconds.

TTS FLUENCY RULES: Single punctuation only — one ! and one ?, never !!! or ??. Medium sentences (12 to 20 words). Max 2 to 3 em-dashes per call. Use connectors (and, so, because) to bridge clauses. Never ALL CAPS. Say "five ninety-nine dollars" naturally rather than reading digits one by one.

HARD STOP — call end_call when:
1. A discovery call is booked and details are confirmed.
2. The caller is clearly not a fit and you've pointed them to the website and said goodbye.
3. The caller says goodbye or that they're done.
4. The caller is hostile or abusive after one calm attempt to help.
5. Two consecutive silent or empty turns.
Never end mid-question or while the caller is still talking. Give a brief warm closing line, then end the call.
EOF

# Step 3a: upload KB
echo "Uploading KB: $KB_FILE"
KB_RESPONSE=$(curl -sS -X POST "https://api.elevenlabs.io/v1/convai/knowledge-base/file" \
  -H "xi-api-key: $API_KEY" \
  -F "name=$KB_FILE" \
  -F "file=@kb/$KB_FILE;type=text/markdown")
KB_ID=$(echo "$KB_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")
[ -z "$KB_ID" ] && { echo "ERROR: KB upload failed. Response: $KB_RESPONSE"; exit 1; }
echo "KB ID: $KB_ID"

# Step 3b: create agent
AGENT_PAYLOAD=$(FIRST_MSG="$FIRST_MSG" SYSTEM_PROMPT="$SYSTEM_PROMPT" AGENT_NAME="$AGENT_NAME" \
  KB_FILE="$KB_FILE" KB_ID="$KB_ID" VOICE_ID="$VOICE_ID" MODEL_ID="$MODEL_ID" python3 -c "
import json, os
payload = {
  'name': os.environ['AGENT_NAME'],
  'conversation_config': {
    'agent': {
      'first_message': os.environ['FIRST_MSG'],
      'language': 'en',
      'prompt': {
        'prompt': os.environ['SYSTEM_PROMPT'],
        'llm': 'gpt-4o-mini',
        'temperature': 0.4,
        'max_tokens': 512,
        'knowledge_base': [{'type':'file','name':os.environ['KB_FILE'],'id':os.environ['KB_ID'],'usage_mode':'auto'}],
        'tools': [{'type':'system','name':'end_call','description':''}]
      }
    },
    'tts': {'voice_id': os.environ['VOICE_ID'], 'model_id': os.environ['MODEL_ID'], 'stability': 0.35, 'similarity_boost': 0.75},
    'asr': {'quality':'high','provider':'elevenlabs','user_input_audio_format':'pcm_16000','keywords':['A-I-R-S','American Ratings','ABN','lifetime bundle','enterprise']},
    'turn': {'turn_timeout': 10, 'silence_end_call_timeout': 25, 'mode': 'turn'}
  },
  'platform_settings': {
    'data_collection': {
      'caller_type': {'type':'string','description':'Whether the caller is calling for an individual or a business.'},
      'use_case': {'type':'string','description':'The caller main goal or use case, e.g. credibility, lead magnet, partner/reseller, enterprise integration, personal branding.'},
      'company_name': {'type':'string','description':'Company name if the caller represents a business; empty otherwise.'},
      'company_size_industry': {'type':'string','description':'Company size and/or industry if mentioned.'},
      'decision_maker': {'type':'boolean','description':'True if the caller is the decision maker for this purchase.'},
      'timeline': {'type':'string','description':'Buying timeline: immediate, next few weeks, or exploring.'},
      'caller_name': {'type':'string','description':'The caller full name.'},
      'caller_email': {'type':'string','description':'The caller email, as confirmed by read-back.'},
      'caller_phone': {'type':'string','description':'The caller best phone number.'},
      'meeting_booked': {'type':'boolean','description':'True if a discovery call with the sales team was booked.'},
      'qualified': {'type':'boolean','description':'True only if the caller is a genuine fit for the sales team (real buying intent, partner/reseller, enterprise, or decision maker with a clear use case).'},
      'outcome': {'type':'string','description':'Outcome of the call, e.g. booked discovery call / sent to website / not interested / disqualified.'}
    },
    'evaluation': {'criteria': [
      {'id':'compliance','name':'Compliance held','type':'prompt',
       'conversation_goal_prompt':'Did Sarah declare herself an AI at the start, quote only the \$599 bundle price (no other pricing), avoid promising outcomes/timelines beyond 48-72 hours, and avoid collecting card or bank details? Fail if any were violated.'},
      {'id':'qualified_correctly','name':'Qualified before booking','type':'prompt',
       'conversation_goal_prompt':'Did Sarah qualify the caller (individual vs business, use case, decision maker, timeline) before either booking a meeting or routing them to the website?'},
      {'id':'goal_achieved','name':'Call goal achieved','type':'prompt',
       'conversation_goal_prompt':'Did Sarah achieve the right outcome: booked a discovery call with confirmed name/email/phone for a genuine fit, or politely routed a non-fit to the website?'}
    ]}
  }
}
print(json.dumps(payload))
")

AGENT_RESPONSE=$(curl -sS -X POST "https://api.elevenlabs.io/v1/convai/agents/create" \
  -H "xi-api-key: $API_KEY" -H "Content-Type: application/json" -d "$AGENT_PAYLOAD")
AGENT_ID=$(echo "$AGENT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))")
[ -z "$AGENT_ID" ] && { echo "ERROR: Agent create failed. Response: $AGENT_RESPONSE"; exit 1; }

echo "AGENT_ID: $AGENT_ID"
echo "$AGENT_NAME=$AGENT_ID" >> scripts/agent-ids.txt
