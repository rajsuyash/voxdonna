#!/usr/bin/env python3
"""Create Kavya — the Emerald Jewel IIJS partner-invitation agent.

Outbound demo: calls a retail partner, invites them to Emerald's stall at IIJS,
asks which day suits them, and offers the stall details on WhatsApp. English first,
mirrors Hindi or Tamil. Show dates and stall number are demo data (see the KB).
Prints agent_id. Re-running creates a NEW agent. Run once.
"""
import json, os, sys, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_KEY = next((l.split("=", 1)[1].strip() for l in open(os.path.join(ROOT, ".env"))
                if l.startswith("ELEVENLABS_API_KEY=")), None)
if not API_KEY:
    sys.exit("ELEVENLABS_API_KEY missing in .env")

KB_FILES = ["emerald-iijs-invite.md"]
VOICE_ID = "TRnaQb7q41oL7sV0w6Bu"          # user-supplied; 189 wpm on eleven_v3_conversational (A/B against Neha on the other two)
MODEL_ID = "eleven_v3_conversational"      # the only real-time ConvAI model with the full Indic set
AGENT_NAME = "Voxdonna Emerald Jewel IIJS Partner Invitation Demo"

# Spoken-form only: no invoice codes, no digit strings, no dates in slashes.
FIRST_MSG = ("Good morning, this is Kavya from the sales team at Emerald Jewel. We are showing "
             "our new collections at IIJS in Mumbai next month, and I wanted to personally invite "
             "you to our stall. Do you have a minute?")

FIRST_MSG_HI = ("नमस्ते सर, मैं काव्या बोल रही हूँ Emerald Jewel की sales team से। "
                "अगले महीने Mumbai में IIJS show में हमारी नई collections आ रही हैं, और आपको हमारे "
                "stall पर invite करना था, एक मिनट बात कर सकते हैं?")

FIRST_MSG_TA = ("வணக்கம், நான் காவ்யா, Emerald Jewel sales team-லிருந்து பேசுகிறேன். "
                "அடுத்த மாதம் மும்பையில் IIJS-ல் எங்கள் புதிய collections-ஐ காட்டுகிறோம், உங்களை "
                "எங்கள் stall-க்கு அழைக்க விரும்பினேன், உங்களுக்கு ஒரு நிமிடம் இருக்கிறதா?")

SYSTEM_PROMPT = open(os.path.join(ROOT, "scripts", "emerald-iijs-system-prompt.txt")).read()

END_CALL_DESCRIPTION = """Ends the call after your closing line finishes playing.

CALL when: the three goal answers are collected and you have said one thank-you line; the partner says goodbye; the partner is busy and you have offered a callback or WhatsApp; the partner asks not to be called again (apologise first); the partner is annoyed; two silent turns; the call passes about ninety seconds.

DO NOT CALL while the partner is still speaking, before you have said the show dates and the stall, or before you have asked whether they are planning to come."""


def api(method, path, data=None, headers=None, raw=None):
    url = "https://api.elevenlabs.io" + path
    h = {"xi-api-key": API_KEY}
    if data is not None and raw is None:
        h["Content-Type"] = "application/json"
    if headers:
        h.update(headers)
    body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path} -> {e.code}: {e.read().decode()}")


# --- Step 1: upload KB docs (multipart, explicit content-type or it 422s) ---
boundary = "----voxdonnaEmeraldIIJS"
knowledge_base = []
for kb_file in KB_FILES:
    kb_bytes = open(os.path.join(ROOT, "kb", kb_file), "rb").read()
    multipart = b"".join([
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n{kb_file}\r\n".encode(),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{kb_file}\"\r\n"
        f"Content-Type: text/markdown\r\n\r\n".encode(),
        kb_bytes,
        f"\r\n--{boundary}--\r\n".encode(),
    ])
    kb = api("POST", "/v1/convai/knowledge-base/file", raw=multipart,
             headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    if not kb.get("id"):
        sys.exit(f"KB upload failed for {kb_file}: {kb}")
    print("KB ID:", kb_file, kb["id"])
    knowledge_base.append({"type": "file", "name": kb_file, "id": kb["id"], "usage_mode": "auto"})

payload = {
    "name": AGENT_NAME,
    "conversation_config": {
        "agent": {
            "first_message": FIRST_MSG,
            "language": "en",
            "prompt": {
                "prompt": SYSTEM_PROMPT,
                "llm": "gpt-4o-mini",
                "temperature": 0.4,
                "max_tokens": 200,
                "knowledge_base": knowledge_base,
                # System tools live here, never in the read-only `tools` array.
                "built_in_tools": {
                    "end_call": {"name": "end_call", "description": END_CALL_DESCRIPTION,
                                 "type": "system", "params": {"system_tool_type": "end_call"}},
                    "language_detection": {"name": "language_detection", "description": "",
                                           "type": "system", "response_timeout_secs": 20},
                }
            }
        },
        # Primary language is en; presets carry the non-primary openers only.
        "language_presets": {
            "hi": {"overrides": {"agent": {"first_message": FIRST_MSG_HI}}},
            "ta": {"overrides": {"agent": {"first_message": FIRST_MSG_TA}}},
        },
        "tts": {
            "voice_id": VOICE_ID,
            "model_id": MODEL_ID,
            "stability": 0.45,
            "similarity_boost": 0.75
        },
        "asr": {"quality": "high", "provider": "scribe_realtime",
                "user_input_audio_format": "pcm_16000",
                "keywords": ["Emerald", "lakh", "crore", "invoice", "credit period", "statement",
                             "RTGS", "NEFT", "cheque", "ledger", "dispatch", "jewellers"]},
        "turn": {"turn_timeout": 10, "silence_end_call_timeout": 25, "mode": "turn"}
    },
    "platform_settings": {
        "data_collection": {
            "outcome": {"type": "string", "description": "Overall outcome: attending_confirmed / maybe_attending / not_attending / callback_requested (partner asked for a human to call or to be sent details, which is NOT an opt-out) / do_not_call (only an explicit stop-calling request) / wrong_person / abandoned."},
            "attending": {"type": "string", "description": "Is the partner planning to come to the show: yes / maybe / no / unknown."},
            "preferred_day": {"type": "string", "description": "Which show day the partner said suits them, in their own words. Empty if not discussed or not attending."},
            "whatsapp_consent": {"type": "boolean", "description": "True only if the partner agreed to receive the stall details and badge link on WhatsApp."},
            "partner_firm": {"type": "string", "description": "Name of the partner firm as stated on the call. Empty if not given."},
            "partner_city": {"type": "string", "description": "City the partner's showroom is in, if mentioned. Empty otherwise."},
            "interest_signal": {"type": "string", "description": "What the partner asked about, as a signal for the sales team: bridal_gold / daily_wear / diamond / platinum / show_terms / catalogue_only / none."},
            "blocker": {"type": "string", "description": "Reason given for not attending or not deciding, in their terms, e.g. travel, festive season staffing, cost. Empty if none."},
            "callback_requested": {"type": "string", "description": "Who the partner wants to hear from: sales_manager / design_team / none."},
            "sentiment": {"type": "string", "description": "How the partner sounded overall: warm / neutral / uninterested / irritated."}
        },
        "evaluation": {"criteria": [
            {"id": "compliance", "name": "Compliance held", "type": "prompt",
             "conversation_goal_prompt": "Did the agent avoid quoting any price, making charge, discount percentage or show term as a number, avoid taking an order or reserving stock, avoid any payment or bank detail, and avoid promising stock or a delivery date? Fail if any were violated."},
            {"id": "no_pressure", "name": "Invited without pressure", "type": "prompt",
             "conversation_goal_prompt": "Did the agent stay warm and unpushy, avoid all scarcity and urgency language (limited slots, hurry, last chance), accept a decline on the first answer without re-pitching, and honour a do-not-call request on the first ask? Fail on any breach."},
            {"id": "details_stated", "name": "Show details stated", "type": "prompt",
             "conversation_goal_prompt": "Did the agent say the show, the dates, the venue city and Emerald's hall and stall out loud, in words rather than as a code, before asking whether the partner will attend?"},
            {"id": "goal_achieved", "name": "Invitation completed", "type": "prompt",
             "conversation_goal_prompt": "Did the call establish whether the partner plans to attend, capture a preferred day when they said yes or maybe, and ask about sending the stall details on WhatsApp — or close early for a valid reason (busy, declined, do-not-call)?"},
            {"id": "clean_close", "name": "Closed without dragging", "type": "prompt",
             "conversation_goal_prompt": "Once the answers were collected, did the agent close with a single thank-you line and hang up, rather than repeating the invitation or asking further questions?"}
        ]}
    }
}

agent = api("POST", "/v1/convai/agents/create", data=payload)
agent_id = agent.get("agent_id")
if not agent_id:
    sys.exit(f"Agent create failed: {agent}")
print("AGENT_ID:", agent_id)
with open(os.path.join(ROOT, "scripts", "agent-ids.txt"), "a") as f:
    f.write(f"{AGENT_NAME}={agent_id}\n")
print("Appended to scripts/agent-ids.txt")
