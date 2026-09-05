#!/usr/bin/env python3
"""Create Meera — the Emerald Jewel new-collection outreach agent.

Outbound demo: calls a retail channel partner about Aadhira, a new lightweight bridal
collection, and books an appointment to show it (showroom visit or video walkthrough).
English first, mirrors Hindi or Tamil. The collection is invented for the demo (see KB).
Prints agent_id. Re-running creates a NEW agent. Run once.
"""
import json, os, sys, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_KEY = next((l.split("=", 1)[1].strip() for l in open(os.path.join(ROOT, ".env"))
                if l.startswith("ELEVENLABS_API_KEY=")), None)
if not API_KEY:
    sys.exit("ELEVENLABS_API_KEY missing in .env")

KB_FILES = ["emerald-collection-launch.md"]
VOICE_ID = "rWhgcICeqKQLaH2mIutU"          # user-chosen Emerald house voice (all three agents)
MODEL_ID = "eleven_v3_conversational"      # the only real-time ConvAI model with the full Indic set
AGENT_NAME = "Voxdonna Emerald Jewel New Collection Outreach Demo"

# Spoken-form only: no invoice codes, no digit strings, no dates in slashes.
FIRST_MSG = ("Good morning, this is Meera, an AI assistant from the product team at Emerald Jewel. "
             "We have just finished a new lightweight bridal collection called Aadhira, and I wanted "
             "to show it to you before the festive season. Do you have a minute?")

FIRST_MSG_HI = ("नमस्ते, मैं मीरा बोल रही हूँ, Emerald Jewel की product team से एक AI assistant। "
                "हमने अभी एक नई lightweight bridal collection तैयार की है, नाम है आधिरा, और festive "
                "season से पहले आपको दिखाना चाहती थी, क्या आपके पास एक मिनट है?")

FIRST_MSG_TA = ("வணக்கம், நான் மீரா, Emerald Jewel product team-லிருந்து ஒரு AI assistant. "
                "ஆதிரா என்ற புதிய lightweight bridal collection-ஐ இப்போதுதான் முடித்திருக்கிறோம், "
                "festive season-க்கு முன் உங்களுக்கு காட்ட விரும்பினேன், ஒரு நிமிடம் இருக்கிறதா?")

SYSTEM_PROMPT = open(os.path.join(ROOT, "scripts", "emerald-collection-system-prompt.txt")).read()

END_CALL_DESCRIPTION = """Ends the call after your closing line finishes playing.

CALL when: the three goal answers are collected and you have said one thank-you line; the partner says goodbye; the partner is busy and you have offered a callback or the lookbook; the partner asks not to be called again (apologise first); the partner is annoyed; two silent turns; the call passes about ninety seconds.

DO NOT CALL while the partner is still speaking, before you have described the collection, or before you have asked whether they would like to see it."""


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
boundary = "----voxdonnaEmeraldCollection"
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
            "outcome": {"type": "string", "description": "Overall outcome: appointment_requested / interested_later / lookbook_only / not_interested / callback_requested (partner asked for a human to call, which is NOT an opt-out) / do_not_call (only an explicit stop-calling request) / wrong_person / abandoned."},
            "interested": {"type": "string", "description": "Does the partner want to see the collection: yes / later / no / unknown."},
            "appointment_day": {"type": "string", "description": "Preferred day and rough time of day in the partner's own words. Empty if none given."},
            "appointment_mode": {"type": "string", "description": "How they want to see it: showroom_visit / video_walkthrough / undecided / none."},
            "whatsapp_consent": {"type": "boolean", "description": "True only if the partner agreed to receive the Aadhira lookbook on WhatsApp."},
            "partner_firm": {"type": "string", "description": "Name of the partner firm as stated on the call. Empty if not given."},
            "partner_city": {"type": "string", "description": "City the partner's showroom is in, if mentioned. Empty otherwise."},
            "objection": {"type": "string", "description": "The partner's stated reason for hesitating, in their terms, e.g. bridal is slow, already carry a temple range, festive stock committed. Empty if none."},
            "counter_signal": {"type": "string", "description": "What the partner said about their counter mix or buyers, as a note for the sales manager. Empty if nothing said."},
            "sentiment": {"type": "string", "description": "How the partner sounded overall: warm / neutral / uninterested / irritated."}
        },
        "evaluation": {"criteria": [
            {"id": "compliance", "name": "Compliance held", "type": "prompt",
             "conversation_goal_prompt": "Did the agent declare itself an AI in the opening, avoid quoting any price, making charge, margin, discount or commercial term as a number, avoid taking an order or reserving stock, avoid any payment or bank detail, avoid promising a dispatch date, and avoid naming a competitor? Fail if any were violated."},
            {"id": "no_pressure", "name": "Pitched without pressure", "type": "prompt",
             "conversation_goal_prompt": "Did the agent stay warm and unpushy, avoid all scarcity and urgency language, accept a decline on the first answer without re-pitching, avoid arguing with the partner about their own counter, and honour a do-not-call request on the first ask? Fail on any breach."},
            {"id": "collection_described", "name": "Collection described", "type": "prompt",
             "conversation_goal_prompt": "Did the agent describe the collection out loud early in the call — the name, roughly how many designs, the lighter temple-motif build and the weight range, with every number spoken in words — before asking whether the partner wants to see it?"},
            {"id": "appointment_framed_correctly", "name": "Appointment framed as a preference", "type": "prompt",
             "conversation_goal_prompt": "When an appointment was discussed, did the agent capture a preferred day and the mode (showroom visit or video walkthrough) while making clear the sales manager will call to fix the exact hour, rather than confirming a specific time as final? Pass if no appointment was discussed because the partner declined."},
            {"id": "goal_achieved", "name": "Outreach completed", "type": "prompt",
             "conversation_goal_prompt": "Did the call establish whether the partner wants to see the collection, capture a day and mode when they said yes or later, and ask about sending the lookbook on WhatsApp — or close early for a valid reason (busy, declined, do-not-call)?"}
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
