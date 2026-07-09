#!/usr/bin/env python3
"""Create the Deltin room-booking agent (Kiara) — trilingual HI/EN/GU inbound demo.
Uploads the KB, creates the ConvAI agent with language_presets (en/gu),
language_detection + end_call system tools, and the conversion layer
(data collection, evaluation criteria). Prints agent_id.
Re-running creates a NEW agent. Run once."""
import json, os, sys, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_KEY = next((l.split("=", 1)[1].strip() for l in open(os.path.join(ROOT, ".env"))
                if l.startswith("ELEVENLABS_API_KEY=")), None)
if not API_KEY:
    sys.exit("ELEVENLABS_API_KEY missing in .env")

KB_FILE = "deltin-room-booking.md"
VOICE_ID = "QTKSa2Iyv0yoxvXY2V8a"          # Neha — Indian voice, renders hi/en/gu on v3_conversational
MODEL_ID = "eleven_v3_conversational"      # the ONLY real-time ConvAI model with Gujarati
AGENT_NAME = "Voxdonna Deltin Room Booking Demo"

FIRST_HI = "नमस्ते, मैं कियारा बोल रही हूँ Deltin reservations से — मैं एक AI assistant हूँ। आप Daman या Goa, किस property के लिए room देखना चाहेंगे?"
FIRST_EN = "Hello, this is Kiara from Deltin reservations — I'm an AI assistant. Are you looking to book a room at Daman or Goa?"
FIRST_GU = "નમસ્તે, હું કિયારા બોલું છું Deltin reservations થી — હું એક AI assistant છું. તમે Daman કે Goa, કઈ property માટે room જોવા માંગો છો?"


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


# --- Step 1: upload KB (multipart, explicit content-type or it 422s) ---
boundary = "----voxdonnaDeltin"
kb_path = os.path.join(ROOT, "kb", KB_FILE)
kb_bytes = open(kb_path, "rb").read()
parts = []
parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n{KB_FILE}\r\n".encode())
parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{KB_FILE}\"\r\n"
             f"Content-Type: text/markdown\r\n\r\n".encode())
parts.append(kb_bytes)
parts.append(f"\r\n--{boundary}--\r\n".encode())
multipart = b"".join(parts)
kb = api("POST", "/v1/convai/knowledge-base/file", raw=multipart,
         headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
kb_id = kb.get("id")
if not kb_id:
    sys.exit(f"KB upload failed: {kb}")
print("KB ID:", kb_id)

SYSTEM_PROMPT = open(os.path.join(ROOT, "scripts", "deltin-system-prompt.txt")).read()

payload = {
    "name": AGENT_NAME,
    "conversation_config": {
        "agent": {
            "first_message": FIRST_HI,
            "language": "hi",
            "prompt": {
                "prompt": SYSTEM_PROMPT,
                "llm": "gpt-4o-mini",
                "temperature": 0.4,
                "max_tokens": 512,
                "knowledge_base": [
                    {"type": "file", "name": KB_FILE, "id": kb_id, "usage_mode": "auto"}
                ],
                # System tools live in the `tools` array; the API materializes them
                # into built_in_tools on save (verified on the TGIF agent).
                "tools": [
                    {"type": "system", "name": "end_call", "description": ""},
                    {"type": "system", "name": "language_detection",
                     "description": "Switch the conversation language when the caller speaks Hindi, English, or Gujarati."}
                ]
            }
        },
        # Non-primary languages ONLY (primary hi must not appear as a preset).
        "language_presets": {
            "en": {"overrides": {"agent": {"first_message": FIRST_EN}}},
            "gu": {"overrides": {"agent": {"first_message": FIRST_GU}}}
        },
        "tts": {
            "voice_id": VOICE_ID,
            "model_id": MODEL_ID,
            "stability": 0.45,
            "similarity_boost": 0.75
        },
        "asr": {"quality": "high", "provider": "scribe_realtime",
                "user_input_audio_format": "pcm_16000",
                "keywords": ["Deltin", "Daman", "Goa", "suite", "WhatsApp", "check-in"]},
        "turn": {"turn_timeout": 10, "silence_end_call_timeout": 25, "mode": "turn"}
    },
    "platform_settings": {
        "data_collection": {
            "outcome": {"type": "string", "description": "Overall outcome: booking_request_captured / info_only / not_interested / wrong_number / abandoned."},
            "property": {"type": "string", "description": "Which property the guest asked about: daman / goa_suites / undecided."},
            "guest_name": {"type": "string", "description": "Guest's name as confirmed on the call. Empty if not shared."},
            "check_in_date": {"type": "string", "description": "Requested check-in date as stated by the guest. Empty if not discussed."},
            "nights": {"type": "string", "description": "Number of nights requested. Empty if not discussed."},
            "room_type": {"type": "string", "description": "Room/suite category the guest preferred. Empty if undecided."},
            "party_size": {"type": "string", "description": "Adults and children count as stated. Empty if not discussed."},
            "whatsapp_optin": {"type": "boolean", "description": "True only if the guest agreed to receive the booking link and details on WhatsApp."},
            "language_used": {"type": "string", "description": "Main language(s) the guest spoke: hindi / english / gujarati / mixed."}
        },
        "evaluation": {"criteria": [
            {"id": "compliance", "name": "Compliance held", "type": "prompt",
             "conversation_goal_prompt": "Did the agent declare itself an AI, avoid quoting an exact tariff or confirming availability, avoid collecting any payment detail, and avoid encouraging gambling or pitching the casino to anyone identified as under twenty-one? Fail if any were violated."},
            {"id": "language_match", "name": "Replied in caller's language", "type": "prompt",
             "conversation_goal_prompt": "Did the agent consistently reply in the language the caller used (Hindi, English, or Gujarati), switching promptly when the caller switched?"},
            {"id": "goal_achieved", "name": "Booking request captured", "type": "prompt",
             "conversation_goal_prompt": "Did the agent collect the booking checklist (property, dates, nights, room type, party size, guest name) and obtain WhatsApp consent for the booking link, or close politely if the guest declined?"}
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
