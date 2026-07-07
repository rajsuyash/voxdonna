#!/usr/bin/env python3
"""Create the TGI Fridays India — Neha outbound Bottomless Margaritas agent.
Uploads the KB, creates the ConvAI agent with the full conversion layer
(data collection, evaluation criteria, end_call + voicemail detection), prints agent_id.
Idempotent-ish: re-running creates a NEW agent. Run once."""
import json, os, sys, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_KEY = next((l.split("=", 1)[1].strip() for l in open(os.path.join(ROOT, ".env"))
                if l.startswith("ELEVENLABS_API_KEY=")), None)
if not API_KEY:
    sys.exit("ELEVENLABS_API_KEY missing in .env")

KB_FILE = "tgi-fridays-margaritas.md"
VOICE_ID = "QTKSa2Iyv0yoxvXY2V8a"          # Neha — Indian, conversational
MODEL_ID = "eleven_v3_conversational"      # most expressive real-time model; Hindi-capable
AGENT_NAME = "Voxdonna TGI Fridays Bottomless Margaritas Outbound"


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
boundary = "----voxdonnaTGIF"
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

SYSTEM_PROMPT = open(os.path.join(ROOT, "scripts", "tgi-fridays-system-prompt.txt")).read()

FIRST_MESSAGE = "Hello {{lead_name}}! Neha बोल रही हूँ TGI Fridays से, कैसे हो आप?"

payload = {
    "name": AGENT_NAME,
    "conversation_config": {
        "agent": {
            "first_message": FIRST_MESSAGE,
            "language": "hi",
            "dynamic_variables": {
                "dynamic_variable_placeholders": {"lead_name": "जी"}
            },
            "prompt": {
                "prompt": SYSTEM_PROMPT,
                "llm": "gpt-4o-mini",
                "temperature": 0.45,
                "max_tokens": 512,
                "knowledge_base": [
                    {"type": "file", "name": KB_FILE, "id": kb_id, "usage_mode": "auto"}
                ],
                # System tools go in the `tools` array; the API materializes them into
                # built_in_tools on save. voicemail_detection is DROPPED if only placed
                # in built_in_tools — it must appear here (verified against a live agent).
                "tools": [
                    {"type": "system", "name": "end_call", "description": ""},
                    {"type": "system", "name": "voicemail_detection",
                     "description": "Detect when the call reaches voicemail; leave a short message and hang up.",
                     "params": {
                         "system_tool_type": "voicemail_detection",
                         "voicemail_message": "Hi, यह TGI Fridays से Neha थी. इस weekend Bottomless Margaritas offer चल रहा है, unlimited margaritas एक fixed price में. Main WhatsApp पे details भेज देती हूँ, ज़रूर देखिएगा. Have a great day!"
                     }}
                ]
            }
        },
        "tts": {
            "voice_id": VOICE_ID,
            "model_id": MODEL_ID,
            "stability": 0.4,
            "similarity_boost": 0.75
        },
        "asr": {"quality": "high", "provider": "elevenlabs",
                "user_input_audio_format": "pcm_16000", "keywords": ["TGI", "Fridays", "margarita", "WhatsApp"]},
        "turn": {"turn_timeout": 10, "silence_end_call_timeout": 25, "mode": "turn"}
    },
    "platform_settings": {
        "data_collection": {
            "outcome": {"type": "string", "description": "Overall outcome: interested_whatsapp_sent / interested_no_send / not_interested / busy_callback / do_not_call / voicemail / wrong_person."},
            "interested": {"type": "boolean", "description": "True if the guest showed genuine interest in the Bottomless Margaritas offer."},
            "whatsapp_optin": {"type": "boolean", "description": "True only if the guest agreed to receive the reservation link on WhatsApp."},
            "opted_out": {"type": "boolean", "description": "True if the guest asked not to receive promotional calls."},
            "party_size": {"type": "string", "description": "Rough group size or day the guest mentioned for a visit, if any. Empty if not discussed."},
            "preferred_outlet_city": {"type": "string", "description": "City or outlet the guest mentioned, if any."}
        },
        "evaluation": {"criteria": [
            {"id": "compliance", "name": "Compliance held", "type": "prompt",
             "conversation_goal_prompt": "Did the agent disclose it is an AI when asked, avoid quoting any price/date/outlet/term not in the knowledge base, avoid collecting any payment detail, and honour a do-not-call request immediately? Fail if any were violated."},
            {"id": "not_pushy", "name": "Warm not pushy", "type": "prompt",
             "conversation_goal_prompt": "Did the agent stay warm and conversational, ask one question at a time, acknowledge the guest, and avoid a second pitch after a clear no? Fail if it oversold, repeated the pitch, or interrupted."},
            {"id": "goal_achieved", "name": "Goal achieved", "type": "prompt",
             "conversation_goal_prompt": "Did the agent clearly present the Bottomless Margaritas offer and, for an interested guest, offer to send the WhatsApp reservation link after confirming consent?"}
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
