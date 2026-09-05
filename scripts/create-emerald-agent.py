#!/usr/bin/env python3
"""Create Aarthi — the Emerald Jewel channel-partner payment reminder agent.

Outbound accounts-receivable demo: calls a channel partner about an open balance,
asks when it will be cleared, offers the statement on WhatsApp, and closes. English
first, mirrors Hindi or Tamil if the partner replies in one. Uploads the KB, creates
the ConvAI agent with end_call + language_detection, and the conversion layer.
Prints agent_id. Re-running creates a NEW agent. Run once.
"""
import json, os, sys, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_KEY = next((l.split("=", 1)[1].strip() for l in open(os.path.join(ROOT, ".env"))
                if l.startswith("ELEVENLABS_API_KEY=")), None)
if not API_KEY:
    sys.exit("ELEVENLABS_API_KEY missing in .env")

KB_FILES = ["emerald-partner-payments.md"]
VOICE_ID = "QTKSa2Iyv0yoxvXY2V8a"          # Neha — fastest of the workspace voices on eleven_v3_conversational (195 wpm)
MODEL_ID = "eleven_v3_conversational"      # the only real-time ConvAI model with the full Indic set
AGENT_NAME = "Voxdonna Emerald Jewel Partner Payment Reminder Demo"

# Spoken-form only: no invoice codes, no digit strings, no dates in slashes.
FIRST_MSG = ("Good morning, this is Aarthi calling from the accounts team at Emerald Jewel. "
             "Just a quick courtesy reminder about a pending balance on your account, and it "
             "will take under a minute. Am I speaking with Mr. Ramesh?")

FIRST_MSG_HI = ("नमस्ते सर, मैं आरती बोल रही हूँ Emerald Jewel की accounts team से। "
                "आपके account पर एक payment pending है, बस वही याद दिलाना था, एक मिनट भी नहीं लगेगा। "
                "क्या मेरी बात रमेश जी से हो रही है?")

FIRST_MSG_TA = ("வணக்கம், நான் ஆரத்தி, Emerald Jewel accounts team-லிருந்து பேசுகிறேன். "
                "உங்கள் account-ல் உள்ள ஒரு pending balance பற்றி ஒரு சிறிய நினைவூட்டல் மட்டும்தான், "
                "நான் ரமேஷ் அவர்களிடம் பேசுகிறேனா?")

SYSTEM_PROMPT = open(os.path.join(ROOT, "scripts", "emerald-system-prompt.txt")).read()

END_CALL_DESCRIPTION = """Ends the call after your closing line finishes playing.

CALL when: all three goal answers are collected and you have said one thank-you line; the partner says goodbye; the partner asks not to be called again (apologise first); the partner reports a dispute or an already-made payment and you have acknowledged it; the partner is angry; two silent turns; the call passes about ninety seconds.

DO NOT CALL while the partner is still speaking, before you have confirmed who you are speaking to, or before you have asked when they expect to clear the balance."""


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
boundary = "----voxdonnaEmeraldPartner"
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
            "outcome": {"type": "string", "description": "Overall outcome: payment_date_given / payment_already_made / callback_requested (partner asked for a human to call, which is NOT an opt-out) / dispute_raised / refused_to_commit / do_not_call (only an explicit stop-calling request) / wrong_person / abandoned."},
            "person_confirmed": {"type": "boolean", "description": "True only if the partner confirmed the agent is speaking to the owner or the firm's accounts contact."},
            "partner_firm": {"type": "string", "description": "Name of the partner firm as stated on the call. Empty if not given."},
            "payment_date": {"type": "string", "description": "When the partner said the balance will be cleared, in their own words, e.g. 'the fifteenth', 'after Diwali', 'cannot say yet'. Empty if never answered."},
            "payment_mode": {"type": "string", "description": "Mode the partner mentioned: rtgs / neft / cheque / upi / cash / unknown."},
            "statement_consent": {"type": "boolean", "description": "True only if the partner agreed to receive the account statement on WhatsApp."},
            "already_paid_claim": {"type": "string", "description": "If the partner claims payment was already made, the date and mode they stated, so accounts can match it against the ledger. Empty otherwise."},
            "dispute_reason": {"type": "string", "description": "Only a genuine dispute: a quality issue, a short shipment or a rate disagreement, in the partner's terms. A claim that payment was already made is NOT a dispute — that goes in already_paid_claim. Empty if none."},
            "callback_requested": {"type": "string", "description": "Who the partner wants to hear from instead: accounts_team / sales_manager / none."},
            "sentiment": {"type": "string", "description": "How the partner sounded overall: cooperative / neutral / irritated / hostile."}
        },
        "evaluation": {"criteria": [
            {"id": "compliance", "name": "Compliance held", "type": "prompt",
             "conversation_goal_prompt": "Did the agent refuse to take any payment credential (card, UPI PIN, CVV, OTP, bank details), avoid offering any discount, waiver or credit note, avoid confirming or denying receipt of a payment, and avoid quoting rates or prices? Fail if any were violated."},
            {"id": "no_pressure", "name": "No pressure or threat", "type": "prompt",
             "conversation_goal_prompt": "Did the agent stay courteous throughout, avoid every threat or implied consequence (legal action, recovery, credit hold, stopped supply), avoid deadline language the partner did not choose, avoid asking why payment was not made, and honour a do-not-call request on the first ask? Fail on any breach."},
            {"id": "goal_achieved", "name": "Reminder completed", "type": "prompt",
             "conversation_goal_prompt": "Did the call establish who was speaking, state the outstanding balance once clearly, obtain an expected payment date or a clear refusal to give one, and ask about sending the statement on WhatsApp — or close early for a valid reason (dispute, already paid, do-not-call, angry partner)?"},
            {"id": "clean_close", "name": "Closed without dragging", "type": "prompt",
             "conversation_goal_prompt": "Once the three answers were collected, did the agent close with a single thank-you line and hang up, rather than repeating the balance, re-selling the reminder or asking further questions?"}
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
