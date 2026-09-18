#!/usr/bin/env python3
"""Create the BSES new-connection voice assistant on ElevenLabs.

Different from the sales/KB demo agents: this agent's whole job is to drive the
BSES web page via CLIENT TOOLS (browser callbacks). We register 5 client tools,
attach them by tool_ids, and put system tools (end_call, language_detection) in
built_in_tools. Voice: Neha (Indian), model eleven_multilingual_v2 for Hinglish.

Run:  python3 scripts/create-bses-agent.py
"""
import json, os, subprocess, sys, urllib.request, urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = "https://api.elevenlabs.io"

def api_key() -> str:
    for line in (ROOT / ".env").read_text().splitlines():
        if line.startswith("ELEVENLABS_API_KEY="):
            return line.split("=", 1)[1].strip()
    sys.exit("ELEVENLABS_API_KEY missing in .env")

KEY = api_key()

def call(path: str, payload: dict, method: str = "POST") -> dict:
    req = urllib.request.Request(
        API + path,
        data=json.dumps(payload).encode(),
        headers={"xi-api-key": KEY, "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path} -> {e.code}: {e.read().decode()}")

def post(path: str, payload: dict) -> dict:
    return call(path, payload, "POST")

# --- Step 1: upload KB (curl handles multipart content-type cleanly) --------
def upload_kb() -> str:
    out = subprocess.run(
        ["curl", "-sS", "-X", "POST", f"{API}/v1/convai/knowledge-base/file",
         "-H", f"xi-api-key: {KEY}",
         "-F", "name=bses-new-connection.md",
         "-F", f"file=@{ROOT}/kb/bses-new-connection.md;type=text/markdown"],
        capture_output=True, text=True,
    )
    data = json.loads(out.stdout or "{}")
    kb_id = data.get("id")
    if not kb_id:
        sys.exit(f"KB upload failed: {out.stdout} {out.stderr}")
    print("KB id:", kb_id)
    return kb_id

# --- Step 2: client tools ---------------------------------------------------
def schema(props: dict):
    """JSON-schema object for a client tool's parameters (empty props = no args)."""
    s = {"type": "object", "properties": props}
    if props:
        s["required"] = list(props)
    return s

def prop(desc):
    return {"type": "string", "description": desc}

CLIENT_TOOLS = [
    {"type": "client", "name": "open_application", "expects_response": True,
     "description": "Open the New Connection application form on the BSES website. "
                    "Call this once, right after the visitor agrees to apply, BEFORE asking for any detail. "
                    "Returns a confirmation that the form is now visible.",
     "parameters": schema({})},
    {"type": "client", "name": "set_field", "expects_response": True,
     "description": "Fill ONE text field on the open application form and highlight it. "
                    "Call immediately after the visitor gives that detail. Returns confirmation.",
     "parameters": schema({
        "field_id": prop("Which field to fill. Must be EXACTLY one of: applicant_name, mobile, email, address, pincode, load_kw."),
        "value": prop("The value the visitor gave for this field. For load_kw give only the number, e.g. '3'."),
     })},
    {"type": "client", "name": "set_choice", "expects_response": True,
     "description": "Select ONE option field (radio or dropdown) on the form and highlight it. "
                    "Call immediately after the visitor tells you their choice. Map their words to the nearest allowed value. Returns confirmation.",
     "parameters": schema({
        "field_id": prop("Which choice field. Must be EXACTLY one of: connection_category, id_proof, ownership."),
        "value": prop("The chosen value. connection_category must be one of Domestic, Non-Domestic, Industrial. "
                      "id_proof must be one of Aadhaar, Voter ID, Passport, Driving Licence. "
                      "ownership must be one of Owned, Rented."),
     })},
    {"type": "client", "name": "review_application", "expects_response": True,
     "description": "Show the review summary of everything entered so far. Call once all fields are filled, "
                    "before submitting, so you can read the details back for confirmation. "
                    "Returns the collected values as text for you to read aloud.",
     "parameters": schema({})},
    {"type": "client", "name": "submit_application", "expects_response": True,
     "description": "Submit the completed application. Call ONLY after the visitor has confirmed the summary is correct. "
                    "Returns the application reference number for you to read out.",
     "parameters": schema({})},
]

def create_tools() -> list:
    ids = []
    for tc in CLIENT_TOOLS:
        res = post("/v1/convai/tools", {"tool_config": tc})
        tid = res.get("id") or res.get("tool_id")
        if not tid:
            sys.exit(f"tool create failed for {tc['name']}: {res}")
        print(f"tool {tc['name']}: {tid}")
        ids.append(tid)
    return ids

# --- Step 3: system prompt --------------------------------------------------
SYSTEM_PROMPT = """You are the BSES voice assistant on the BSES website. You have a FEMALE voice. Your only job: help a visitor apply for a NEW electricity connection by filling the on-screen application form for them, one field at a time, using your tools.

START: The visitor has just been greeted. When they agree to apply (or ask to start), FIRST call open_application to open the form. Then collect details.

COLLECT THESE FIELDS, ONE AT A TIME, IN THIS ORDER. Ask a short question, wait for the answer, then IMMEDIATELY call the matching tool with the value before asking the next one:
1. applicant_name -> set_field(field_id="applicant_name")
2. mobile -> set_field(field_id="mobile")  (10-digit mobile)
3. email -> set_field(field_id="email")  (optional; if they skip, move on)
4. connection_category -> set_choice(field_id="connection_category", value= Domestic | Non-Domestic | Industrial)
5. address -> set_field(field_id="address")  (premises address in Delhi)
6. pincode -> set_field(field_id="pincode")  (6-digit)
7. load_kw -> set_field(field_id="load_kw")  (number only; if unsure, suggest from the KB: ~3 kW for a 2 BHK home, more for shops/industry)
8. id_proof -> set_choice(field_id="id_proof", value= Aadhaar | Voter ID | Passport | Driving Licence)
9. ownership -> set_choice(field_id="ownership", value= Owned | Rented)

Read back the NAME and EMAIL to confirm spelling. Map the visitor's words to the exact allowed values above. Only ask which TYPE of ID proof they will use — NEVER ask for the Aadhaar number or any document number.

FINISH: After all nine fields are filled, you MUST call review_application (never skip it) and read back the FULL summary it returns to you — every field — then ask "Shall I submit this?". If they want a change, call the right set_field or set_choice again, then call review_application again. Only after they confirm, call submit_application and read out the reference number it returns, digit by digit, and tell them BSES will SMS them the status. Then give a short goodbye and call end_call.

LANGUAGE: Start in English. If the visitor speaks Hindi, switch to Hindi in Devanagari script (देवनागरी) and stay there. Keep tech/brand words in Roman as people actually say them: BSES, kilowatt, kW, Aadhaar, email, pincode, PIN.

GENDER RULE (female voice): In Hindi ALWAYS use feminine first-person forms — "मैं भर रही हूँ", "मैं बता सकती हूँ", "मैंने भर दिया"। NEVER masculine ("भर रहा हूँ", "बता सकता हूँ").

COMPLIANCE: You are BSES's AI assistant — say so if asked, never claim to be a human. Never quote a final connection charge or deposit — say BSES calculates it after load and category are confirmed. Never ask for Aadhaar/bank/card numbers, OTPs, or passwords. Never guarantee a connection date. Billing, outages, or existing-connection changes are out of scope — offer to continue the new-connection application instead.

TTS FLUENCY: One question per turn, kept short. Single punctuation only, never !!! or ??. Sentences 12-20 words. Max 2-3 em-dashes in the whole call. Spell numbers in words when speaking Hindi (तीन किलोवाट, not 3). No ALL CAPS."""

FIRST_MSG_EN = ("Hello, welcome to BSES. I'm the BSES voice assistant, and I can help you apply for a "
                "new electricity connection right now. Shall I open the application form and take your details?")
FIRST_MSG_HI = ("नमस्ते, बीएसईएस में आपका स्वागत है। मैं बीएसईएस की वॉइस असिस्टेंट हूँ, और मैं अभी आपके लिए "
                "नया बिजली कनेक्शन का आवेदन भर सकती हूँ। क्या मैं फ़ॉर्म खोलकर आपकी जानकारी लेना शुरू करूँ?")

def create_agent(kb_id: str, tool_ids: list) -> str:
    payload = {
        "name": "BSES New Connection Assistant",
        "conversation_config": {
            "agent": {
                "first_message": FIRST_MSG_EN,
                "language": "en",
                "prompt": {
                    "prompt": SYSTEM_PROMPT,
                    "llm": "gpt-4o",
                    "temperature": 0.4,
                    "max_tokens": 600,
                    "knowledge_base": [{"type": "file", "name": "bses-new-connection.md",
                                        "id": kb_id, "usage_mode": "auto"}],
                    "tool_ids": tool_ids,
                    "built_in_tools": {
                        "end_call": {"name": "end_call", "description": "", "type": "system",
                                     "params": {"system_tool_type": "end_call"}},
                        "language_detection": {"name": "language_detection", "description": "",
                                               "type": "system", "response_timeout_secs": 20},
                    },
                },
            },
            "tts": {"voice_id": "QTKSa2Iyv0yoxvXY2V8a", "model_id": "eleven_multilingual_v2",
                    "stability": 0.45, "similarity_boost": 0.75},
            "asr": {"quality": "high", "provider": "elevenlabs",
                    "user_input_audio_format": "pcm_16000", "keywords": ["BSES", "kilowatt", "Aadhaar"]},
            "turn": {"turn_timeout": 12, "silence_end_call_timeout": 30, "mode": "turn"},
            "language_presets": {
                "hi": {"overrides": {"agent": {"first_message": FIRST_MSG_HI}}},
            },
        },
        "platform_settings": {
            "data_collection": {
                "applicant_name": {"type": "string", "description": "Applicant full name captured."},
                "mobile": {"type": "string", "description": "Applicant 10-digit mobile."},
                "connection_category": {"type": "string", "description": "Domestic / Non-Domestic / Industrial."},
                "load_kw": {"type": "number", "description": "Sanctioned load requested in kW."},
                "submitted": {"type": "boolean", "description": "True if the application was submitted (submit_application fired)."},
            },
            "evaluation": {"criteria": [
                {"id": "form_completed", "name": "Form completed", "type": "prompt",
                 "conversation_goal_prompt": "Did the assistant collect all required fields and submit the application?"},
                {"id": "compliance", "name": "Compliance held", "type": "prompt",
                 "conversation_goal_prompt": "Did the assistant declare itself AI when relevant, avoid asking for Aadhaar/bank/OTP numbers, and avoid quoting final charges or guaranteeing dates?"},
            ]},
        },
    }
    res = post("/v1/convai/agents/create", payload)
    aid = res.get("agent_id")
    if not aid:
        sys.exit(f"agent create failed: {res}")
    return aid

def get(path: str) -> dict:
    req = urllib.request.Request(API + path, headers={"xi-api-key": KEY})
    with urllib.request.urlopen(req) as r:
        return json.load(r)

def patch_prompt(agent_id: str):
    """Re-PATCH only the system prompt, preserving KB + tools (minimal prompt object)."""
    pr = get(f"/v1/convai/agents/{agent_id}")["conversation_config"]["agent"]["prompt"]
    minimal = {
        "prompt": SYSTEM_PROMPT, "llm": pr.get("llm", "gpt-4o"),
        "temperature": pr.get("temperature", 0.4), "max_tokens": pr.get("max_tokens", 600),
        "knowledge_base": pr.get("knowledge_base", []), "tool_ids": pr.get("tool_ids", []),
        "built_in_tools": pr.get("built_in_tools", {}),
    }
    call(f"/v1/convai/agents/{agent_id}",
         {"conversation_config": {"agent": {"prompt": minimal}}}, "PATCH")
    print("Prompt patched for", agent_id)

if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--patch":
        patch_prompt(sys.argv[2])
        sys.exit(0)
    kb = os.environ.get("KB_ID") or upload_kb()  # reuse an already-uploaded KB via KB_ID=...
    tids = create_tools()
    agent_id = create_agent(kb, tids)
    print("\nAGENT_ID:", agent_id)
    with (ROOT / "scripts" / "agent-ids.txt").open("a") as f:
        f.write(f"BSES New Connection Assistant={agent_id}\n")
    print("Appended to scripts/agent-ids.txt")
