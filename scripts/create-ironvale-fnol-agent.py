#!/usr/bin/env python3
"""Create the Ironvale General Insurance FNOL agent (Claire) — English inbound
claims-intake demo. Uploads the KB, creates the ConvAI agent with end_call,
and the conversion layer (data collection, evaluation criteria). Prints agent_id.
Re-running creates a NEW agent. Run once."""
import json, os, sys, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_KEY = next((l.split("=", 1)[1].strip() for l in open(os.path.join(ROOT, ".env"))
                if l.startswith("ELEVENLABS_API_KEY=")), None)
if not API_KEY:
    sys.exit("ELEVENLABS_API_KEY missing in .env")

KB_FILE = "ironvale-insurance-fnol.md"
VOICE_ID = "QTKSa2Iyv0yoxvXY2V8a"          # Neha — Indian female
MODEL_ID = "eleven_v3_conversational"
AGENT_NAME = "Voxdonna Ironvale Insurance FNOL Demo"

FIRST_MSG = ("Ironvale claims, this is Claire — I'm an AI assistant on the twenty-four-hour "
             "claims line. Before anything else, is everyone safe, or is someone injured?")


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
boundary = "----voxdonnaIronvale"
kb_bytes = open(os.path.join(ROOT, "kb", KB_FILE), "rb").read()
multipart = b"".join([
    f"--{boundary}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n{KB_FILE}\r\n".encode(),
    f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{KB_FILE}\"\r\n"
    f"Content-Type: text/markdown\r\n\r\n".encode(),
    kb_bytes,
    f"\r\n--{boundary}--\r\n".encode(),
])
kb = api("POST", "/v1/convai/knowledge-base/file", raw=multipart,
         headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
kb_id = kb.get("id")
if not kb_id:
    sys.exit(f"KB upload failed: {kb}")
print("KB ID:", kb_id)

SYSTEM_PROMPT = open(os.path.join(ROOT, "scripts", "ironvale-fnol-system-prompt.txt")).read()

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
                "max_tokens": 512,
                "knowledge_base": [
                    {"type": "file", "name": KB_FILE, "id": kb_id, "usage_mode": "auto"}
                ],
                "built_in_tools": {
                    "end_call": {"name": "end_call", "description": "", "type": "system",
                                 "params": {"system_tool_type": "end_call"}}
                }
            }
        },
        "tts": {
            "voice_id": VOICE_ID,
            "model_id": MODEL_ID,
            "stability": 0.45,
            "similarity_boost": 0.75
        },
        "asr": {"quality": "high", "provider": "scribe_realtime",
                "user_input_audio_format": "pcm_16000",
                "keywords": ["Ironvale", "FNOL", "FIR", "surveyor", "policy number",
                             "registration number", "cashless", "garage", "claim"]},
        "turn": {"turn_timeout": 10, "silence_end_call_timeout": 25, "mode": "turn"}
    },
    "platform_settings": {
        "data_collection": {
            "outcome": {"type": "string", "description": "Overall outcome: claim_registered / escalated_to_human / wrong_line / info_only / abandoned."},
            "claim_type": {"type": "string", "description": "Type of loss: motor_accident / motor_theft / third_party / home_property / shop_business / other."},
            "identity_verified": {"type": "boolean", "description": "True only if the caller gave a policy number or the registered mobile plus policyholder name."},
            "policy_number": {"type": "string", "description": "Policy number as stated and read back. Empty if not provided."},
            "caller_name": {"type": "string", "description": "Caller's name and relationship to the policy, e.g. 'Rohit Sharma - policyholder'. Empty if not shared."},
            "loss_datetime": {"type": "string", "description": "Date and time of the loss as stated by the caller. Empty if not captured."},
            "loss_location": {"type": "string", "description": "Location of the loss - city and road/landmark, or property address. Empty if not captured."},
            "incident_description": {"type": "string", "description": "Two-line factual summary of what happened, in the caller's terms."},
            "vehicle_or_property": {"type": "string", "description": "Vehicle registration, make and model, or the property/shop details. Empty if not applicable."},
            "drivable": {"type": "string", "description": "For motor claims: drivable / needs_tow / not_applicable / unknown."},
            "injuries_reported": {"type": "boolean", "description": "True if any injury or fatality to anyone, including third parties, was mentioned."},
            "third_party_involved": {"type": "string", "description": "Third-party names, vehicle numbers or insurer if mentioned. Empty if none."},
            "police_report_number": {"type": "string", "description": "FIR or police report number if given. Empty if none exists yet."},
            "photos_optin": {"type": "boolean", "description": "True only if the caller agreed to receive the photo-upload link on WhatsApp or SMS."},
            "callback_preference": {"type": "string", "description": "Best callback number and preferred channel (call or WhatsApp). Empty if not captured."},
            "escalation_reason": {"type": "string", "description": "Why the call was escalated: injury / emergency / legal / suspected_fraud / vulnerable_caller / coverage_dispute / human_requested / none."}
        },
        "evaluation": {"criteria": [
            {"id": "safety_first", "name": "Safety check ran first", "type": "prompt",
             "conversation_goal_prompt": "Did the agent ask whether anyone was injured or unsafe before starting the intake checklist, and if an injury or live emergency was mentioned, did it direct the caller to emergency services and escalate instead of continuing the checklist?"},
            {"id": "compliance", "name": "Compliance held", "type": "prompt",
             "conversation_goal_prompt": "Did the agent declare itself an AI, refuse to state whether the claim is covered or payable, avoid quoting any settlement, repair or deductible amount, avoid collecting payment or OTP details, and avoid revealing policy data before the caller was verified? Fail if any were violated."},
            {"id": "field_completeness", "name": "Mandatory FNOL fields captured", "type": "prompt",
             "conversation_goal_prompt": "Did the agent capture the mandatory intake fields for the claim type - identity, date and time of loss, location, what happened, injuries, third parties, police report if applicable, and a callback number - or escalate before completing them for a valid reason?"},
            {"id": "goal_achieved", "name": "Claim registered or cleanly escalated", "type": "prompt",
             "conversation_goal_prompt": "Did the call end with either a registered claim - reference number read back, photo-upload consent taken, next steps and surveyor timeline explained - or a clean escalation to a human with the reason flagged?"}
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
