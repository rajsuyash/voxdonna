#!/usr/bin/env python3
"""Create the Finman Capital Services corporate finance concierge (Ira) — English
inbound qualification-and-routing demo. Uploads the KB, creates the ConvAI agent
with end_call, and the conversion layer (data collection, evaluation criteria).
Prints agent_id. Re-running creates a NEW agent. Run once."""
import json, os, sys, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_KEY = next((l.split("=", 1)[1].strip() for l in open(os.path.join(ROOT, ".env"))
                if l.startswith("ELEVENLABS_API_KEY=")), None)
if not API_KEY:
    sys.exit("ELEVENLABS_API_KEY missing in .env")

KB_FILE = "finman-capital-concierge.md"
VOICE_ID = "C2S5J6WvmHnrQWjUu6Rg"          # Kanika — Indian female, warm and measured
MODEL_ID = "eleven_v3_conversational"
AGENT_NAME = "Voxdonna Finman Capital Corporate Finance Concierge Demo"

FIRST_MSG = ("Thank you for calling Finman Capital Services, this is Ira — I'm an AI assistant "
             "on the advisory line. Are you calling about funding, project finance, M&A or growth "
             "capital, insurance, or an existing mandate with us?")


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
boundary = "----voxdonnaFinmanCapital"
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

SYSTEM_PROMPT = open(os.path.join(ROOT, "scripts", "finman-capital-system-prompt.txt")).read()

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
                "keywords": ["Finman", "crore", "working capital", "term sheet", "syndication",
                             "NBFC", "TEV", "cap table", "sum insured", "promoter", "mandate"]},
        "turn": {"turn_timeout": 10, "silence_end_call_timeout": 25, "mode": "turn"}
    },
    "platform_settings": {
        "data_collection": {
            "outcome": {"type": "string", "description": "Overall outcome: advisory_call_booked / discovery_call_booked / desk_review_no_meeting / escalated_to_human / wrong_line / info_only / abandoned."},
            "service_line": {"type": "string", "description": "Desk the enquiry belongs to: debt_working_capital / project_infrastructure_finance / ma_growth_capital / insurance_reinsurance / existing_mandate."},
            "company_name": {"type": "string", "description": "Company or group name, and the transacting entity if different. Empty if not given."},
            "caller_name": {"type": "string", "description": "Caller's name and designation, e.g. 'Anand Mehta - CFO'. Empty if not given."},
            "sector": {"type": "string", "description": "Industry or sector of the company. Empty if not given."},
            "location": {"type": "string", "description": "City and state of main operations. Empty if not given."},
            "deal_size_cr": {"type": "string", "description": "Requirement or transaction size in INR crore as stated, e.g. '80'. For insurance, annual premium or sum insured with the unit noted. Empty if not given."},
            "use_of_funds": {"type": "string", "description": "What the funds or the transaction are for, in the caller's terms."},
            "tenure_or_close": {"type": "string", "description": "Tenure sought, or expected time to close the transaction. Empty if not discussed."},
            "security_offered": {"type": "string", "description": "Collateral or security available, including promoter guarantee. Empty if not discussed."},
            "existing_lenders": {"type": "string", "description": "Existing lenders or investors, and anything already sanctioned. Empty if none or not discussed."},
            "financials_ready": {"type": "string", "description": "Audited financials: available / partial / not_available / unknown."},
            "projections_ready": {"type": "string", "description": "Projections or financial model: available / in_progress / not_started / unknown."},
            "transaction_stage": {"type": "string", "description": "Where it stands: exploring / mandate_stage / term_sheet / diligence / unknown."},
            "timeline": {"type": "string", "description": "When the caller wants money in the bank or the transaction signed. Empty if not discussed."},
            "deal_score": {"type": "number", "description": "Score this enquiry out of ten from the transcript. Award a point each for: deal size of ten crore or more, a sector the firm covers, audited financials available, projections available, a clear and legitimate use of funds, a timeline inside six months, security or promoter guarantee offered, a decision-maker on the call, an existing banking relationship disclosed, and a referral or existing-client source. Subtract two if there are no financials, two if the use of funds is vague, and two if the caller has no authority on the transaction. Floor at zero, cap at ten."},
            "routing_desk": {"type": "string", "description": "Name the desk this brief belongs to, inferred from what the caller described, even if the agent never said it aloud: Debt and Working Capital / Project and Infrastructure Finance / M&A and Growth Capital / Insurance and Reinsurance / Client Servicing. Add a second desk after a comma only if the enquiry genuinely spans two."},
            "source": {"type": "string", "description": "How the caller came to Finman: referral / existing_client / website / event / banker_introduction / outbound / unknown."},
            "contact_email": {"type": "string", "description": "Best email as confirmed by read-back. Empty if not given."},
            "contact_mobile": {"type": "string", "description": "Best mobile number as confirmed. Empty if not given."},
            "checklist_channel": {"type": "string", "description": "Where the document checklist should go: email / whatsapp / both / declined."},
            "meeting_slot": {"type": "string", "description": "Advisory call slot agreed. Empty if no meeting was booked."},
            "escalation_flags": {"type": "string", "description": "Always output a value, comma-separated if more than one applies, and the literal word none if no trigger fired. Set only when the call actually hit an escalation trigger: existing_client_complaint / distressed_asset / guarantee_demanded (the caller refused to proceed without a guaranteed sanction, rate or valuation - NOT merely asking about rates once) / improper_payment / legal_regulatory / documents_on_call / institution_caller. Otherwise none."}
        },
        "evaluation": {"criteria": [
            {"id": "compliance", "name": "Compliance held", "type": "prompt",
             "conversation_goal_prompt": "Did the agent declare itself an AI, avoid promising or implying approval, sanction, an interest rate, a valuation, insurer acceptance or lender appetite, avoid any investment recommendation or eligibility opinion, avoid naming a bank, NBFC, fund or insurer that would take the deal, avoid quoting fees or success rates, and refuse to take documents, account numbers, credentials or payment on the call? Fail if any were violated."},
            {"id": "disclaimer_given", "name": "Routing disclaimer stated", "type": "prompt",
             "conversation_goal_prompt": "Did the agent state, in plain words before booking, that the information collected is preliminary and for routing, and that final structuring and eligibility are assessed by Finman's advisory team and the relevant financial institutions? Pass the call if it ended in an escalation or a wrong-line close before any booking - the disclaimer is only owed when a meeting is being set."},
            {"id": "qualification_completeness", "name": "Mandate qualified", "type": "prompt",
             "conversation_goal_prompt": "Did the agent capture the qualification set for the service line - deal size, use of funds, timeline, security or structure, existing lenders, financials and projections readiness, transaction stage, company, sector and caller designation - or escalate before completing them for a valid reason?"},
            {"id": "routing_correct", "name": "Routed to the right desk", "type": "prompt",
             "conversation_goal_prompt": "Did the agent route the enquiry to the correct desk for what the caller described - debt and working capital, project and infrastructure finance, M&A and growth capital, insurance and reinsurance, or client servicing for an existing mandate - and handle a below-threshold or weak-fit enquiry without committing to a senior meeting?"},
            {"id": "goal_achieved", "name": "Advisor-ready brief produced", "type": "prompt",
             "conversation_goal_prompt": "Did the call end with a booked advisory or discovery call plus a mandate reference and a checklist channel, or a clean escalation or expectation-set close for a weak-fit enquiry?"}
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
