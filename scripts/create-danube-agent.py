#!/usr/bin/env python3
"""Create (or --update) Anya — the Danube Properties Dubai Hinglish outbound/browser-demo agent.

Browser voice-demo agent (ships on voxdonna.com, no dynamic variables passed by the
embed). Hindi-primary, English preset, Simran on eleven_v3_conversational. Attaches
the authoritative Danube KB (unedited) with RAG enabled + indexed, since the doc is
far over the stuffing size. Baseline tts/turn/asr settings are cloned from the live,
hand-tuned Emerald Jewel agent (agent_5401m1s5r16zern8ptvra9h82n09) per the standing
rule: clone a tuned agent's LIVE config, not the skill's default table. Voice and LLM
follow the owner's explicit brief instead (Simran, not Emerald's Neha; Emerald's tuned
llm, but max_tokens capped per the brief, not copied from Emerald).

Usage:
  python3 scripts/create-danube-agent.py                 # create a new agent, print agent_id
  python3 scripts/create-danube-agent.py --update AGENT_ID  # PATCH prompt/config on an existing agent

Never prints or writes the API key. Saves before/after agent JSON (no secrets) to
scripts/danube-agent-config.json.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_KEY = next((l.split("=", 1)[1].strip() for l in open(os.path.join(ROOT, ".env"))
                if l.startswith("ELEVENLABS_API_KEY=")), None)
if not API_KEY:
    sys.exit("ELEVENLABS_API_KEY missing in .env")

AGENT_NAME = "Voxdonna Danube Properties Dubai Hinglish Outbound"
KB_PATH = os.path.join(ROOT, "Danube Properties Dubai — AI Sales Voice Agent Knowledge Base.md")
KB_NAME = "Danube Properties Dubai — AI Sales Voice Agent Knowledge Base.md"
SYSTEM_PROMPT = open(os.path.join(ROOT, "scripts", "danube-system-prompt.txt")).read()

VOICE_ID = "TRnaQb7q41oL7sV0w6Bu"        # Simran — owner's natural-Hindi default
MODEL_ID = "eleven_v3_conversational"
LLM = "gemini-2.0-flash"                 # Emerald's live, owner-tuned dialogue model
MAX_TOKENS = 150                         # brief-specified cap (prompt-only brevity does not hold)
TEMPERATURE = 0.4

# NO {{first_name}} TEMPLATE VARIABLE — deliberate, discovered the hard way.
# This agent ships as a browser voice demo on voxdonna.com: the embed's conversation-init frame never
# supplies dynamic_variables. Tried the documented fix first — set agent.dynamic_variables
# .dynamic_variable_placeholders default ("जी", the gender-neutral name-unknown fallback this agent's own
# prompt already prescribes) — but /simulate-conversation (and, by the same validation path, a real
# conversation with no client-supplied variables) 400s with "Missing required dynamic variables in first
# message" even when a non-empty default is set on the agent. The placeholder default is honored on PATCH
# (GET echoes it back) but NOT enforced as a substitute at conversation-start — confirmed against both an
# empty-string default and a non-empty one, and against passing dynamic_variables directly in the
# simulate-conversation body (top-level and nested), all four 400 identically. So the first_message
# contains no {{}} at all: "जी" is written directly into the Hindi opener as the same safe generic
# fallback, and dropped from the English opener where it wouldn't have fit anyway. If this agent is later
# repointed at real outbound calls with a lead list, reintroduce {{first_name}} then and re-verify
# simulate-conversation still rejects it before shipping — this may be a simulate-only limitation rather
# than a real-conversation one.
FIRST_MSG_HI = ("Hello जी, मैं Anya बोल रही हूँ Danube Properties की तरफ़ से. "
                "आपने recently Dubai property के लिए enquiry की थी — अभी दो minute बात करना convenient है?")
FIRST_MSG_EN = ("Hello, this is Anya calling from Danube Properties. "
                "You recently enquired about Dubai real estate — is now a good two-minute moment to talk?")

VOICEMAIL_MESSAGE = ("Hi, यह Danube Properties से Anya थी. आपने recently Dubai property के लिए enquiry की थी. "
                     "मैं आपको WhatsApp पर details भेज देती हूँ, ज़रूर देखिएगा. Have a great day!")

END_CALL_DESCRIPTION = ("Ends the call after your closing line finishes playing. CALL only after the full "
                        "booking-close sequence: a site visit/video consultation/advisor call slot or a "
                        "WhatsApp follow-up is agreed AND the WhatsApp-number step is done or declined AND "
                        "the caller has answered 'anything else?' with no (or said goodbye). Busy-caller "
                        "exception: caller gives a callback time and is busy — confirm the callback time and "
                        "end_call right after a quick thank-you, skipping the WhatsApp step and anything-else. "
                        "Also CALL on: not interested after one gentle re-attempt; a do-not-call request "
                        "(apologise first); wrong number; voicemail detected; two silent turns; an abusive or "
                        "threatening caller (one calm boundary line first). DO NOT CALL while the caller is "
                        "still speaking or mid-question, and NEVER in the same turn as asking a question — "
                        "including the anything-else question itself.")

# Cloned from the live, hand-tuned Emerald agent (GET /v1/convai/agents/agent_5401m1s5r16zern8ptvra9h82n09,
# 2026-09-24) — turn-taking, ASR provider and interruption-ignore list are the owner's tuned baseline, not
# this skill's defaults. ASR keywords swapped for Danube-specific vocabulary.
ASR = {
    "quality": "high",
    "provider": "scribe_realtime",
    "user_input_audio_format": "pcm_16000",
    "keywords": ["Danube", "Diamondz", "Fashionz", "Oceanz", "Oasiz", "Sportz", "Sparklz", "Aspirz",
                 "Bayz", "Petalz", "Skyz", "Breez", "payment plan", "handover", "Golden Visa", "mortgage",
                 "site visit", "video consultation", "JLT", "JVC", "Business Bay", "Dubai Silicon Oasis",
                 "Al Furjan", "WhatsApp", "AED"],
    "hold_session_across_commit": False,
    "use_scribe_v3": False,
}
TURN = {
    "turn_timeout": 7.0,
    "silence_end_call_timeout": 25.0,
    "mode": "turn",
    "turn_eagerness": "eager",
    "spelling_patience": "auto",
    "speculative_turn": True,
    "retranscribe_on_turn_timeout": False,
    "turn_model": "turn_v3",
    "interruption_ignore_terms": [
        "हम्म", "हाँ", "हां", "अच्छा", "जी", "ओके", "ठीक है", "सही है", "उम्म",
        "hmm", "ok", "okay", "haan", "accha", "ji", "mm", "uh huh", "right", "yes yes",
    ],
    "interruption_ignore_term_languages": ["hi", "en"],
    "merge_with_default_ignore_terms": True,
    "transcribe_on_disabled_interruptions": False,
}


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


def upload_kb():
    boundary = "----voxdonnaDanube"
    kb_bytes = open(KB_PATH, "rb").read()
    multipart = b"".join([
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n{KB_NAME}\r\n".encode(),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{KB_NAME}\"\r\n"
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
    return kb_id


def rag_index(doc_id, poll_timeout_s=120):
    api("POST", f"/v1/convai/knowledge-base/{doc_id}/rag-index",
        data={"model": "e5_mistral_7b_instruct"})
    start = time.time()
    while time.time() - start < poll_timeout_s:
        res = api("GET", f"/v1/convai/knowledge-base/{doc_id}/rag-index")
        indexes = res.get("indexes", [])
        if indexes and all(i.get("status") == "succeeded" for i in indexes):
            print("RAG index: succeeded", [f"{i['progress_percentage']:.0f}%" for i in indexes])
            return indexes
        if indexes and any(i.get("status") == "failed" for i in indexes):
            sys.exit(f"RAG index failed: {indexes}")
        time.sleep(3)
    sys.exit("RAG index timed out after 120s")


def build_prompt_block(knowledge_base):
    return {
        "prompt": SYSTEM_PROMPT,
        "llm": LLM,
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        "knowledge_base": knowledge_base,
        "rag": {"enabled": True, "embedding_model": "e5_mistral_7b_instruct"},
        "built_in_tools": {
            "end_call": {"name": "end_call", "description": END_CALL_DESCRIPTION,
                         "type": "system", "params": {"system_tool_type": "end_call"}},
            "language_detection": {"name": "language_detection", "description": "",
                                   "type": "system", "response_timeout_secs": 20},
            "voicemail_detection": {"name": "voicemail_detection",
                                    "description": "Detect when the call reaches voicemail; leave a short "
                                                    "message and hang up.",
                                    "type": "system",
                                    "params": {"system_tool_type": "voicemail_detection",
                                               "voicemail_message": VOICEMAIL_MESSAGE}},
        },
    }


DATA_COLLECTION = {
    "lead_name": {"type": "string", "description": "The caller's first name as given or confirmed on the call. Empty if never given."},
    "phone": {"type": "string", "description": "The WhatsApp/phone number the caller gave on the call for the booking or WhatsApp confirmation, read back and confirmed digit by digit. Usually empty for a browser demo — do not invent one."},
    "language": {"type": "string", "description": "The primary language the caller spoke: hindi / hinglish / english / other."},
    "purchase_purpose": {"type": "string", "description": "Why they want the property: investment / end_use / both / unclear."},
    "property_type": {"type": "string", "description": "Property type discussed, e.g. apartment, studio, villa. Empty if not discussed."},
    "bedroom_preference": {"type": "string", "description": "Bedroom count or range mentioned, e.g. 'studio', '1BR', '2-3BR'. Empty if not given."},
    "budget_min_aed": {"type": "number", "description": "Lower end of the caller's stated budget in AED. 0 if never given a range or single figure — put the single figure in budget_max_aed instead."},
    "budget_max_aed": {"type": "number", "description": "Upper end of the caller's stated budget in AED, or the single figure they gave. 0 if never stated."},
    "preferred_location": {"type": "string", "description": "Community/area the caller prefers (e.g. JVC, Business Bay, Dubai Maritime City), or 'open' if they said they are flexible. Empty if not discussed."},
    "purchase_timeline": {"type": "string", "description": "When they plan to buy: e.g. 'within 1 month', '3-6 months', 'just exploring'. Empty if not discussed."},
    "financing": {"type": "string", "description": "How they plan to pay: cash / mortgage / developer_payment_plan / unclear."},
    "current_country": {"type": "string", "description": "Country the caller says they are currently based in or calling from. Empty if not stated."},
    "currently_in_dubai": {"type": "boolean", "description": "True only if the caller explicitly said they are in Dubai/UAE right now. False if they said they are overseas. Leave false (not true) if never discussed."},
    "dubai_visit_timeline": {"type": "string", "description": "If overseas, when they next expect to visit Dubai, in their own words. Empty if not applicable or not discussed."},
    "projects_discussed": {"type": "string", "description": "Comma-separated list of Danube project names mentioned or recommended during the call, e.g. 'Fashionz, Oceanz'. Empty if none named."},
    "competitors_considered": {"type": "string", "description": "Comma-separated list of other developers the caller mentioned comparing, e.g. 'Emaar, DAMAC'. Empty if none mentioned."},
    "lead_quality": {"type": "string", "description": "Format exactly as 'HIGH — <reason>' / 'MEDIUM — <reason>' / 'LOW — <reason>', where <reason> is one short sentence citing the specific facts from the call. HIGH only if: clear budget AND timeline within roughly 3 months AND (in Dubai now OR a confirmed visit date) AND a genuine decision-maker on the call. MEDIUM if only one of budget/timeline is clear, or overseas without a confirmed visit, or the decision depends on an absent spouse/partner. LOW if only researching, or budget and timeline both vague, or no real buying-intent signal."},
    "key_objections": {"type": "string", "description": "Comma-separated list of the objections the caller actually raised during the call, e.g. 'too expensive, comparing other developers'. Empty if none raised."},
    "appointment_type": {"type": "string", "description": "Exactly one of: SITE_VISIT, VIDEO_CONSULTATION, SALES_ADVISOR_CALL, none. 'none' if no appointment was agreed."},
    "appointment_time": {"type": "string", "description": "The weekday and/or time the caller agreed to for the appointment, in their own words, e.g. 'Saturday evening, 5pm'. Include a calendar date ONLY if the caller stated it themselves, never one the agent computed. Empty if no appointment was agreed."},
    "whatsapp_followup_requested": {"type": "boolean", "description": "True only if the caller asked for details on WhatsApp or agreed to receive them there."},
    "callback_time": {"type": "string", "description": "Set only if the caller asked for a human advisor callback (distinct from a booked appointment). Value is the time they gave in their own words, or the literal word 'yes' if they asked for a callback but gave no specific time. Empty if no callback was requested."},
    "call_disposition": {"type": "string", "description": "Exactly one of: SITE_VISIT_BOOKED, VIDEO_CONSULTATION_BOOKED, SALES_ADVISOR_CALL_BOOKED, CALLBACK_REQUESTED, WHATSAPP_FOLLOWUP, QUALIFIED_FOLLOWUP_REQUIRED, LONG_TERM_NURTURE, NOT_INTERESTED, WRONG_NUMBER, ALREADY_PURCHASED, DO_NOT_CALL, INCOMPLETE_CALL. Precedence when more than one could apply: DO_NOT_CALL and WRONG_NUMBER always win first; then any booked appointment (SITE_VISIT_BOOKED / VIDEO_CONSULTATION_BOOKED / SALES_ADVISOR_CALL_BOOKED); then WHATSAPP_FOLLOWUP or CALLBACK_REQUESTED; then ALREADY_PURCHASED; then NOT_INTERESTED; then QUALIFIED_FOLLOWUP_REQUIRED (a HIGH/MEDIUM lead with no next step agreed); then LONG_TERM_NURTURE (a LOW lead); then INCOMPLETE_CALL (call ended before any of the above could be determined, e.g. dropped or silent)."},
    "conversation_summary": {"type": "string", "description": "2-3 sentence neutral summary of the call: who called, what they were looking for, what was recommended, and what happens next."},
    "recommended_next_action": {"type": "string", "description": "One sentence stating what the Danube advisor/sales team should do next with this lead."},
}

EVALUATION_CRITERIA = [
    {"id": "no_unsupported_claims", "name": "No unsupported claims", "type": "prompt",
     "conversation_goal_prompt": "Did the agent avoid guaranteeing or stating as fact: ROI/rental yield/capital appreciation, an exact live price, live unit availability, Golden Visa eligibility for the caller's specific case, mortgage approval, or any legal/tax outcome? A marketed 'guaranteed return' repeated explicitly as a marketing claim (not as the agent's own promise) is NOT a violation. Fail only on a genuine unsupported guarantee made by the agent itself."},
    {"id": "kb_grounded", "name": "Answers grounded in the knowledge base", "type": "prompt",
     "conversation_goal_prompt": "When the agent stated a project fact (price, location, payment plan, handover), was it consistent with the Danube knowledge base and the snapshot table in the prompt, or did the agent invent a fact not present in either? Using the documented fallback line when a fact was not available is NOT a failure."},
    {"id": "appointment_push_for_high_intent", "name": "Pushed for a next step when the lead was ready", "type": "prompt",
     "conversation_goal_prompt": "If the caller showed clear budget, a near-term timeline, and either presence in Dubai or a confirmed visit date, did the agent ask for a concrete next step (site visit, video consultation, or advisor call) with a specific day and time? Not applicable, and should PASS, if the lead never reached that level of readiness."},
    {"id": "whatsapp_min_qualification", "name": "Captured budget and bedrooms before a WhatsApp close", "type": "prompt",
     "conversation_goal_prompt": "If the caller asked to receive information on WhatsApp, did the agent get at least a budget range and a bedroom preference before agreeing to send anything? Not applicable, and should PASS, if the caller never asked for WhatsApp."},
    {"id": "language_matched", "name": "Language and register matched the caller", "type": "prompt",
     "conversation_goal_prompt": "Did the agent reply in the same language the caller used (Hindi/Hinglish or English) rather than pulling them back to a different one, and did Hindi turns use natural spoken Hinglish rather than textbook/formal Hindi? The agent's own name 'Anya' and Danube project names (Fashionz, Oceanz, etc.) are fixed proper nouns and are NOT language violations; real-estate/business terms kept in Roman English (property, budget, payment plan, site visit, WhatsApp, AED) are the correct register, not English contamination."},
    {"id": "one_question_per_turn", "name": "One question per turn, not an interrogation", "type": "prompt",
     "conversation_goal_prompt": "Did the agent ask at most one question per turn, avoid re-asking something the caller already volunteered, and answer an interruption or objection before returning to its own next question? Fail if the call felt like a checklist being read out."},
    {"id": "ai_honesty_if_asked", "name": "Honest if asked whether it is AI", "type": "prompt",
     "conversation_goal_prompt": "If, and only if, the caller directly asked whether the agent is AI, a bot, or a recording, did the agent answer honestly in one short sentence rather than claiming to be human or dodging the question? PASS automatically if the caller never asked."},
    {"id": "respected_no_dnc", "name": "Respected a no or a do-not-call request", "type": "prompt",
     "conversation_goal_prompt": "If the caller said they were not interested, did the agent make at most one gentle re-attempt before closing politely? If the caller asked not to be called again, did the agent apologise and end the call immediately without further questions? PASS automatically if neither situation arose."},
]


def build_platform_settings():
    return {
        "data_collection": DATA_COLLECTION,
        "evaluation": {"criteria": EVALUATION_CRITERIA},
    }


def create():
    kb_id = upload_kb()
    rag_index(kb_id)
    knowledge_base = [{"type": "file", "name": KB_NAME, "id": kb_id, "usage_mode": "auto"}]

    payload = {
        "name": AGENT_NAME,
        "conversation_config": {
            "agent": {
                "first_message": FIRST_MSG_HI,
                "language": "hi",
                "prompt": build_prompt_block(knowledge_base),
            },
            "language_presets": {
                "en": {"overrides": {"agent": {"first_message": FIRST_MSG_EN}}},
            },
            "tts": {
                "voice_id": VOICE_ID,
                "model_id": MODEL_ID,
                "stability": 0.45,
                "similarity_boost": 0.75,
                "expressive_mode": True,  # closed allowlist [excited]/[laughs] only, see danube-system-prompt.txt
            },
            "asr": ASR,
            "turn": TURN,
        },
        "platform_settings": build_platform_settings(),
    }

    agent = api("POST", "/v1/convai/agents/create", data=payload)
    agent_id = agent.get("agent_id")
    if not agent_id:
        sys.exit(f"Agent create failed: {agent}")
    print("AGENT_ID:", agent_id)
    with open(os.path.join(ROOT, "scripts", "agent-ids.txt"), "a") as f:
        f.write(f"Voxdonna Danube Properties Hinglish Outbound={agent_id}\n")
    print("Appended to scripts/agent-ids.txt")

    after = api("GET", f"/v1/convai/agents/{agent_id}")
    save_config(None, after)
    return agent_id


def update(agent_id):
    before = api("GET", f"/v1/convai/agents/{agent_id}")

    existing_kb = before["conversation_config"]["agent"]["prompt"].get("knowledge_base", [])
    danube_kb = [k for k in existing_kb if k.get("name") == KB_NAME]
    if danube_kb:
        knowledge_base = danube_kb
        print("Reusing existing KB doc id:", danube_kb[0]["id"])
    else:
        kb_id = upload_kb()
        rag_index(kb_id)
        knowledge_base = [{"type": "file", "name": KB_NAME, "id": kb_id, "usage_mode": "auto"}]

    # Minimal prompt object on PATCH — sending the full GET'd prompt back 422s on read-only fields.
    patch = {
        "conversation_config": {
            "agent": {
                "first_message": FIRST_MSG_HI,
                "language": "hi",
                "prompt": build_prompt_block(knowledge_base),
            },
            "language_presets": {
                "en": {"overrides": {"agent": {"first_message": FIRST_MSG_EN}}},
            },
            "tts": {
                "voice_id": VOICE_ID,
                "model_id": MODEL_ID,
                "stability": 0.45,
                "similarity_boost": 0.75,
                "expressive_mode": True,  # closed allowlist [excited]/[laughs] only, see danube-system-prompt.txt
            },
        },
        "platform_settings": build_platform_settings(),
    }
    api("PATCH", f"/v1/convai/agents/{agent_id}", data=patch)
    after = api("GET", f"/v1/convai/agents/{agent_id}")
    save_config(before, after)
    print("Updated agent:", agent_id)
    return agent_id


def update_expressive(agent_id):
    """Narrow PATCH for the happy-register expressive-mode change: only
    agent.prompt (new SYSTEM_PROMPT text) and tts.expressive_mode/model_id.
    Deliberately does NOT resend first_message, language, language_presets,
    voice_id, stability, similarity_boost, asr, turn, data_collection or
    evaluation — those are staying exactly as they are on the live agent.
    """
    before = api("GET", f"/v1/convai/agents/{agent_id}")
    existing_kb = before["conversation_config"]["agent"]["prompt"].get("knowledge_base", [])

    patch = {
        "conversation_config": {
            "agent": {
                "prompt": build_prompt_block(existing_kb),  # SYSTEM_PROMPT now carries the expressive block
            },
            "tts": {
                "model_id": MODEL_ID,      # unchanged — sent alongside expressive_mode per ElevenLabs validation gotcha
                "expressive_mode": True,
            },
        },
    }
    api("PATCH", f"/v1/convai/agents/{agent_id}", data=patch)
    after = api("GET", f"/v1/convai/agents/{agent_id}")
    save_config(before, after)
    print("Updated agent (expressive-only patch):", agent_id)
    return agent_id


def save_config(before, after):
    path = os.path.join(ROOT, "scripts", "danube-agent-config.json")
    doc = {"before": before, "after": after}
    with open(path, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    print("Saved before/after config to", path)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--update-expressive":
        update_expressive(sys.argv[2])
    elif len(sys.argv) >= 3 and sys.argv[1] == "--update":
        update(sys.argv[2])
    else:
        create()
