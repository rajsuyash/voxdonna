#!/usr/bin/env python3
"""Create (or --update) Aisha — the IIJS Jewellers gift-and-catalogue browser-demo agent.

Inbound browser voice-demo agent (ships on voxdonna.com, no dynamic variables
passed by the embed). Hindi-primary Hinglish, English preset, Anjali on
eleven_v3_conversational — a distinct voice from the PC Jewellers demo (Simran)
so the two adjacent jewellery-vertical cards don't repeat a voice. ASR/turn
settings cloned from the live, hand-tuned Danube agent (the standing rule: clone
a tuned agent's LIVE config, not the skill's default table), with keywords swapped
for gift/catalogue/custom-order vocabulary. Attaches the workspace's existing
search_web webhook tool (Tavily via voxdonna.com/websearch.php) for live gold and
silver rate lookups — reuses the tool_id created for the Joyalukkas agent rather
than re-provisioning secrets.

Usage:
  python3 scripts/create-iijs-jewellers-agent.py                    # create, print agent_id
  python3 scripts/create-iijs-jewellers-agent.py --update AGENT_ID  # PATCH an existing agent

Never prints or writes the API key. Saves before/after agent JSON (no secrets) to
scripts/iijs-jewellers-agent-config.json.
"""
import json
import os
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_api_key():
    env_key = os.environ.get("ELEVENLABS_API_KEY")
    if env_key:
        return env_key
    env_path = os.path.join(ROOT, ".env")
    if os.path.exists(env_path):
        for line in open(env_path):
            if line.startswith("ELEVENLABS_API_KEY="):
                return line.split("=", 1)[1].strip()
    return None


API_KEY = load_api_key()
if not API_KEY:
    sys.exit("ELEVENLABS_API_KEY missing (checked process env and .env)")

AGENT_NAME = "Voxdonna IIJS Jewellers Gift & Catalogue Demo"
KB_PATH = os.path.join(ROOT, "kb", "iijs-jewellers-gift-catalogue.md")
KB_NAME = "iijs-jewellers-gift-catalogue.md"
SYSTEM_PROMPT = open(os.path.join(ROOT, "scripts", "iijs-jewellers-system-prompt.txt")).read()

VOICE_ID = "gHu9GtaHOXcSqFTK06ux"           # Anjali - Warm, Cheerful and Clear (distinct from PC Jewellers' Simran)
MODEL_ID = "eleven_v3_conversational"
LLM = "gpt-4o"                              # mini/turbo are unreliable at tool-calls (search_web)
MAX_TOKENS = 400
TEMPERATURE = 0.4

SEARCH_WEB_TOOL_ID = "tool_7701ky2zqzgveafscpac1hh1mhg8"  # existing workspace tool -> websearch.php

FIRST_MSG_HI = ("Hello, मैं आइशा हूँ, IIJS Jewellers की तरफ़ से। Gold या silver rate, catalogue, "
                "gift suggestion, या custom order — आज किसमें मदद कर सकती हूँ?")
FIRST_MSG_EN = ("Hello, I'm Aisha, here for IIJS Jewellers. Today's gold or silver rate, our "
                 "catalogue, a gift suggestion, or a custom order — where should we start?")

END_CALL_DESCRIPTION = ("Ends the call after your closing line finishes playing. CALL when: a "
                        "gift suggestion has been given or a custom-order brief has been noted "
                        "(metal, budget, timeline captured); the caller says goodbye or is done; "
                        "the caller asks an out-of-scope or escalation question and has been "
                        "routed to customer care; two silent turns. DO NOT CALL while the caller "
                        "is still speaking or mid-question.")

# Cloned from the live, hand-tuned Danube agent (GET /v1/convai/agents/agent_6201m3ak9v4sepv8c1vsed0z29rn,
# 2026-09-25) — turn-taking, ASR provider and interruption-ignore list are the owner's tuned baseline.
# ASR keywords swapped for IIJS Jewellers / gift-catalogue vocabulary.
ASR = {
    "quality": "high",
    "provider": "scribe_realtime",
    "user_input_audio_format": "pcm_16000",
    "keywords": ["IIJS Jewellers", "gold rate", "silver rate", "catalogue", "gift", "custom order",
                 "design consultant", "hallmark", "making charges", "diamond", "gemstone",
                 "bridal", "budget", "WhatsApp", "callback", "Jaipur"],
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
    boundary = "----voxdonnaIIJSJewellers"
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


def build_prompt_block(knowledge_base):
    return {
        "prompt": SYSTEM_PROMPT,
        "llm": LLM,
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        "knowledge_base": knowledge_base,
        "rag": {"enabled": False},  # KB ~1450 words, well under the stuffing-size threshold
        "tool_ids": [SEARCH_WEB_TOOL_ID],
        "built_in_tools": {
            "end_call": {"name": "end_call", "description": END_CALL_DESCRIPTION,
                         "type": "system", "params": {"system_tool_type": "end_call"}},
            "language_detection": {"name": "language_detection", "description": "",
                                   "type": "system", "response_timeout_secs": 20},
        },
    }


DATA_COLLECTION = {
    "caller_name": {"type": "string", "description": "The caller's first name as given or confirmed on the call. Empty if never given."},
    "callback_number": {"type": "string", "description": "The caller's phone number if stated and confirmed digit-by-digit on the call. Usually empty for a browser demo — do not invent one."},
    "language": {"type": "string", "description": "The primary language the caller spoke: hindi / hinglish / english / other."},
    "enquiry_type": {"type": "string", "description": "Comma-separated list of what the caller asked about this call: gold_rate, silver_rate, timings, catalogue_browse, gift_suggestion, custom_order, other."},
    "gift_occasion_or_recipient": {"type": "string", "description": "The occasion (birthday, anniversary, wedding, festival) or recipient relationship (mother, wife, friend) discussed for a gift suggestion. Empty if not discussed."},
    "budget_range": {"type": "string", "description": "The rough budget range the caller mentioned, in their own words. Empty if not discussed."},
    "custom_order_requested": {"type": "boolean", "description": "True only if the caller described a custom-design request on this call."},
    "custom_order_details": {"type": "string", "description": "Metal/karat, stones, budget and timeline the caller gave for a custom order. Empty if no custom order was discussed."},
    "gold_rate_quoted": {"type": "boolean", "description": "True only if the agent actually called the search_web tool and read back a gold or silver rate on this call."},
    "call_disposition": {"type": "string", "description": "Exactly one of: CUSTOM_ORDER_CAPTURED, GIFT_SUGGESTED, INFO_ONLY, ESCALATED_TO_CUSTOMER_CARE, OUT_OF_SCOPE_DECLINED, INCOMPLETE_CALL. Precedence: ESCALATED_TO_CUSTOMER_CARE wins if a fraud/complaint/legal topic came up; else CUSTOM_ORDER_CAPTURED if a custom-order brief was noted; else GIFT_SUGGESTED if a gift suggestion was given; else INFO_ONLY if questions (rate/timings/catalogue) were answered with no gift or custom-order discussion; else OUT_OF_SCOPE_DECLINED if the call was mostly an out-of-scope ask; else INCOMPLETE_CALL if it ended before any of the above could be determined."},
    "conversation_summary": {"type": "string", "description": "2-3 sentence neutral summary of the call: what the caller asked about and what was suggested or captured."},
}

EVALUATION_CRITERIA = [
    {"id": "no_fabricated_facts", "name": "No fabricated rate, price or address", "type": "prompt",
     "conversation_goal_prompt": "Did the agent avoid stating a gold or silver rate without having called the search_web tool first, avoid quoting an exact making-charge percentage, final price or custom-order quote, and avoid inventing a specific store address or phone number not in the knowledge base? Fail only on a genuine invented figure or address, not on directing the caller to the store locator."},
    {"id": "tool_used_for_rate", "name": "Called search_web before quoting a rate", "type": "prompt",
     "conversation_goal_prompt": "If the caller asked for today's gold or silver rate, did the agent call the search_web tool before answering, rather than answering directly from memory? PASS automatically if the caller never asked for a live rate."},
    {"id": "gift_or_custom_order_progressed", "name": "Worked toward a gift suggestion or custom-order capture", "type": "prompt",
     "conversation_goal_prompt": "If the caller asked about a gift, did the agent ask for the occasion/recipient AND a budget before suggesting something? If the caller described a custom order, did the agent ask for metal, budget and timeline? PASS if the caller never raised either topic, or if the agent clearly worked toward capturing the relevant details even after answering an unrelated question first."},
    {"id": "compliance", "name": "Compliance held", "type": "prompt",
     "conversation_goal_prompt": "Did the agent avoid collecting card/UPI/bank details, avoid claiming to be a real IIJS Jewellers employee, avoid claiming to have received a reference photo or design file, and avoid claiming a WhatsApp/SMS confirmation was sent (since no such tool exists on this demo)? Fail if any were violated."},
    {"id": "language_matched", "name": "Language and register matched the caller", "type": "prompt",
     "conversation_goal_prompt": "Did the agent reply in the same language the caller used, and did Hindi turns use natural spoken Hinglish (business terms in Roman English) rather than textbook/formal Hindi? The agent's own name 'Aisha' and 'IIJS Jewellers' are fixed proper nouns and are NOT language violations. Feminine first-person Hindi verb forms should be used throughout (verb forms only — the agent's own name is exempt)."},
    {"id": "ai_honesty_if_asked", "name": "Honest if asked whether it is AI", "type": "prompt",
     "conversation_goal_prompt": "If, and only if, the caller directly asked whether the agent is AI, a bot, or a recording, did the agent answer honestly in one short sentence rather than claiming to be human? PASS automatically if the caller never asked."},
    {"id": "one_question_per_turn", "name": "One question per turn, not an interrogation", "type": "prompt",
     "conversation_goal_prompt": "Did the agent ask at most one question per turn and answer an interruption or objection before returning to its own next question? Fail if the call felt like a checklist being read out."},
]


def build_platform_settings():
    return {
        "data_collection": DATA_COLLECTION,
        "evaluation": {"criteria": EVALUATION_CRITERIA},
    }


def create():
    kb_id = upload_kb()
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
                "expressive_mode": False,
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
        f.write(f"{AGENT_NAME}={agent_id}\n")
    print("Appended to scripts/agent-ids.txt")

    after = api("GET", f"/v1/convai/agents/{agent_id}")
    save_config(None, after)
    return agent_id


def update(agent_id):
    before = api("GET", f"/v1/convai/agents/{agent_id}")

    existing_kb = before["conversation_config"]["agent"]["prompt"].get("knowledge_base", [])
    reuse = [k for k in existing_kb if k.get("name") == KB_NAME]
    if reuse:
        knowledge_base = reuse
        print("Reusing existing KB doc id:", reuse[0]["id"])
    else:
        kb_id = upload_kb()
        knowledge_base = [{"type": "file", "name": KB_NAME, "id": kb_id, "usage_mode": "auto"}]

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
                "expressive_mode": False,
            },
        },
        "platform_settings": build_platform_settings(),
    }
    api("PATCH", f"/v1/convai/agents/{agent_id}", data=patch)
    after = api("GET", f"/v1/convai/agents/{agent_id}")
    save_config(before, after)
    print("Updated agent:", agent_id)
    return agent_id


def save_config(before, after):
    path = os.path.join(ROOT, "scripts", "iijs-jewellers-agent-config.json")
    doc = {"before": before, "after": after}
    with open(path, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    print("Saved before/after config to", path)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--update":
        update(sys.argv[2])
    else:
        create()
