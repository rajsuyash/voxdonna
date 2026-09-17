"""Apply the shared human-voice layer to an Emerald/TCG ElevenLabs agent.

Replaces the agent's *voice* layer (register, turn size, fillers, markup rules,
honorifics, examples) and leaves its business logic untouched. Config is ported
from the Tanishq Aanya agent, which is the reference for how a human one sounds.
"""
import json, sys, urllib.request, pathlib

KEY = sys.argv[1]
ONLY = sys.argv[2] if len(sys.argv) > 2 else None
HERE = pathlib.Path("scripts/voice-human-layer")
SHARED = (HERE / "shared.txt").read_text(encoding="utf-8")

# Backchannels the agent must not treat as an interruption (ported from Tanishq).
IGNORE = ['हम्म','हाँ','हां','अच्छा','जी','ओके','ठीक है','सही है','उम्म',
          'hmm','ok','okay','haan','accha','ji','mm','uh huh','right','yes yes']

TOP_RULE = """# \u0938\u092c\u0938\u0947 \u091c\u093c\u0930\u0942\u0930\u0940 \u0928\u093f\u092f\u092e \u2014 \u0939\u0930 \u090f\u0915 turn \u092a\u0930 \u0932\u093e\u0917\u0942
1. \u0939\u0930 \u091c\u0935\u093e\u092c \u0938\u093f\u0930\u094d\u092f\u093c \u090f\u0915 \u092f\u093e \u0926\u094b \u0935\u093e\u0915\u094d\u092f \u0915\u093e, \u092e\u093f\u0932\u093e\u0915\u0930 \u092a\u0948\u0902\u0924\u0940\u0938 \u0936\u092c\u094d\u0926 \u0938\u0947 \u0915\u092e\u0964 \u0924\u0940\u0938\u0930\u093e \u0935\u093e\u0915\u094d\u092f \u0915\u092d\u0940 \u0928\u0939\u0940\u0902\u0964
2. \u090f\u0915 turn \u092e\u0947\u0902 \u090f\u0915 \u0939\u0940 \u0938\u0935\u093e\u0932, \u0914\u0930 turn \u0909\u0938\u0940 \u0938\u0935\u093e\u0932 \u092a\u0930 \u0916\u093c\u0924\u094d\u092e\u0964
3. Square bracket, asterisk, emoji, stage direction \u2014 \u0915\u0941\u091b \u092d\u0940 \u0928\u0939\u0940\u0902\u0964
4. \u0905\u092a\u0928\u0940 \u0939\u0940 \u0915\u0939\u0940 \u0939\u0941\u0908 \u092c\u093e\u0924 \u0926\u094b\u092c\u093e\u0930\u093e \u0928\u0939\u0940\u0902\u0964
5. Devanagari \u092e\u0947\u0902 Hindi, Roman \u092e\u0947\u0902 English \u2014 \u090f\u0915 \u0939\u0940 \u0935\u093e\u0915\u094d\u092f \u092e\u0947\u0902\u0964
\u0928\u0940\u091a\u0947 \u0938\u092c \u0915\u0941\u091b \u0907\u0928\u0939\u0940\u0902 \u092a\u093e\u0901\u091a \u0928\u093f\u092f\u092e\u094b\u0902 \u0915\u0947 \u0905\u0902\u0926\u0930 \u0930\u0939\u0915\u0930 \u0915\u0930\u0928\u093e \u0939\u0948\u0964

"""

SYS_TOOL = lambda n, desc="": {"name": n, "description": desc, "type": "system",
                               "params": {"system_tool_type": n}}

TCG_EXTRA = """

# HARD STOPS — call end_call at once
- The visit slot or the callback time is agreed and you have recapped it once.
- The caller says goodbye, or asks not to be called again. Apologise once, confirm removal, end.
- The caller says they are busy — offer a callback time, then end in one line.
- The caller asks for a human — confirm the callback number, say the Relationship Manager will call within the next business hour, end.
- The caller is annoyed or distressed — apologise briefly, end.
- Two silent turns, or the call passes about two minutes.
Always call the end_call tool to hang up. Saying goodbye without calling the tool leaves the caller on a dead line. Never end while they are asking a question.
"""

AGENTS = {
"iijs-partner-invite": dict(
  id="agent_9201m1s65xfvfeq9vmt4zj3zxs9v", cut="# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550 \u092c\u094b\u0932\u0928\u0947 \u0915\u093e \u0924\u0930\u0940\u0915\u093e", extra="",
  persona="\u0906\u092a Emerald \u0915\u0940 sales team \u0915\u0940 coordinator Kavya \u0939\u0948\u0902: warm, \u0938\u0932\u0940\u0915\u0947 \u0935\u093e\u0932\u0940, \u0914\u0930 relaxed \u2014 telecaller \u091c\u0948\u0938\u0940 \u0928\u0939\u0940\u0902\u0964 \u092f\u0947 partners \u0938\u093e\u0932\u094b\u0902 \u0938\u0947 Emerald \u0915\u0947 \u0938\u093e\u0925 \u0915\u093e\u092e \u0915\u0930 \u0930\u0939\u0947 \u0939\u0948\u0902\u0964",
  nouns="show, stall, hall, badge, registration, collection, catalogue, design, sample, counter, order, delivery, discount, offer, terms, travel, booking",
  roman_ok="show, stall, badge, collection, catalogue, registration, team, design, WhatsApp",
  roman_bad="\u0936\u094b, \u0938\u094d\u091f\u0949\u0932, \u092c\u0948\u091c, \u0915\u0932\u0947\u0915\u094d\u0936\u0928, \u0915\u0948\u091f\u0932\u0949\u0917, \u0930\u091c\u093f\u0938\u094d\u091f\u094d\u0930\u0947\u0936\u0928, \u091f\u0940\u092e, \u0921\u093f\u091c\u093c\u093e\u0907\u0928, \u0935\u094d\u0939\u093e\u091f\u094d\u0938\u090f\u092a",
  extra_langs="Tamil replies get Tamil script. ",
  hi="\u0928\u092e\u0938\u094d\u0924\u0947 \u091c\u0940, \u092e\u0948\u0902 \u0915\u093e\u0935\u094d\u092f\u093e \u092c\u094b\u0932 \u0930\u0939\u0940 \u0939\u0942\u0901 Emerald Jewel \u0938\u0947\u0964 \u0905\u0917\u0932\u0947 \u092e\u0939\u0940\u0928\u0947 Mumbai \u092e\u0947\u0902 IIJS \u0939\u0948, \u0914\u0930 \u0906\u092a\u0915\u094b \u0939\u092e\u093e\u0930\u0947 stall \u092a\u0930 invite \u0915\u0930\u0928\u093e \u0925\u093e \u2014 \u090f\u0915 \u092e\u093f\u0928\u091f \u092c\u093e\u0924 \u0915\u0930 \u0938\u0915\u0924\u0947 \u0939\u0948\u0902?",
  en="Hello, Kavya here from Emerald Jewel. We have our stall at IIJS in Mumbai next month, and I wanted to invite you \u2014 do you have a minute?",
  keep_ta=True, add_tools=False, legacy="scripts/emerald-iijs-system-prompt.txt"),
"collection-outreach": dict(
  id="agent_2701m1s69m06fwjbhqbhg8eh0tc4", cut="# HINGLISH RULE", extra="",
  persona="आप Emerald की product team की Meera हैं: warm, सलीके वाली, और product की बात करने वाली — closer नहीं। ये partners सालों से Emerald के साथ काम कर रहे हैं, तो आवाज़ में वही अपनापन हो।",
  nouns="collection, design, sample, catalogue, counter, order, delivery, stock, video walkthrough, appointment, showroom, lightweight, bridal, festive",
  roman_ok="collection, catalogue, design, sample, counter, appointment, video walkthrough, WhatsApp",
  roman_bad="कलेक्शन, कैटलॉग, डिज़ाइन, सैंपल, काउंटर, अपॉइंटमेंट, वीडियो वॉकथ्रू, व्हाट्सएप",
  extra_langs="Tamil replies get Tamil script. ",
  hi="नमस्ते जी, मैं मीरा बोल रही हूँ Emerald Jewel की product team से। हमारी नई lightweight bridal collection आई है, Aadhira, और festive season से पहले वो आपको दिखानी थी, एक मिनट बात कर सकते हैं?",
  en="Hello, Meera here from the product team at Emerald Jewel. We have just finished a new lightweight bridal collection called Aadhira, and I wanted to show it to you before the festive season — do you have a minute?",
  keep_ta=True, add_tools=False, legacy="scripts/emerald-collection-system-prompt.txt"),

"payment-reminder": dict(
  id="agent_5401m1s5r16zern8ptvra9h82n09", cut="# HINGLISH RULE",
  extra="",
  persona="आप Emerald की accounts team की Aarthi हैं: शांत, सलीके वाली और मददगार। ये partner हैं, defaulter नहीं — आवाज़ में कभी दबाव, ताना या शिकायत नहीं।",
  nouns="payment, balance, invoice, statement, account, credit period, due date, cheque, RTGS, NEFT, UPI, UTR, clear",
  roman_ok="payment, invoice, statement, account, balance, credit period, clear, cheque, UTR, WhatsApp",
  roman_bad="पेमेंट, इनवॉइस, स्टेटमेंट, अकाउंट, बैलेंस, क्रेडिट पीरियड, क्लियर, चेक, व्हाट्सएप",
  extra_langs="Tamil replies get Tamil script. ",
  hi="नमस्ते जी, मैं आरती बोल रही हूँ Emerald Jewel की accounts team से। आपके account पर कुछ payment pending है, बस वही याद दिलानी थी, एक मिनट से ज़्यादा नहीं लूँगी।",
  en="Hello, Aarthi here from the accounts team at Emerald Jewel. There is a payment pending on your account and I just wanted to check on it — it will take under a minute.",
  keep_ta=True, add_tools=False, legacy="scripts/emerald-system-prompt.txt"),

"tcg-real-estate": dict(
  id="agent_3001kt4eayypfzhs0zpfna0a710z",
  cut="LANGUAGE: Default to natural Indian English.", cut_to="CONNECTIVITY CHEAT SHEET",
  extra=TCG_EXTRA,
  persona="आप TCG Real Estate की pre-sales executive Aanya हैं: warm, confident, अच्छी inside-sales वाली — न ज़रूरत से ज़्यादा मीठी, न robotic। छोटे turns, एक बार में एक सवाल।",
  nouns="project, site visit, sample flat, experience centre, carpet area, configuration, BHK, possession, brochure, floor plan, budget, home loan, EMI, RERA, IT park, phase, Relationship Manager, RM, lakh, crore",
  roman_ok="site visit, carpet area, configuration, BHK, possession, brochure, floor plan, budget, RERA, IT park, WhatsApp",
  roman_bad="साइट विज़िट, कार्पेट एरिया, कॉन्फ़िगरेशन, बीएचके, पजेशन, ब्रोशर, फ्लोर प्लान, बजट, व्हाट्सएप",
  extra_langs="Marathi replies get Devanagari Marathi with the same English terms kept in Roman. ",
  hi="नमस्ते जी, मैं आन्या बोल रही हूँ TCG Real Estate से। Hinjewadi में The Cliff Garden के लिए आपने enquiry की थी, उसी के बारे में दो मिनट बात करनी थी, अभी ठीक रहेगा?",
  en="Hi, this is Aanya from TCG Real Estate about your enquiry for The Cliff Garden in Hinjewadi, Pune. Is this a good time to talk for two minutes?",
  keep_ta=False, add_tools=True, legacy="scripts/tcg-system-prompt.txt"),
}

def api(method, path, body=None):
    req = urllib.request.Request("https://api.elevenlabs.io/v1/convai" + path,
        data=json.dumps(body).encode() if body else None, method=method,
        headers={"xi-api-key": KEY, "Content-Type": "application/json"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=90).read() or "{}")
    except urllib.error.HTTPError as e:
        print("   HTTP", e.code, e.read().decode()[:500]); raise

for slug, a in AGENTS.items():
    if ONLY and ONLY != slug:
        continue
    print(f"== {slug} ({a['id']})")
    cur = api("GET", f"/agents/{a['id']}")
    cc = cur["conversation_config"]; p = cc["agent"]["prompt"]
    old = p["prompt"]

    BANNER = "# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550 \u092c\u094b\u0932\u0928\u0947 \u0915\u093e \u0924\u0930\u0940\u0915\u093e"
    i = old.find(BANNER)                      # re-apply: cut the layer we added last time
    first_apply = i < 0
    if first_apply: i = old.find(a["cut"])     # first apply: cut the agent's original voice block
    assert i > 0, f"cut marker not found in {slug}"
    # cut_to only applies on the first pass; on a re-apply that block is already gone
    if first_apply and a.get("cut_to"):
        j = old.find(a["cut_to"]); assert j > i, "cut_to not found"
        business = old[:i] + old[j:]
    else:
        business = old[:i]

    layer = (SHARED.replace("__PERSONA__", a["persona"])
                   .replace("__DOMAIN_NOUNS__", a["nouns"])
                   .replace("__ROMAN_OK__", a["roman_ok"])
                   .replace("__ROMAN_BAD__", a["roman_bad"])
                   .replace("__EXTRA_LANGS__", a["extra_langs"])
                   .replace("__EXAMPLES__", (HERE / f"examples-{slug}.txt").read_text(encoding="utf-8").strip()))
    if TOP_RULE.strip() in business: business = business.replace(TOP_RULE, "")
    new_prompt = TOP_RULE + business.rstrip() + "\n" + layer + a["extra"]
    assert len(new_prompt) > len(old) * 0.75, (
        f"{slug}: spliced prompt is {len(new_prompt)} chars vs {len(old)} before — "
        "the business logic was probably cut. Refusing to PATCH.")
    (HERE / f"built-{slug}.txt").write_text(new_prompt, encoding="utf-8")
    # Keep the legacy prompt file the create-* script reads in sync, or re-running that
    # script silently recreates the agent with the pre-humanisation prompt.
    if a.get("legacy"):
        pathlib.Path(a["legacy"]).write_text(new_prompt, encoding="utf-8")
    print(f"   prompt {len(old)} -> {len(new_prompt)} chars")

    presets = {"en": {"overrides": {"agent": {"first_message": a["en"]}}}}
    if a["keep_ta"]:
        presets["ta"] = {"overrides": {"agent": {"first_message":
            cc["language_presets"]["ta"]["overrides"]["agent"]["first_message"]}}}

    # model_id must ride with `language` or the validator revalidates against eleven_flash_v2
    api("PATCH", f"/agents/{a['id']}", {"conversation_config": {
        # expressive_mode defaults true on v3 and makes the model write bracket
        # tags of its own. The prompt forbids them too — neither defence holds alone.
        "tts": {"model_id": cc["tts"]["model_id"], "voice_id": cc["tts"]["voice_id"],
                "stability": 0.2, "similarity_boost": 0.75, "speed": 1.05,
                "expressive_mode": False},
        "agent": {"language": "hi", "first_message": a["hi"]},
        "language_presets": presets,
        "turn": {"turn_timeout": 7.0, "turn_eagerness": "eager",
                 "interruption_ignore_terms": IGNORE,
                 "interruption_ignore_term_languages": ["hi", "en"],
                 "merge_with_default_ignore_terms": True}}})
    print("   PATCH tts+turn+language: ok")

    bt = {k: v for k, v in (p.get("built_in_tools") or {}).items() if v}
    if a["add_tools"]:
        bt.setdefault("end_call", SYS_TOOL("end_call",
            "Ends the call after your closing line finishes playing. Call it once the visit slot or callback is agreed and recapped, or on any HARD STOP in the system prompt. Never call it while the caller is speaking or asking a question."))
        bt.setdefault("language_detection", SYS_TOOL("language_detection"))
    api("PATCH", f"/agents/{a['id']}", {"conversation_config": {"agent": {"prompt": {
        "prompt": new_prompt, "llm": "gemini-2.0-flash", "temperature": 0.4, "max_tokens": 320,
        "knowledge_base": p["knowledge_base"], "built_in_tools": bt, "tool_ids": []}}}})
    print("   PATCH prompt+llm+tools: ok |", sorted(bt))
