#!/usr/bin/env python3
"""Assert a ConvAI agent emits no gendered vocative and no bracket markup.

The agent has no gender signal on an inbound call, so any gendered address
form is a guess. This runs simulated conversations and counts those forms in
the AGENT's turns only.

A zero from a checker that cannot detect the defect is worthless, so the run
starts with a positive control: the same checker is pointed at a clone of the
agent still carrying the pre-fix prompt. If the control does not flag, the
run aborts instead of reporting a pass.

Usage:
  python3 scripts/check-honorific-neutrality.py                  # agent + control
  python3 scripts/check-honorific-neutrality.py --no-control     # agent only
  python3 scripts/check-honorific-neutrality.py --control-prompt FILE
"""
import argparse, json, os, re, sys, urllib.error, urllib.request

API = "https://api.elevenlabs.io/v1/convai"
AGENT_ID = "agent_4001m2n3ar96fy0t0fp1kb5vbx08"
CONTROL_PROMPT = "/tmp/tamil-prompt.bak"

# simulate-conversation splits words with stray spaces (observed in both Tamil
# and Hindi output), so every needle below tolerates whitespace between its
# characters. Do NOT solve that by stripping all whitespace instead: that
# destroys the only word boundary Devanagari has, and \b cannot replace it
# because Python's \w excludes combining vowel signs — \bसर\b matches inside
# तीसरा. Guard on the Devanagari block itself.
DEV = "\u0900-\u097F\u200c\u200d"


def _loose(word):
    """Match `word` even when the transcript has spaces inside it."""
    return r"\s*".join(map(re.escape, word))


TAMIL = [("சார்", re.compile(_loose("சார்") + r"(?!\s*ந)")),   # not சார்ந்த
         ("மேடம்", re.compile(_loose("மேடம்")))]
# "जी" is deliberately absent from HINDI — it is gender-neutral and the prompts
# prescribe it.
HINDI = [("सर", re.compile(f"(?<![{DEV}])" + _loose("सर") + f"(?![{DEV}])")),
         ("मैडम", re.compile(f"(?<![{DEV}])" + _loose("मैडम") + f"(?![{DEV}])")),
         ("महोदय", re.compile(f"(?<![{DEV}])" + _loose("महोदय") + f"ा?(?![{DEV}])"))]
ENGLISH = [("sir", re.compile(r"\bsirs?\b", re.I)),
           ("madam", re.compile(r"\bmadams?\b", re.I))]

# Any bracket markup is a defect: the prompts forbid it and the agents that
# had expressive_mode on have had it turned off, so a tag here means one of
# the two defences has stopped holding.
TAG = re.compile(r"\[([^\]]{1,20})\]")

HI_PERSONAS = [
    ("hindi-female-named",
     "You are Sunita Agarwal, a woman who runs a jewellery retail shop in "
     "Jaipur. Speak Hindi. Say your name early. You are interested but "
     "cautious about time. Answer briefly, one short sentence per turn."),
    ("hindi-unnamed",
     "You are a shop owner taking a cold call. Speak Hindi. Never give your "
     "name. Ask one practical question, then decide. Answer briefly, one "
     "short sentence per turn."),
    ("hindi-female-busy",
     "You are Rekha, a woman running a busy showroom. Speak Hindi. You are "
     "distracted and want the call short. Say your name once. Answer in a "
     "few words per turn."),
]

PERSONAS = [
    ("tamil-female-named",
     "You are Priya, a 34-year-old woman in Coimbatore calling a jewellery "
     "shop. Speak Tamil. Say your name is பிரியா early. You want jewellery for "
     "your sister's wedding, budget around one lakh. Answer briefly and "
     "naturally, one short sentence per turn."),
    ("tamil-female-unnamed",
     "You are a woman in Chennai calling a jewellery shop. Speak Tamil. Never "
     "give your name. You want something light for daily wear. Answer briefly, "
     "one short sentence per turn."),
    ("tamil-male-named",
     "You are Ramesh, a man in Madurai calling a jewellery shop. Speak Tamil. "
     "Say your name is ரமேஷ் early. You want an anniversary gift for your "
     "wife. Answer briefly, one short sentence per turn."),
    ("tamil-terse-unnamed",
     "You are calling a jewellery shop and are in a hurry. Speak Tamil. Never "
     "give your name or any personal detail. Answer in two or three words per "
     "turn. You want a gift for a friend."),
    ("english-female",
     "You are Anitha, a woman in Bangalore calling a jewellery shop. Speak "
     "English from your very first message and stay in English. You want "
     "bridal jewellery. Answer briefly, one short sentence per turn."),
]


def call(key, path, body=None, method="GET"):
    req = urllib.request.Request(
        f"{API}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"xi-api-key": key, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        if method != "GET":
            sys.stderr.write(f"HTTP {e.code} on {method} {path}: {e.read().decode()[:500]}\n")
        raise
    return json.loads(raw) if raw else {}


def simulate(key, agent_id, persona_prompt):
    body = {"simulation_specification": {
        "simulated_user_config": {"prompt": {"prompt": persona_prompt}}}}
    res = call(key, f"/agents/{agent_id}/simulate-conversation", body, "POST")
    return res.get("simulated_conversation") or []


def agent_turns(convo):
    return [t.get("message") or "" for t in convo if t.get("role") == "agent"]


def scan(turns):
    """Return (token, turn_index, excerpt) for every gendered vocative."""
    hits = []
    for i, turn in enumerate(turns):
        for name, pat in TAMIL + HINDI + ENGLISH:
            for _ in pat.finditer(turn):
                hits.append((name, i, turn.strip()[:100]))
    return hits


def self_test():
    """The patterns must fire on the defect as it actually reaches a
    transcript — including the split-word form the simulator produces — and
    must stay silent on the many words that merely contain those letters."""
    defects = [
        "வணக்கம் சார், நான் ஆன்யா",
        "வ ண க் க ம்  சா ர் , நா ன்",          # simulator split-word form
        "சரி மேடம், நன்றி",
        "नमस्ते सर, मैं काव्या बोल रही हूँ",
        "न म स् ते  स र ,",                     # split-word form
        "जी सर बिल्कुल",
        "Thank you सर",
        "मैडम, आपका account",
        "Sure sir — is this for a wedding?",
        "Thank you, Madam.",
    ]
    clean = [
        "வணக்கம், நான் ஆன்யா, ஜாயலுக்காஸ்-ல இருந்து",
        "ஊர் சார்ந்த slang வேண்டாம்",            # சார்ந்த is a different word
        "ரமேஷ் அவர்கள், Saturday showroom-ல பாக்கலாம்",
        "Sure — is this for a wedding?",
        "जी बिल्कुल, मैं अभी भेज देती हूँ",        # जी is neutral
        "तीसरा वाक्य कभी नहीं",                  # सर inside तीसरा
        "सिर्फ़ सरकारी काम है",
        "इसका कोई असर नहीं",
        "दूसरा option भी है",
    ]
    for c in defects:
        assert scan([c]), f"checker missed a known defect: {c!r}"
    for c in clean:
        assert not scan([c]), f"checker false-positived on: {c!r} -> {scan([c])}"
    print(f"  self-test: {len(defects)} defect forms flagged, {len(clean)} clean forms silent")


def tag_report(turns):
    per_turn = [TAG.findall(t) for t in turns]
    total = sum(len(x) for x in per_turn)
    return total, sorted({t for x in per_turn for t in x})


def run_agent(key, agent_id, label, dump=None, personas=None):
    """-> (gendered vocatives, bracket tags, failing persona names).

    The two counts stay separate on purpose: the positive-control gate asks
    whether the checker detects VOCATIVES, and a control that emitted only
    bracket tags would satisfy a combined total while proving nothing.
    """
    n_voc, n_tag, failures = 0, 0, []
    for name, persona in (personas or PERSONAS):
        convo = simulate(key, agent_id, persona)
        turns = agent_turns(convo)
        if dump:
            with open(os.path.join(dump, f"{label}-{name}.json"), "w", encoding="utf-8") as fh:
                json.dump(convo, fh, ensure_ascii=False, indent=1)
        n_tags, vocab = tag_report(turns)
        hits = scan(turns)
        n_voc += len(hits)
        n_tag += n_tags
        mark = "FAIL" if (hits or n_tags) else "ok  "
        print(f"  [{mark}] {label}/{name}: {len(turns)} agent turns, "
              f"{len(hits)} gendered vocatives, {n_tags} bracket tags")
        for tok, i, ex in hits[:3]:
            print(f"         turn {i}: {tok} — {ex}")
        if n_tags:
            print(f"         bracket markup: {vocab}")
        if hits or n_tags:
            failures.append(name)
    return n_voc, n_tag, failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", default=AGENT_ID)
    ap.add_argument("--control-prompt", default=CONTROL_PROMPT)
    ap.add_argument("--no-control", action="store_true")
    ap.add_argument("--dump", metavar="DIR", help="save every transcript as JSON")
    ap.add_argument("--personas", choices=("ta", "hi"), default="ta")
    args = ap.parse_args()
    personas = HI_PERSONAS if args.personas == "hi" else PERSONAS
    if args.dump:
        os.makedirs(args.dump, exist_ok=True)

    key = os.environ.get("ELEVENLABS_API_KEY")
    if not key:
        for line in open(".env", encoding="utf-8"):
            if line.startswith("ELEVENLABS_API_KEY"):
                key = line.split("=", 1)[1].strip().strip("\"'")
    if not key:
        sys.exit("ELEVENLABS_API_KEY not found in env or .env")

    print("Checker self-test on fixed strings:")
    self_test()

    control_id = None
    try:
        if not args.no_control:
            if not os.path.exists(args.control_prompt):
                sys.exit(f"positive control needs the pre-fix prompt at {args.control_prompt}")
            print("\nPositive control — clone carrying the PRE-FIX prompt:")
            src = call(key, f"/agents/{args.agent}")
            cfg = src["conversation_config"]
            cfg["agent"]["prompt"]["prompt"] = open(args.control_prompt, encoding="utf-8").read()
            # /agents/create rejects `tools` and `tool_ids` together; the clone
            # only has to talk, so keep the ids and drop the inline copies.
            cfg["agent"]["prompt"].pop("tools", None)
            created = call(key, "/agents/create", {
                "name": "ZZ-TEMP honorific positive control (delete me)",
                "conversation_config": cfg}, "POST")
            control_id = created["agent_id"]
            print(f"  created {control_id}")
            c_voc, _, _ = run_agent(key, control_id, "control", args.dump, personas)
            if c_voc == 0:
                sys.exit("\nABORT: the control agent produced zero gendered vocatives.\n"
                         "The checker cannot detect the defect it is meant to catch, so a\n"
                         "clean result from the real agent would prove nothing.")
            print(f"  control flagged {c_voc} gendered vocatives — checker detects the defect")

        print(f"\nAgent under test ({args.agent}):")
        n_voc, n_tag, failures = run_agent(key, args.agent, "fixed", args.dump, personas)
    finally:
        if control_id:
            call(key, f"/agents/{control_id}", method="DELETE")
            try:
                call(key, f"/agents/{control_id}")
                print(f"\nWARNING: control agent {control_id} still exists — delete it manually")
            except urllib.error.HTTPError as e:
                if e.code in (401, 404):
                    print(f"\ncleanup: control agent {control_id} deleted (GET -> {e.code})")
                else:
                    raise

    print()
    if n_voc or n_tag:
        print(f"FAIL: {n_voc} gendered vocatives, {n_tag} bracket tags "
              f"across {len(failures)} personas: {', '.join(failures)}")
        sys.exit(1)
    print(f"PASS: 0 gendered vocatives, 0 bracket tags across {len(personas)} personas")


if __name__ == "__main__":
    main()
