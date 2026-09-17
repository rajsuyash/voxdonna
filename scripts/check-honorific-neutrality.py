#!/usr/bin/env python3
"""Assert a ConvAI agent never uses a gendered vocative (sir/madam/சார்/மேடம்).

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

# Tamil is matched after stripping ALL whitespace: simulate-conversation joins
# streamed tokens with spaces, which splits Indic graphemes mid-word and would
# otherwise hide every match. சார்(?!ந) skips சார்ந்த ("related to"), a
# different word that shares the prefix.
TAMIL = [("சார்", re.compile(r"சார்(?!ந)")), ("மேடம்", re.compile(r"மேடம்"))]
ENGLISH = [("sir", re.compile(r"\bsirs?\b", re.I)), ("madam", re.compile(r"\bmadams?\b", re.I))]

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
    """Return list of (token, turn_index, excerpt) for every gendered vocative."""
    hits = []
    for i, turn in enumerate(turns):
        squashed = re.sub(r"\s+", "", turn)
        for name, pat in TAMIL:
            for _ in pat.finditer(squashed):
                hits.append((name, i, turn.strip()[:100]))
        for name, pat in ENGLISH:
            for _ in pat.finditer(turn):
                hits.append((name, i, turn.strip()[:100]))
    return hits


def self_test():
    """The regexes must fire on the defect as it actually appears in a
    transcript, including the space-mangled form."""
    cases = [
        "வணக்கம் சார், நான் ஆன்யா",
        "வ ண க் க ம்  சா ர் , நா ன்",          # token-joined form
        "சரி மேடம், நன்றி",
        "Sure sir — is this for a wedding?",
        "Thank you, Madam.",
    ]
    for c in cases:
        assert scan([c]), f"checker missed a known defect: {c!r}"
    clean = ["வணக்கம், நான் ஆன்யா, ஜாயலுக்காஸ்-ல இருந்து",
             "ஊர் சார்ந்த slang வேண்டாம்",       # சார்ந்த must NOT match
             "ரமேஷ் அவர்கள், Saturday showroom-ல பாக்கலாம்",
             "Sure — is this for a wedding?"]
    for c in clean:
        assert not scan([c]), f"checker false-positived on: {c!r}"
    print("  self-test: regexes fire on 5 defect forms, silent on 4 clean forms")


def run_agent(key, agent_id, label):
    total, failures = 0, []
    for name, persona in PERSONAS:
        turns = agent_turns(simulate(key, agent_id, persona))
        hits = scan(turns)
        total += len(hits)
        mark = "FAIL" if hits else "ok  "
        print(f"  [{mark}] {label}/{name}: {len(turns)} agent turns, {len(hits)} gendered vocatives")
        for tok, i, ex in hits[:3]:
            print(f"         turn {i}: {tok} — {ex}")
        if hits:
            failures.append(name)
    return total, failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", default=AGENT_ID)
    ap.add_argument("--control-prompt", default=CONTROL_PROMPT)
    ap.add_argument("--no-control", action="store_true")
    args = ap.parse_args()

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
            c_total, _ = run_agent(key, control_id, "control")
            if c_total == 0:
                sys.exit("\nABORT: the control agent produced zero gendered vocatives.\n"
                         "The checker cannot detect the defect it is meant to catch, so a\n"
                         "clean result from the real agent would prove nothing.")
            print(f"  control flagged {c_total} vocatives — checker detects the defect")

        print(f"\nAgent under test ({args.agent}):")
        total, failures = run_agent(key, args.agent, "fixed")
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
    if total:
        print(f"FAIL: {total} gendered vocatives across {len(failures)} personas: {', '.join(failures)}")
        sys.exit(1)
    print(f"PASS: 0 gendered vocatives across {len(PERSONAS)} personas")


if __name__ == "__main__":
    main()
