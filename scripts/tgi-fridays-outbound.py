#!/usr/bin/env python3
"""Place outbound Bottomless Margaritas calls with the TGI Fridays agent (Neha).

Reads a leads CSV (columns: name,phone[,city]) and dials each via the ElevenLabs
SIP-trunk outbound endpoint, passing lead_name so the opener is personalised.

Safety:
  - DRY RUN by default. It prints the exact call payload and dials NOTHING.
    Add --live to actually place calls.
  - Refuses to dial outside an India calling window (default 10:00-20:00 IST).
    Honour NDNC/DND on your list BEFORE it reaches this script.

Usage:
  python3 scripts/tgi-fridays-outbound.py leads.csv            # dry run
  python3 scripts/tgi-fridays-outbound.py leads.csv --live     # real calls

leads.csv:
  name,phone,city
  Rahul,+919812345678,Mumbai
"""
import csv, json, os, sys, time, datetime, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_KEY = next((l.split("=", 1)[1].strip() for l in open(os.path.join(ROOT, ".env"))
                if l.startswith("ELEVENLABS_API_KEY=")), None)
if not API_KEY:
    sys.exit("ELEVENLABS_API_KEY missing in .env")

AGENT_ID = "agent_4901kws5vqwhfb7asfqrbk3wc5nt"
PHONE_NUMBER_ID = "phnum_1901krhczv3pfe9bzd2q85swkhxc"   # +917971441897 Vobiz SIP trunk
WINDOW_START, WINDOW_END = 10, 20                        # IST hours, inclusive-exclusive
IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))


def in_window():
    h = datetime.datetime.now(IST).hour
    return WINDOW_START <= h < WINDOW_END


def call(lead, live):
    body = {
        "agent_id": AGENT_ID,
        "agent_phone_number_id": PHONE_NUMBER_ID,
        "to_number": lead["phone"],
        "conversation_initiation_client_data": {
            "user_id": lead.get("id") or lead["phone"],
            # MUST nest inside conversation_initiation_client_data, not top-level.
            "dynamic_variables": {
                "lead_name": lead.get("name") or "जी",
                "lead_city": lead.get("city", ""),
            },
        },
        "telephony_call_config": {"ringing_timeout_secs": 30},
    }
    if not live:
        print("DRY  ", lead["phone"], "->", json.dumps(body["conversation_initiation_client_data"]["dynamic_variables"], ensure_ascii=False))
        return
    req = urllib.request.Request(
        "https://api.elevenlabs.io/v1/convai/sip-trunk/outbound-call",
        data=json.dumps(body).encode(),
        headers={"xi-api-key": API_KEY, "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            res = json.load(r)
        print("CALLED", lead["phone"], "conv:", res.get("conversation_id") or res.get("call_sid") or res)
    except urllib.error.HTTPError as e:
        print("FAIL  ", lead["phone"], e.code, e.read().decode()[:300])


def main():
    args = sys.argv[1:]
    live = "--live" in args
    paths = [a for a in args if not a.startswith("--")]
    if not paths:
        sys.exit("usage: tgi-fridays-outbound.py leads.csv [--live]")
    if live and not in_window() and "--force" not in args:
        sys.exit(f"Refusing to dial: outside {WINDOW_START}:00-{WINDOW_END}:00 IST window. Use --force for a test call.")
    with open(paths[0], newline="") as f:
        leads = list(csv.DictReader(f))
    print(f"{'LIVE' if live else 'DRY RUN'} — {len(leads)} leads, agent {AGENT_ID}")
    for lead in leads:
        if not lead.get("phone"):
            continue
        call(lead, live)
        if live:
            time.sleep(2)   # gentle pacing; raise if you hit concurrency limits


if __name__ == "__main__":
    main()
