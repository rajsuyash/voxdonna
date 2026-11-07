#!/usr/bin/env python3
"""Build assets/automation-plan/industries.json.

Usage: build-automation-plan-data.py <research.xlsx> [out.json]

Outputs: the planner data file and oracle-relay/planner-industries.json (ids + names).

Inputs: the research workbook (read-only, path given on argv, never stored in
the repo), oracle-relay/industry-library.json, and the hand-written
scripts/automation-plan-overrides.json. From the workbook only these columns
are read: ID, Group, Industry, Opportunity Type, Primary Channel(s), Ease,
Weighted Score. Benchmark, evidence and source columns are never read.
"""
import json
import sys
from pathlib import Path

import openpyxl

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "oracle-relay" / "industry-library.json"
OVR = Path(__file__).resolve().parent / "automation-plan-overrides.json"
BASE = "https://voxdonna.com/"
MENU = ["jewellery-retail", "jewellery-manufacturing", "sap-manufacturing", "real-estate",
        "rooftop-solar", "kitchen-appliances", "luxury-furniture"]
CHANNELS = {"voice": "voice", "whatsapp": "whatsapp", "email": "email", "sms": "sms", "web": "web"}
TYPES = {"Revenue-generating": "revenue", "Operational": "cost", "Cost-saving": "cost",
         "Customer-experience": "experience"}
EFFORT = {5: "days", 4: "2-4 weeks", 3: "2-4 weeks", 2: "1-2 months", 1: "1-2 months"}


def channels(raw):
    s = raw.lower()
    if "multichannel" in s:
        return ["voice", "whatsapp", "email", "chat"]
    out = []
    for token in s.replace("/", "+").split("+"):
        c = CHANNELS[token.strip()]
        if c not in out:
            out.append(c)
    return out


def page_url(ovr, row_id, chans):
    name = ovr["pages"].get(row_id)
    if not name:
        name = next((ovr["page_defaults"][c] for c in ("voice", "whatsapp") if c in chans), None)
    if not name:
        return None
    if not (ROOT / name).is_file():
        sys.exit(f"missing page {name} for {row_id}")
    return BASE + name


def load_rows(xlsx):
    ws = openpyxl.load_workbook(xlsx, data_only=True)["Opportunity Database"]
    rows = []
    for r in ws.iter_rows(min_row=5):
        v = [c.value for c in r][1:21]
        if v[0]:
            rows.append({"id": v[0], "group": v[1], "industry": v[2], "type": v[5],
                         "channels": v[6], "ease": v[13], "score": v[14]})
    return rows


def research_auto(ovr, key, row, auto_id):
    o = ovr["rows"][key]
    chans = channels(row["channels"])
    score = int(row["score"])
    assert score == row["score"] and 0 <= score <= 100, row["id"]
    return {"id": auto_id, "title": o["title"], "what_it_does": o["what_it_does"],
            "channels": chans, "pains": o["pains"], "type": TYPES[row["type"]],
            "effort": EFFORT[row["ease"]], "first_step": o["first_step"], "score": score,
            "page_url": page_url(ovr, row["id"], chans), "source": "research"}


def by_score(autos):
    return sorted(autos, key=lambda a: (-a["score"], a["id"]))


def main():
    xlsx = sys.argv[1]
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "assets" / "automation-plan" / "industries.json"
    lib = json.loads(LIB.read_text())
    ovr = json.loads(OVR.read_text())
    rows = load_rows(xlsx)
    assert len(rows) > 0
    used = set()

    featured = {}
    for ind in lib["industries"]:
        autos = []
        for rank, a in enumerate(ind["automations"], start=1):
            # "proposed" entries were approved by the owner for the planner; page-live or not, they ship as source "site".
            if a["status"] not in ("on_site", "proposed"):
                continue
            f = ovr["featured"][a["id"]]
            used.add(a["id"])
            autos.append({"id": a["id"], "title": a["title"], "what_it_does": a["what_it_does"],
                          "channels": f["channels"], "pains": a["pains"], "type": f["type"],
                          "effort": a["effort"], "first_step": a["first_step"],
                          "score": 95 - 3 * (rank - 1), "page_url": a["page_url"], "source": "site"})
        featured[ind["id"]] = {"id": ind["id"], "name": ind["name"], "group": ovr["featured_groups"][ind["id"]],
                               "featured": True, "page_url": ind["page_url"], "volume_unit": ind["volume_unit"],
                               "pains": ind["pains"], "automations": autos}
    assert list(featured) == MENU, list(featured)

    standalone = {}
    for row in rows:
        m = ovr["merges"].get(row["id"], {})
        action, into = m.get("action"), m.get("into")
        if row["industry"] in ovr["subsumed"]:
            assert action in ("drop", "add"), row["id"]
            if action == "add":
                key = f"{row['id']}@{into}"
                used.add(key)
                featured[into]["automations"].append(research_auto(ovr, key, row, row["id"].lower()))
            continue
        used.add(row["id"])
        if action == "copy":
            key = f"{row['id']}@{into}"
            used.add(key)
            featured[into]["automations"].append(research_auto(ovr, key, row, f"{row['id'].lower()}-{into}"))
        d = ovr["industries"][row["industry"]]
        ind = standalone.setdefault(row["industry"], {
            "id": d["id"], "name": d["name"], "group": row["group"], "featured": False,
            "page_url": BASE + ovr["industry_pages"][row["industry"]] if row["industry"] in ovr["industry_pages"] else None,
            "volume_unit": d["volume_unit"], "pains": d["pains"], "automations": []})
        ind["automations"].append(research_auto(ovr, row["id"], row, row["id"].lower()))

    unused = (set(ovr["rows"]) | set(ovr["featured"])) - used
    assert not unused, f"unused overrides: {sorted(unused)}"
    assert set(standalone) | set(ovr["subsumed"]) == {r["industry"] for r in rows}

    industries = [featured[i] for i in MENU] + [standalone[k] for k in sorted(standalone, key=lambda k: standalone[k]["name"].lower())]
    for ind in industries:
        ind["automations"] = by_score(ind["automations"])
        pain_ids = {p["id"] for p in ind["pains"]}
        for a in ind["automations"]:
            assert a["pains"] and set(a["pains"]) <= pain_ids, (ind["id"], a["id"])
        assert all(any(p["id"] in a["pains"] for a in ind["automations"]) for p in ind["pains"]), ind["id"]

    data = {"schema_version": 1, "industries": industries}
    text = json.dumps(data, indent=1, ensure_ascii=False) + "\n"
    json.loads(text)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text)
    # The relay deploys from oracle-relay/ only, so it gets its own ids+names copy for the planner deep link.
    ids = [{"id": i["id"], "name": i["name"]} for i in industries]
    (ROOT / "oracle-relay" / "planner-industries.json").write_text(json.dumps(ids, indent=1, ensure_ascii=False) + "\n")
    print(f"{len(industries)} industries, {sum(len(i['automations']) for i in industries)} automations -> {out_path}")


if __name__ == "__main__":
    main()
