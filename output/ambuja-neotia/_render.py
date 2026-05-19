"""Custom renderer for Ambuja Neotia — INR-aware, real-estate-tuned ROI."""
import json
import re
from html import escape
from pathlib import Path

ROOT = Path(__file__).parent
TEMPLATE = Path("/Users/suyashraj/.claude/skills/prospect-landing-builder/assets/template.html")

brand = json.loads((ROOT / "brand.json").read_text())
use_cases = json.loads((ROOT / "use-cases.json").read_text())
agent = json.loads((ROOT / "agent.json").read_text())

hero = use_cases["hero"]
secondary = use_cases["secondary"]

# Logo block
logo_path = "assets/logo.png"
logo_block = f'<img src="{logo_path}" alt="Ambuja Neotia logo" class="prospect-logo">'

# Agent embed
agent_id = agent.get("agent_id")
if agent_id:
    agent_embed = (
        f'<elevenlabs-convai agent-id="{escape(agent_id)}"></elevenlabs-convai>\n'
        '<script src="https://unpkg.com/@elevenlabs/convai-widget-embed" async type="text/javascript"></script>'
    )
else:
    agent_embed = (
        '<div class="agent-placeholder">'
        '<strong>Live demo arriving in 24 hours.</strong> The Voxdonna agent for the Ambuja Neotia property-enquiry flow is being provisioned on the Voxdonna voice platform with Bengali, Hindi and English voices. You\'ll receive a refreshed link with the inline widget.'
        '</div>'
    )

# Why facts — Ambuja-specific
why_facts_html = "\n".join(f"<li>{f}</li>" for f in [
    "Your published support hours are <strong>10 AM to 6:30 PM, except Sundays and national holidays</strong>. That leaves <strong>109 hours a week</strong> when a serious buyer asking about Upohar, Utalika, Urvisha or The Residency Patna hits an enquiry form they may never hear back on. The agent above covers that window.",
    "You operate across <strong>7 states</strong> — West Bengal, Bihar, UP, Himachal, Punjab, Chhattisgarh, Rajasthan. A Patna caller wants Hindi; a Salt Lake caller wants Bengali; an Ecospace office tenant wants English. One agent, three native voices, zero retraining.",
    "Your portfolio spans residential, commercial, retail (six City Centres), hospitality (26 hotels including Taj City Centre and Tree of Life), healthcare (Bhagirathi Neotia, Neotia Getwel) and TNU. <strong>Same agent, different scope.</strong> Start with property enquiry — the highest-ticket line — then clone the flow.",
    "Your FAQ page promises <em>\"personalised assistance from our sales team to guide you through every step.\"</em> The team is on weekdays, 10–6:30. The agent above keeps that promise the other 109 hours.",
])

# Use case cards
cards = []
for uc in secondary:
    cards.append(f"""
        <article class="use-case-card">
          <h3>{escape(uc['title'])}</h3>
          <p class="outcome">{escape(uc['outcome'])}</p>
          <p class="body">{escape(uc['narrative'])}</p>
        </article>""")
use_case_cards = "\n".join(cards)

# ROI block — INR, real-estate-tuned
# Conservative: 26 projects × ~400 enquiries/month/project = 10,400. Round to 8,000.
# After-hours share for residential calling: ~55% (evenings + weekends are buyer time).
# Pickup 90%, qualification 70%, site-visit conversion 25%, sale conversion 3%.
# Avg residential ticket: ₹1.5 Cr (mid-segment Ambuja product).
# Voxdonna recovered = enquiries × after-hours share × pickup × qual × site-conv × sale-conv × ticket
# We don't claim incremental sale — we claim incremental qualified site visits and pipeline value.
monthly_enquiries = 8000
after_hours_share = 0.55
pickup = 0.90
qual = 0.70
site_conv = 0.25
ticket_value_inr = 15000000  # ₹1.5 Cr
# Incremental qualified site visits per month
incr_visits = monthly_enquiries * after_hours_share * pickup * qual * site_conv
# Pipeline value created (visits × historical close rate ~5%)
pipeline = incr_visits * 0.05 * ticket_value_inr
# Voxdonna cost: setup ₹2 lakh amortised over 12 = ₹16,667/mo + per-min usage (~₹8/min × 3 min avg × 8000 calls)
voxdonna_monthly = 200000 / 12 + 8 * 3 * monthly_enquiries

def inr(n):
    n = round(n)
    if n >= 10000000:
        return f"₹{n/10000000:.1f} Cr"
    if n >= 100000:
        return f"₹{n/100000:.1f} L"
    return f"₹{n:,}"

roi_block = f"""
    <div class="roi-row"><span class="roi-label">Est. monthly enquiry-call volume (across all verticals)</span><span class="roi-value">{monthly_enquiries:,}</span></div>
    <div class="roi-row"><span class="roi-label">After-hours share captured (55%, with 90% pickup)</span><span class="roi-value">{int(monthly_enquiries*after_hours_share*pickup):,}</span></div>
    <div class="roi-row"><span class="roi-label">Incremental qualified site visits / month</span><span class="roi-value">{int(incr_visits):,}</span></div>
    <div class="roi-row"><span class="roi-label">Voxdonna monthly cost (setup amortised + usage)</span><span class="roi-value">{inr(voxdonna_monthly)}</span></div>
    <div class="roi-row total"><span class="roi-label">Incremental pipeline value created / month</span><span class="roi-value">{inr(pipeline)}</span></div>
    <p class="roi-disclaimer">Illustrative only. Assumptions: 8,000 enquiry calls/month across residential, commercial, retail and hospitality; 55% land outside 10 AM–6:30 PM Mon–Sat; 90% pickup; 70% qualification; 25% site-visit conversion; ₹1.5 Cr avg residential ticket; 5% historical close rate from site visit. We calibrate to your real numbers in a 30-minute call.</p>
"""

# Read template
template = TEMPLATE.read_text(encoding="utf-8")

mapping = {
    "COMPANY_NAME": "Ambuja Neotia",
    "TAGLINE": escape(brand.get("tagline", "")),
    "ACCENT_COLOR": brand.get("accent_color", "#7a5a3c"),
    "LOGO_BLOCK": logo_block,
    "HERO_USE_CASE_TITLE": escape(hero["title"]),
    "HERO_USE_CASE_NARRATIVE": escape(hero["narrative"]),
    "AGENT_EMBED": agent_embed,
    "WHY_FACTS": why_facts_html,
    "USE_CASE_CARDS": use_case_cards,
    "ROI_BLOCK": roi_block,
    "CALENDLY_URL": "https://calendly.com/suyash-voxdonna/30min",
    "FOUNDER_NAME": "Suyash Raj",
    "FOUNDER_TITLE": "Founder, Voxdonna",
}

out = template
for k, v in mapping.items():
    out = out.replace("{{" + k + "}}", v if v else "")
out = re.sub(r"\{\{[A-Z0-9_]+\}\}", "", out)

(ROOT / "index.html").write_text(out, encoding="utf-8")
print(f"wrote {ROOT}/index.html ({len(out):,} bytes)")
