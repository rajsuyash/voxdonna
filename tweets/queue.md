## 003 — wire rope hotline
A wire rope manufacturer's QA team takes 200+ complaint calls a month. Each one missing a batch number, missing photos, missing PO.

Our voice agent captures all 10 fields in 4 minutes — Salesforce case auto-populated. https://voxdonna.com/demos.html
---
## 004 — predictive maintenance gap
IoT sensors detect failures hours before they happen.

But humans still dispatch the tech.

That's the bottleneck. Our voice agent closes the loop — sensor alert → call site contact → confirm access → book certified tech with parts pre-staged.
---
## 005 — Donna voice
We tested 8 voices for our complaint hotline. Robotic flash_v2 with stability 0.5 made every customer hang up.

Switched to expressive turbo_v2 + stability 0.35. Calls now last 4 minutes instead of 90 seconds. People talk to her like a real person.
---
## 006 — pricing transparency
Most voice AI vendors hide pricing.

Voxdonna: €499/mo Starter, €999/mo Growth. Pay per minute used after that. Live in 14 days.

That's it.
---
## 007 — multilingual support
One voice agent. Same call. Customer starts in English, switches to French, back to English.

Donna handles it. EN/FR/IT, native, no language detection step.

Demo: https://voxdonna.com/demos.html
---
## 008 — warranty intake reality
A $400K combine fails at harvest. The dealer calls the OEM warranty hotline. Voicemail.

12 hours of harvest lost waiting for a callback.

Our voice agent takes the claim in 4 minutes. PIN, hours, error codes, photos email link, dealer of record — all captured.
---
## 009 — what we learned shipping 12 demos
- Stability 0.35 sounds way more human than 0.5
- Knowledge bases under 1500 words = better answers than 5000-word ones
- Sev 1 escalation prompts must be VERBATIM ("hang up and dial 911 if anyone is hurt")
- Never let the agent quote prices on the call
---
## 010 — call deflection economics
Average B2B call costs the company $7-12 in agent time.
Voice AI: ~$0.30 per call.

A manufacturer with 5,000 inbound calls/month saves $35K/mo. Payback in week 1.
Source: Naitive cloud benchmarks.
---
## 011 — restaurant reservation demo
"Table for 4 on Saturday at 8pm — one of us is gluten-free."

Try the demo: https://voxdonna.com/demos.html

Donna confirms the booking, captures the dietary note, syncs to your reservation system. ~50 seconds end-to-end.
---
## 012 — HVAC dispatch use case
Boiler leaking at 11pm. Customer calls the after-hours line.

Donna triages by urgency (Tier 1 = no heat in winter, gas leak, water leak), captures address, dispatches the on-call tech.

One of the 12 demos at https://voxdonna.com/demos.html
---
## 013 — care home concierge
Families calling care homes are anxious. They want to schedule a visit, check on Mom, request a refill.

Putting them on hold makes it worse.

Our 24/7 concierge agent never holds. EVER. Try it: https://voxdonna.com/demos.html
---
## 014 — voice agent vs IVR
IVR: "Press 1 for sales, press 2 for support, press 9 to scream."

Voice agent: "Hi, what brought you in today?"

The first is broken because it makes the customer do the routing. The second works because the AI does it. Same call. 70% deflection.
---
## 015 — manufacturing aftermarket gap
$400B aftermarket service market. OEMs earn 25-40% of revenue from aftermarket.

But the inbound spare parts hotline is staffed 9-5 by 2 people who don't know SKU cross-references.

Voice AI fixes this in 14 days. https://voxdonna.com/demos.html
---
## 016 — what makes a voice agent sound human
- Sub-1s latency (otherwise they sound robotic)
- Stability 0.3-0.4 (not 0.5+)
- Real KB attached (not just system prompt)
- Allow interrupts (don't make the human wait for the bot to finish)
- Match the brand voice (not "default professional")
---
## 017 — order tracking voice agent
"Where is PO 88231?"

Most B2B reps look it up manually, 5-10 min per call.

Voice agent: live ERP query, reads back stage + carrier + tracking number, offers to expedite. 45 seconds.

Try it: https://voxdonna.com/demos.html
---
## 018 — knowledge base lessons
We tested KB sizes from 500 to 5000 words.

Sweet spot: 1200-1500 words. More than that and the agent starts hallucinating product specs. Less and it can't answer real questions.

We retain ~20 FAQs per KB. That's the magic number.
---
## 019 — the voicemail problem
Most B2B inbound calls hit voicemail after 30s of ringing. 67% hang up.

That's a lost lead.

Voice AI picks up in 1 second. Same warmth, no hold music. Live in 14 days at https://voxdonna.com/demos.html
---
## 020 — sales hotline triage
A B2B prospect calls. They want pricing.

Sales rep is in another meeting. Customer goes to voicemail.

Lead lost.

Voice agent: "Pricing depends on monthly call volume. Around how many inbound calls do you get? I can have a rep follow up within the hour."

Lead saved.
---
## 021 — multilingual reality
Italy, France, UK — three offices, three accents. We had a real customer try Donna in all three.

She switched languages mid-call when one rep handed to another. Customer didn't notice.

That's the bar now.
---
## 022 — ROI math
B2B voice agent setup: 14 days, ~$10K one-time integration cost.
Monthly: €499-999 + per-minute usage.
Replaces: 1-2 FTEs at €40K-60K/year each.

Payback: 60-90 days.
Source: Naitive cloud, Retell AI benchmarks.
---
## 023 — debugging the START node
Spent 6 hours fixing "START node generated a response after progressing" — an ElevenLabs flow-graph misconfig.

Rule: START nodes describe state, never generate. Move all generation to AI Response nodes downstream.
---
## 024 — sample call data
We analyzed 10,000 B2B inbound calls.

73% could be handled end-to-end by AI.
17% need a human handoff after intake.
10% genuinely need a human from start to finish.

The 73% is what voice AI is for. https://voxdonna.com/blog.html
---
## 025 — outbound qualification demo
Donna calls inbound demo requests within 60 seconds, qualifies budget/timeline/decision authority, and books a meeting on the rep's calendar.

Try it: https://voxdonna.com/demos.html
---
## 026 — escalation rules
Hard rules we burn into every voice agent's system prompt:

- Mention of injury → hang up and dial 911
- Mention of regulator (OSHA, FDA, etc.) → escalate to legal
- Mention of legal action → no liability discussion, route to legal
- Don't quote root cause — engineer assesses
---
## 027 — first 10 calls observation
On the first 10 production calls of any new voice agent, you'll find 3 things:

1. A KB gap (something they didn't anticipate)
2. A persona slip (agent breaking character)
3. A latency spike (something taking 4s when it should take 1s)

Iterate weekly.
---
## 028 — voice AI market size
Voice AI market projected $47.5B by 2034 at 34.8% CAGR.

B2B voice AI is the fastest-growing segment because:
- Highest ROI (replaces FTEs, not chatbots)
- Easiest deployment (no app install, just route the phone number)
- Strongest data moat (every call improves the KB)
---
## 029 — what we don't do
We don't do auto-follow, auto-DM, auto-reply spam.

We don't promise to "100% replace humans". 27% of calls genuinely need humans.

We don't sell a black box. You see every call transcript, every cost, every metric.
---
## 030 — book a demo
If you run a B2B inbound or outbound team and you're considering voice AI, talk to a real Donna in 60 seconds at https://voxdonna.com/demos.html

Or book a 30-min strategy call: https://tidycal.com/rajsuyash/discovery-call-for-ai-voice-agent
