# SalesDonna — Landing Page Copy (Production)

> Source copy for `salesdonna.html`. Voice: Donna blend per SOUL.md. Declarative, no hedging, no em-dashes, one number per claim. Design tokens per DESIGN.md.

---

## 1. Hero

**Eyebrow:** `SALESDONNA · BY VOXDONNA`

**Headline (H1):**
Your team had 4,000 customer meetings last month.
You saw none of them.

**Subheadline:**
SalesDonna sits in on every field sales conversation, with consent, and does the work nobody does after: the summary, the CRM entry, the follow-up tasks, the coaching note. Filed before your rep is back in the car.

**Primary CTA:** Book a demo
**Secondary CTA:** See how it works ↓ (anchors to #how)

**Hero visual:**
Abstract flow, right side or below on mobile: a live waveform (copper, animated) resolving into three stacked structured cards labelled "Meeting summary", "CRM updated", "3 follow-ups created". No stock photos. No fake dashboards.

**UX notes:**
- Full-viewport hero, headline `clamp(42px, 7vw, 80px)` Inter 700, letter-spacing -0.04em
- "You saw none of them." on its own line, copper-light `#d4a574`
- GSAP text reveal on load, `power3.out`, 900ms, staggered lines
- Waveform: CSS/SVG bars animating height, then ScrollTrigger morph into cards on first scroll

**Icons:** none in hero. Type carries it.

---

## 2. Social Proof Strip

**Trust statement (above logos):**
Field sales teams in FMCG, pharma, building materials and consumer durables run on SalesDonna.

**Logos:** 6 grayscale placeholder slots, 40% opacity, hover to 70%.

**UX notes:**
- Slim band, 80px padding, `rgba(255,255,255,0.02)` surface
- Marquee scroll on mobile (pattern exists in index.html), static row on desktop
- Placeholder logos: neutral wordmarks until real customers sign off

---

## 3. The Problem

**Eyebrow:** `THE PROBLEM`

**Headline:**
Your CRM is a work of fiction.

**Subtitle:**
Every field meeting produces intelligence. Orders, objections, competitor moves, buying signals. Then the rep drives to the next visit and 90% of it evaporates. What survives is a two-line CRM note written from memory at 9pm. You manage a team on that.

**Three cards:**

**Card 1: The notes lie by omission**
"Met the customer, discussed pricing, will follow up." That is what the CRM says about a 40-minute negotiation. The objection that stalled the deal is not in there. It is not anywhere.

**Card 2: Coaching happens too late**
You find out a rep has been mishandling the price objection in month three, from the churn report. The conversation that would have told you was in week one. Nobody heard it but the customer.

**Card 3: The playbook retires with the rep**
Your best rep closes 2× the team average. Her openers, her objection handling, her sequencing. None of it is written down. When she leaves, it leaves.

**UX notes:**
- 3-column grid, 1-column mobile. Standard card treatment, hover lift + copper glow
- Cards enter with staggered fade-up on scroll (IntersectionObserver pattern)

**Icons:** line icons, 2px stroke, 32px: file-x (notes), clock-alert (coaching), door-open (playbook)

---

## 4. How SalesDonna Works

**Eyebrow:** `HOW IT WORKS`

**Headline (scramble, JetBrains Mono):**
From handshake to CRM in six steps. You do one of them.

**Subtitle:**
The rep starts the recording. SalesDonna does everything after.

**Steps (numbered, mono labels 01–06):**

**01 · Meet**
The rep opens the app, confirms consent, taps record. That is the entire workflow change.

**02 · Record**
SalesDonna captures the conversation in the field. Showroom noise, clinic corridors, distributor godowns. Built for rooms without microphones.

**03 · Understand**
The transcript goes through models trained on sales conversations. Not keywords. Meaning. Who committed to what, what the customer pushed back on, which competitor came up and in what tone.

**04 · Structure**
Out comes a meeting summary, the order details, every objection, every buying signal, every commitment with an owner and a date.

**05 · Execute**
The CRM updates itself. Follow-up tasks land in the rep's queue with deadlines. Nothing depends on anyone remembering anything.

**06 · Coach**
Managers see scored conversations, flagged coaching moments, and what the top performers do differently. Before the quarter ends, not after.

**UX notes:**
- Horizontal scroll-pinned sequence on desktop (ScrollTrigger `scrub: 0.6`, pattern exists in index.html usecase-showcase), vertical stacked steps on mobile
- Step numbers in JetBrains Mono 500, copper
- Thin copper progress line connecting steps, draws with scrub

**Icons:** 24px line icons per step: mic, waveform, brain-circuit, list-checks, refresh-cw (sync), trending-up

---

## 5. Features (4 clusters, 14 features)

**Eyebrow:** `THE PLATFORM`

**Headline:**
Everything between the conversation and the close.

**Subtitle:**
Fifteen capabilities. One job: no field intelligence ever gets lost again.

---

### Cluster A — CAPTURE

**A1. AI Meeting Recorder**
*Every conversation, captured where it happens.*
- One-tap recording with built-in consent capture, in the customer's language
- Tuned for field conditions: traffic, showrooms, factory floors
- Works on the phone the rep already carries
- Offline recording with sync when coverage returns

**A2. Automatic Meeting Notes**
*The rep talks to customers. The notes write themselves.*
- Structured summary within minutes of the meeting ending
- Key points, decisions, commitments, next steps, separated and labelled
- Editable before filing, so the rep stays in control
- Searchable across every meeting the team has ever had

**A3. Order Capture**
*Spoken orders become structured orders.*
- Product, quantity, price and delivery terms extracted from conversation
- Flagged for rep confirmation before submission
- Feeds directly into your order workflow
- No more orders reconstructed from memory in the parking lot

---

### Cluster B — EXECUTE

**B1. CRM Auto Sync**
*Your CRM, updated by the meeting itself.*
- Contact, account, opportunity and activity records updated automatically
- Field mapping configured to your CRM schema, not the other way round
- Works with Salesforce, HubSpot, Zoho, Dynamics and SAP
- CRM hygiene stops being a management campaign. It becomes a default.

**B2. Follow-up Task Creation**
*Every commitment becomes a task with a deadline.*
- "I'll send the quote by Friday" becomes a Friday task, automatically
- Tasks route to the right owner: rep, sales ops, technical team
- Overdue commitments surface to managers before customers notice
- Follow-up speed is the cheapest win rate lever you have. This pulls it.

**B3. Commitment Tracking**
*What was promised, by whom, by when. On both sides.*
- Tracks rep commitments and customer commitments separately
- Timeline view per account: every promise ever made in the relationship
- Broken-commitment alerts before the next meeting
- Negotiation history that does not depend on anyone's memory

---

### Cluster C — UNDERSTAND

**C1. Customer Objection Detection**
*Objections are your market talking. Start listening.*
- Every objection extracted, categorised and counted across the team
- Price, product, timing, trust: see which one is actually costing you deals
- Per-rep objection-handling patterns, compared
- The input your product and pricing teams have been guessing at

**C2. Buying Signal Detection**
*Know which deals are real before the forecast call.*
- Detects intent language: budget mentions, timeline questions, stakeholder references
- Deal-level signal strength, trending across meetings
- Forecast built on what customers said, not what reps hope
- Cold deals identified early, while the pipeline review can still fix them

**C3. Competitor Tracking**
*Every competitor mention, logged with its context.*
- Who came up, in which accounts, said by whom, in what tone
- Pricing and feature comparisons customers raise, verbatim
- Win/loss patterns against each competitor by region and product line
- Competitive intelligence from the field, not from a subscription

**C4. Conversation Intelligence**
*Search every customer conversation your company has ever had.*
- Ask questions in plain language: "What did Mehta Distributors say about credit terms in March?"
- Talk-time ratios, question rates, topic coverage per meeting
- Patterns across thousands of conversations, surfaced without asking
- Institutional memory that survives attrition

**C5. Territory Insights**
*What the field knows, aggregated by geography.*
- Objection, competitor and demand patterns by territory and beat
- Compare what customers in the North say against the South, this quarter against last
- Territory-level coaching priorities for regional managers
- Market feedback loops measured in days, not quarters

---

### Cluster D — COACH

**D1. AI Sales Coaching**
*Every rep gets reviewed. Every meeting is film.*
- Conversation scoring against your playbook: discovery, pitch, objection handling, closing
- Specific coaching moments flagged with the exact clip and transcript line
- Reps see their own scores and trends. Improvement stops being abstract.
- Coaching load drops from "listen to everything" to "review what matters"

**D2. Performance Analytics**
*Measure the selling, not just the sales.*
- Rep-level trends: meeting volume, conversion by stage, objection outcomes
- Leading indicators weeks ahead of the revenue report
- Ramp tracking for new hires against your best performers' baseline
- One number worth repeating: you see performance forming, not just reported

**D3. Sales Manager Dashboard**
*Your entire field, one screen.*
- Every meeting across the team: summaries, scores, flags
- Deals that need intervention, sorted by urgency
- Coaching queue: which rep, which skill, which conversation proves it
- The Monday review meeting, without the "so what happened with..." hour

**D4. Team Leader Dashboard**
*For the person running eight reps and a number.*
- Team activity and outcomes at a glance, daily
- Commitment slippage and follow-up backlog per rep
- Territory comparisons the RSM will ask about, answered in advance
- Built for leaders who coach in the field, on a phone, between visits

**UX notes:**
- 4 cluster tabs or stacked cluster sections, each with 3–5 feature cards in grid
- Recommended: stacked sections with sticky cluster label on desktop
- Cards: standard DESIGN.md treatment. Feature headline Inter 600 20px, benefit line copper-light italic, bullets 15px secondary text
- Stagger cards on scroll entry, 80ms apart

**Icons per feature (18–24px line):** mic / file-text / package / refresh-cw / check-square / handshake / shield-question / radar / swords (or crosshair) / search / map / graduation-cap / bar-chart-3 / layout-dashboard / users

---

## 6. Benefits by Role

**Eyebrow:** `WHO IT'S FOR`

**Headline:**
Everyone gets time back. You get the truth.

**Card 1 — Sales Representatives**
*Zero evening admin.*
Reps sell for a living and type for punishment. SalesDonna ends the 9pm CRM session. Notes, orders, tasks and updates are done when the meeting is done. The rep's job goes back to being the meeting.

**Card 2 — Sales Managers**
*See every meeting without riding along.*
You can accompany one rep per day. SalesDonna sits in on all of them. Review the conversations that matter, coach on evidence instead of anecdotes, and stop running your region on hearsay.

**Card 3 — Business Owners**
*Reports written by the market, not the team.*
Every number in your Monday review currently passes through someone with an incentive. SalesDonna's numbers come from the conversations themselves. What customers said, what they ordered, what they objected to. Unedited.

**Card 4 — Revenue Leaders**
*A forecast built on evidence.*
Pipeline reviews become audits of real conversations, not confidence surveys. Buying signals, commitment velocity and objection trends feed the forecast. When you commit a number to the board, you know where it came from.

**UX notes:**
- 4 cards, 2×2 grid desktop, 1-column mobile
- Role label as tag/eyebrow on each card, italic benefit line in copper-light
- Same entrance pattern as problem cards

**Icons:** 32px: briefcase (rep), eye (manager), building-2 (owner), trending-up (revenue leader)

---

## 7. ROI Band

**Eyebrow:** `THE MATH`

**Headline:**
The admin was never the job.

**Stats (tabular-nums, counter animation on scroll):**

- **Up to 70% less time on CRM admin** — the notes, updates and tasks write themselves
- **3× faster follow-ups** — commitments become deadlined tasks the moment the meeting ends
- **100% meeting visibility** — every recorded conversation summarised, scored and searchable
- **Weeks off new-rep ramp** — new hires study your best performers' real conversations from day one

**Supporting line (below stats):**
Reps spend roughly a third of their week on reporting and admin. Give most of it back and the same headcount makes more calls, follows up faster and closes more. No motivation poster required.

**UX notes:**
- Full-width band, subtle copper gradient edge top and bottom
- 4 stats in a row, stacked on mobile. Number in Inter 700 clamp(40–64px), tabular-nums, copper-light. Label 14px secondary below
- GSAP counter tween on scroll into view (stats pattern exists in index.html)
- "Up to" framing stays. Do not inflate.

---

## 8. Comparison Table

**Eyebrow:** `BEFORE / AFTER`

**Headline:**
Traditional CRM asks reps to report. SalesDonna listens.

| | Traditional CRM | SalesDonna |
|---|---|---|
| Meeting notes | Typed from memory, hours later | Generated from the conversation, minutes later |
| Follow-up tracking | Depends on the rep remembering | Every commitment becomes a deadlined task |
| Meeting visibility | Ride-alongs and verbal updates | Every meeting summarised, scored, searchable |
| Coaching | Quarterly, from lagging numbers | Weekly, from flagged conversation moments |
| CRM updates | A discipline problem | A default |
| Analytics | Activity counts | Conversation outcomes, objections, signals |
| Customer insights | Lost at the car door | Captured, structured, aggregated |

**Closing line under table:**
Your CRM is not the problem. Feeding it is. SalesDonna is the feed.

**UX notes:**
- Two-column comparison, SalesDonna column with featured-card treatment (copper border, soft copper background)
- `overflow-x: auto` wrapper on mobile, or collapse to stacked before/after pairs
- Row-by-row fade-in on scroll

---

## 9. AI Sales Coach

**Eyebrow:** `THE COACH`

**Headline:**
Great sales teams review film. Yours finally has some.

**Body copy (editorial, 720px max-width):**

Football teams review every game. Sales teams review almost nothing, because until now there was nothing to review. The meeting happened in a distributor's office 200km away and the only record is the rep's version of it.

SalesDonna turns every field conversation into reviewable film. Managers open the dashboard and see each meeting scored against the playbook: how discovery went, how the price objection was handled, whether the close was asked for at all. The weak moments come flagged, with the exact minute and the transcript line.

Then it gets useful. SalesDonna compares. Your top rep handles the credit-terms objection in a way that keeps deals alive, and your newest rep doesn't. That difference used to be invisible. Now it is a coaching session with a specific example, delivered in week two instead of quarter three.

**Four proof points (compact grid):**
- **Review every interaction** without leaving your desk. Ride-alongs become a choice, not a bottleneck.
- **Spot coaching opportunities** flagged automatically, with the clip attached.
- **Learn from top performers.** Their real conversations become the team's playbook.
- **Fix objections at the source.** See the top five objections costing you revenue and rehearse the answers that win.

**Closing line:**
Win rates don't improve from dashboards. They improve from better conversations. This is how conversations get better.

**UX notes:**
- Editorial layout: headline left, body copy in single measure, proof grid below
- Optional visual: a "scored conversation" card mock (score ring, flagged moment chips)
- This section carries the emotional weight for the Sales Head persona. Give it room. 160px padding.

**Icons:** 24px: play-circle, flag, trophy, shield-check

---

## 10. Integrations

**Eyebrow:** `PLAYS WELL WITH`

**Headline:**
Your stack stays. SalesDonna feeds it.

**Subtitle:**
SalesDonna is not another system your team logs into. It pushes structured intelligence into the tools you already run.

**Grid (name + one line each):**
- **Salesforce** — activities, notes, tasks and opportunity updates, mapped to your schema
- **HubSpot** — meetings logged, deals updated, tasks created
- **Zoho CRM** — full activity and module sync
- **Microsoft Dynamics** — enterprise-grade field mapping and sync
- **SAP** — order and account data where your operations live
- **WhatsApp** — meeting summaries and tasks delivered where field teams actually read
- **Google Calendar** — meetings matched to scheduled visits automatically
- **Outlook** — calendar sync and follow-up scheduling
- **Microsoft Teams** — deal rooms and manager alerts in channel
- **Slack** — real-time deal signals and coaching flags

**UX notes:**
- 5×2 logo grid desktop, 2-column mobile. Monochrome logos, copper on hover
- One-liners appear on hover (desktop) / always visible (mobile)

---

## 11. Security

**Eyebrow:** `TRUST`

**Headline:**
Recording conversations is serious. So is our security.

**Six items:**

**Consent, built in**
Recording starts with explicit consent capture, in the customer's language. Consent records are stored with every recording. No consent, no recording. Non-negotiable and non-configurable.

**Encrypted end to end**
Conversations are encrypted in transit and at rest. Keys are managed to enterprise standards.

**GDPR compliant**
Data subject rights, retention controls and deletion workflows are built into the product, not bolted on for the audit.

**SOC 2 readiness**
Controls aligned to SOC 2 from day one, with certification on the roadmap. Ask us where we are; you get the real answer.

**Role-based access**
Reps see their meetings. Managers see their teams. Nobody sees more than their role requires, and every access is logged.

**Secure cloud infrastructure**
Hosted on hardened cloud infrastructure with regional data residency options for regulated industries.

**UX notes:**
- 3×2 grid, restrained styling. No hover theatrics here. Trust sections should sit still.
- Info-blue `#7da9c4` acceptable for icon accents per semantic palette

**Icons:** 24px: user-check (consent), lock, scale (GDPR), badge-check (SOC 2), key-round (RBAC), server

---

## 12. Testimonials (placeholders)

**Eyebrow:** `WHAT LEADERS SAY`

> **"I used to get 40 meeting reports a week and believe maybe half. Now I read the meetings themselves. My Monday review is 45 minutes shorter and twice as honest."**
> VP Sales, consumer durables company · *placeholder*

> **"We found out three distributors were being pitched by a competitor two weeks before it showed up anywhere else. That alone paid for the year."**
> National Sales Manager, building materials company · *placeholder*

> **"My reps hated it for a week. Then they realised they'd stopped doing CRM at night. Adoption stopped being my problem."**
> CEO, pharma distribution company · *placeholder*

**UX notes:**
- 3 cards, quote-first, attribution small and secondary. Mark clearly as illustrative until real customers sign off (keep the *placeholder* tag in HTML comments, not visible text, once real quotes land)
- No headshots until real. Avoid fake-face stock.

---

## 13. FAQ (20)

**Eyebrow:** `QUESTIONS`
**Headline:** Asked and answered.

1. **Do customers know they're being recorded?**
Yes, always. Recording starts with explicit consent captured in the customer's language, and the consent record is stored with the recording. No consent, no recording.

2. **Is recording face-to-face conversations legal?**
With consent, in most jurisdictions, yes. SalesDonna enforces consent capture and we configure the flow to your legal team's requirements per market. Your counsel signs off before rollout.

3. **What happens to the recordings?**
They are encrypted, stored under your retention policy, and accessible only by role. You control retention windows and deletion.

4. **Which CRMs does SalesDonna integrate with?**
Salesforce, HubSpot, Zoho, Microsoft Dynamics and SAP out of the box. Custom CRMs via API.

5. **What if our CRM fields are heavily customised?**
Field mapping is configured to your schema during onboarding. Your CRM does not change to fit us.

6. **Does it work offline?**
Yes. Recordings capture offline and sync when the phone finds coverage. Field-first was the design constraint, not an afterthought.

7. **Is there a mobile app?**
Yes. iOS and Android. The rep-facing product is mobile-first because the rep is in the field, not at a desk.

8. **What languages does it support?**
Major global and Indian languages for both recording and analysis, including mixed-language conversations, which is how field sales actually sounds. Ask us about your specific mix.

9. **How accurate are the transcripts and summaries?**
Strong enough to file, and every summary is shown to the rep for a one-tap review before it syncs. The rep confirms in seconds; the system learns from corrections.

10. **Can the AI misattribute a commitment or order?**
It can, which is why extracted orders and commitments are flagged for rep confirmation before they enter your workflow. Automation does the work; a human approves the consequences.

11. **How is conversation scoring calibrated?**
Against your playbook, not a generic one. We configure scoring criteria with your sales leadership during onboarding.

12. **Will reps feel surveilled?**
Reps feel surveilled by micromanagement, not by tools that erase their admin. In practice adoption follows the first week of not typing CRM notes at night. Managers coach on flagged moments, not on live monitoring.

13. **Can reps edit or delete their meeting notes?**
Edit before filing, yes. Deletion follows your data governance policy, with audit logs either way.

14. **How long does deployment take?**
A pilot team is live in days. Full deployment with CRM mapping and playbook calibration typically runs a few weeks, not quarters.

15. **What does onboarding look like?**
We configure CRM sync, consent flows and scoring criteria with your team, run a pilot region, then scale. You get a named contact, not a ticket queue.

16. **What does it cost?**
Pricing is tailored to team size, integration depth and deployment scope. Talk to us and you'll have a number the same week.

17. **Is our data used to train models for other companies?**
No. Your conversations are your asset. They improve your deployment, nobody else's.

18. **Where is the data hosted?**
Secure cloud infrastructure with regional residency options for regulated industries. We'll match your compliance requirements.

19. **Can we restrict who sees what?**
Yes. Role-based access is standard: reps see their own meetings, managers their teams, admins what you decide. Every access is logged.

20. **We already have Gong. Why SalesDonna?**
Gong hears your Zoom calls. Your revenue happens in showrooms, clinics and distributor offices. SalesDonna covers the conversations your call-recording stack has never heard, and executes the CRM work afterward instead of just analysing it.

**UX notes:**
- Accordion, single-open, pattern from index.html FAQ
- Group visually into 4 columns of concern via subtle labels if space allows: Consent & privacy, Integration, Usage, Commercial

---

## 14. Final CTA

**Headline:**
Your team is already having the conversations.
Start keeping them.

**Supporting copy:**
Book a 30-minute demo. Bring your messiest CRM and your hardest objection. We'll show you what SalesDonna does with both.

**Primary CTA:** Book a demo
**Secondary CTA:** Talk to us → hello@voxdonna.com

**UX notes:**
- Full-width closing band, copper gradient glow behind headline
- Headline centered, clamp(36–64px)
- Generous 160px padding. Last impression, no clutter.

---

## SEO Head (for salesdonna.html)

**Title (58 chars):** SalesDonna: AI Sales Assistant for Field Sales Teams
**Meta description (156 chars):** SalesDonna records field sales meetings with consent, writes the CRM notes, creates follow-ups and coaches your team. AI sales intelligence for field sales.
**Keywords woven into H2s/body:** AI sales assistant, AI sales coach, sales enablement software, field sales software, sales conversation intelligence, CRM automation, revenue intelligence, sales analytics, AI meeting notes, sales performance management
**OG image:** reuse Voxdonna OG pattern, new 1200×630 with SalesDonna headline (TODO: generate asset)
**JSON-LD:** `SoftwareApplication` (name SalesDonna, publisher Voxdonna) + Organization
**Canonical:** https://voxdonna.com/salesdonna.html
