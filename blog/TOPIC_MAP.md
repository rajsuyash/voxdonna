# VoxDonna Blog — Topic Map (rev 2026-09-22)

**Positioning (2026-09-22, supersedes the 2026-07 voice-led map):** VoxDonna builds **custom AI employees that handle repeated business tasks across WhatsApp, email and voice, and update the customer's ERP or CRM as the work gets done.** Voice is one channel inside that offer, not the category. Source: `voxdonna-seo-implementation-plan.md` and `voxdonna-seo-strategy-revision-2026-09-22.md` — in this repo at the root and under `docs/seo-ecosystem/`, and on the writer's host at `~/clawd/seo/` (the repo copies are untracked, the `~/clawd/seo/` copies are what the writer can actually read).

**Niche (decided 2026-09-25, owner):** enterprise clients in the **US, EU and India**, across eight industries — **manufacturers, jewellers, real estate, furniture, kitchen appliances, luxury furniture, rooftop solar, premium consumer brands**. Source: `voxdonna-seo-implementation-plan.md` §6, "Decision 2026-09-25 (owner)" and "Amendment 2026-09-25 (owner): eighth industry".

**Niche gate (2026-09-25):** every post must be anchored in one of the eight industries above — the task, the buyer and the worked example all come from that industry. A cross-industry task post (V1–V4) is allowed only when its worked example is drawn from one of these eight industries, never a generic or out-of-niche one.

**Market rule (2026-09-25):** each post picks one primary market — US, EU or India — for its examples, currency, regulation and unit spelling, and rotates across the queue. Never mix an Indian-rupee example into a US-framed post, or vice versa.

**Market note (2026-09-25, owner):** market "UK" is accepted as the English-language EU stand-in — the owner chose the UK Semrush database to research the EU market in English, since Semrush has no single pan-EU database. A row tagged market UK satisfies the EU slot in the market rule above.

**Enterprise buyer framing (2026-09-25):** buyer roles are enterprise operating roles — Head of Sales Ops, Customer Service Director, Plant/Operations Manager, Dealer/Channel Manager, CFO/Controller — not solo founders or SMB owners.

**Ownership rule (2026-09-19, still in force):** per `~/clawd/seo/three-site-seo-ecosystem-plan.md` §B, generic AI-strategy, framework, common-mistakes and research-roundup topics belong to rajsuyash.com. Pillars **C1, C3, C5, C6 stay RETIRED**. **C7 (Future Trends) is RETIRED as of 2026-09-22** — grounded-outlook and "what's real vs marketing" commentary is the same generic-strategy category that moved to rajsuyash.com.

**Task-anchor rule (2026-09-22) — the gate that replaces "pick the next slug":** a VoxDonna post must name (a) one specific repeated business task, (b) the buyer role who owns that task today, and (c) the system the work lands in (ERP, CRM, WhatsApp, email, phone). A post that is a framework, checklist, maturity model, adoption roadmap or research roundup fails the gate and belongs to rajsuyash.com — no matter which pillar it appears to sit under.

**Channel-balance rule (2026-09-22):** as of this revision, 25 of 37 EN posts are voice/call-framed, 1 is WhatsApp, 1 is email/ERP. Until non-voice posts are at least 40% of `blog/en/`, every alternate post must be non-voice (email→ERP, WhatsApp, or cross-channel). Measure it, never estimate it — the command is in the writer's AGENTS.md Step 0.

Work top-down within a pillar; skip any slug already in `blog/en/` or `sitemap.xml`. Each entry names its destination page — the post must link it with a natural anchor. Extend this map when <5 uncovered remain, using only VoxDonna-owned clusters (§B 9–21 and 32–38).

---

## V1 · Custom AI employees — the category (→ `index.html`)
Explains the offer. Do NOT write a definitional "what is an AI agent" piece — that is rajsuyash.com cluster 5. The boundary is intent: *define/compare concepts* = R, *decide whether to hire/deploy one* = V.

1. what-is-an-ai-employee — What an "AI Employee" Actually Is, and What It Isn't
2. ai-employee-vs-chatbot-vs-rpa — AI Employee vs Chatbot vs RPA: Where Each One Breaks
3. ai-employee-scope-approval-boundaries — Deciding What an AI Employee Is Allowed to Do on Its Own
4. ai-employee-first-90-days — The First 90 Days of an AI Employee: Discovery to Acceptance

## V2 · Business-task automation — the repeated task (→ `sap-email-agent.html`, `salesdonna.html`, `whatsapp-donna-agents.html`, `personal-assistant.html`)
The highest-priority pillar: only 2 of 37 existing posts sit here.

5. ~~email-to-erp-sales-order-entry~~ — **MERGED into #55 (2026-09-26)**: same task as V5 #55 `sales-order-automation-ai-agent` — write #55 instead.
6. purchase-order-intake-automation — Purchase Order Intake Without Re-Typing It → `sap-email-agent.html`
7. ai-lead-qualification-what-it-asks — What an AI Lead Qualifier Actually Asks → `salesdonna.html`
8. automated-document-collection-onboarding — Chasing Documents: Automating Onboarding Follow-Up → `whatsapp-donna-agents.html`
9. payment-reminder-automation-whatsapp — Payment Reminders That Don't Damage the Relationship → `whatsapp-donna-agents.html`
10. order-status-requests-automation — Answering "Where Is My Order?" Without a Human → `whatsapp-donna-agents.html`
11. appointment-coordination-when-slots-move — Appointment Coordination When the Schedule Changes → `industries/index.html`
12. quote-follow-up-automation-b2b — The Quote Nobody Followed Up On → `salesdonna.html`

## V3 · ERP/CRM and channel integration — how the work completes (→ `sap-analytics.html`, `procurement-intelligence.html`, `customer-intelligence.html`)
13. erp-write-access-ai-agents — What an AI Agent Needs to Write Into Your ERP → `sap-analytics.html`
14. crm-hygiene-when-agents-write — Keeping the CRM Clean When an Agent Updates It → `salesdonna.html`
15. whatsapp-business-api-workflow-limits — WhatsApp Business API: What It Can and Cannot Automate → `whatsapp-donna-agents.html`
16. connector-vs-custom-integration — Connector or Custom Build: Choosing the Integration Path → `sap-email-agent.html`
17. human-approval-gates-ai-workflows — Where to Put the Human in an Automated Workflow → `index.html`
18. ai-agent-escalation-design — When the Agent Can't Finish: Escalation Design → `index.html`

## V4 · Proof and buying decisions (→ `case-studies/*`, pricing sections)
Case studies need an owner-approved customer and named consent scope. Never invent one; never publish results without a baseline, date range and measurement method.

19. ai-automation-audit-what-we-examine — What an AI Automation Audit Actually Examines → `index.html`
20. pricing-custom-ai-agent-work — What Drives the Price of a Custom AI Agent Build → `index.html`
21. acceptance-testing-an-ai-employee — Acceptance Testing an AI Employee Before It Goes Live → `case-studies/usha-martin.html`
22. measuring-task-completion-not-minutes — Measuring an AI Employee: Task Completion, Not Call Minutes → `cost-per-resolved-call-model`

## V5 · Industry × task — the eight niche industries (rewritten 2026-09-26, buyer-intent queue)

**Buyer-intent rule (2026-09-26, owner) — replaces the 2026-09-25 FROZEN gate and the 2026-09-25 topic-source rule below:** V5 topics must pass buyer intent first: the searcher is a business buyer AND wants AI/automation to do a task VoxDonna's agents do. Volume and KD rank only among topics that pass. Industry landing pages (jewellers, furniture, kitchen appliances, solar) are anchored on buyer phrases with little search volume; do not write search-driven blog posts for those phrases — the pages carry them.

Two or more task-anchored topics per industry, per the niche gate above. Each line: slug — title → destination page | market | buyer role | system | evidence. Skip any slug already in `blog/en/`.

**Topic-source rule (2026-09-26):** rows #55+ are keyword-backed from `SEO VOXDONNA/semrush-industry-discovery-r3-2026-09-25.csv`, `SEO VOXDONNA/semrush-industry-discovery-2026-09-25.csv` and `SEO VOXDONNA/industry-ai-agent-keywords-2026-09-26.csv` (evidence IDs cited per row: `D-*`, `R3-*`, `RT-*`, `C-*`, `CTRL-*`, `E-*`). A number not found in those three files is omitted from the row, never invented. Never state a keyword volume in a post.

**Retired 2026-09-25 volume-ranked queue — rows #23–54, SUPERSEDED 2026-09-26 by the buyer-intent queue below. Kept for history only; do not write any of these slugs.** (Full per-row evidence for this retired queue is preserved in git history of this file.)
~~23. dealer-claim-status-updates-manufacturing~~ · ~~24. production-downtime-alert-routing-whatsapp~~ · ~~25. jewellery-inventory-reconciliation-memo-stock~~ · ~~26. jewellery-order-to-dispatch-updates~~ · ~~27. jewellery-repair-status-whatsapp-updates~~ · ~~28. real-estate-lead-follow-up-whatsapp~~ · ~~29. real-estate-broker-commission-payout-tracking~~ · ~~30. furniture-order-status-dealer-network~~ · ~~31. furniture-custom-order-spec-confirmation-erp~~ · ~~32. kitchen-appliance-warranty-registration-automation~~ · ~~33. kitchen-appliance-service-technician-scheduling~~ · ~~34. luxury-furniture-white-glove-delivery-scheduling~~ · ~~35. luxury-furniture-trade-account-order-status~~ · ~~36. solar-site-survey-scheduling~~ · ~~37. solar-subsidy-paperwork-status-updates~~ · ~~38. sales-order-automation-email-to-erp~~ · ~~39. dealer-orders-outside-the-b2b-portal~~ · ~~40. manufacturer-order-status-questions-from-erp~~ · ~~41. sales-order-processing-france-email-to-erp~~ · ~~42. sales-order-processing-italy-email-to-erp~~ · ~~43. jewellery-repeat-visit-follow-up~~ · ~~44. how-to-respond-to-a-real-estate-lead~~ · ~~45. real-estate-lead-follow-up-system~~ · ~~46. estate-agent-crm-updates-without-data-entry~~ · ~~47. solar-permit-interconnection-status-updates~~ · ~~48. solar-panel-survey-booking-uk~~ · ~~49. wismo-where-is-my-order-premium-brands~~ · ~~50. returns-management-rma-intake~~ · ~~51. whatsapp-order-updates-d2c-india~~ · ~~52. ecommerce-customer-service-france~~ · ~~53. ecommerce-customer-service-tickets-an-agent-can-close~~ · ~~54. returns-management-italy~~

**Buyer-intent queue (2026-09-26, owner-approved) — write in row order, 55→63 is the priority order.**
55. sales-order-automation-ai-agent — Sales Order Automation: How an AI Agent Turns PO Emails Into ERP Orders → `sap-email-agent.html` | US | Head of Sales Ops | Email → SAP/ERP | evidence: sales order automation (us, 390, KD14, 2026-09-25, R3-us-2); sales order automation software (us, 260, KD10, 2026-09-25, R3-us-2); automated sales order entry (us, 110, KD13, 2026-09-25, C-us-1); sales order automation (uk, 140, KD13, 2026-09-25, R3-uk-2); gestion des commandes clients (fr, 140, KD19, 2026-09-25, R3-fr-1); gestione ordini clienti (it, 140, KD13, 2026-09-25, R3-it-1) — **FR translation must target "gestion des commandes clients" / IT translation must target "gestione ordini clienti"** in title, H1/intro and meta description. Note: "sales order automation" (us) is also logged as a control keyword at 390/KD17 in `industry-ai-agent-keywords-2026-09-26.csv` (evidence CTRL-us-1) — same keyword, later capture, KD moved 14→17; both cited for completeness.
    MERGES V2 #5 `email-to-erp-sales-order-entry` (same task) — V2 #5 struck as "MERGED into #55."
56. sales-order-automation-tools-enterprise-erp — Sales Order Automation Tools for Enterprise ERPs: OCR vs AI Agent → `sap-email-agent.html` | US | Head of Sales Ops / IT | Email → ERP | evidence: leading sales order automation tools for enterprise erps (us, 90, KD9, 2026-09-25, C-us-1); sales order automation solutions (us, 140, KD10, 2026-09-25, R3-us-2; UK variant 50, KD n/a, R3-uk-2) — both rows are recorded as competitor-context/off-task in their source CSV, not as a primary "kept" row; write task-anchored (enterprise ERP buyer choosing a tool), not as a keyword-volume post.
57. rfq-automation-manufacturers — RFQ Automation: Answering Quote Requests Before the Buyer Asks a Competitor → `ai-for-manufacturers.html` | US | Head of Sales Ops | Email → CRM/ERP | evidence: rfq automation (us, 140, KD11, 2026-09-25, C-us-2) — competitor-gap row (goautonomous.io), recorded as off-task/context in source CSV; write task-anchored. Checked V2 #12 `quote-follow-up-automation-b2b` for overlap: different task (RFQ automation answers an inbound quote request before it's sent; #12 follows up on a quote already sent) — no merge, V2 #12 unchanged.
58. automate-customer-service-premium-brands — How to Automate Customer Service for a Premium Brand Without Losing the Tone → `industries/index.html` | US | Head of Customer Experience | Email/WhatsApp/voice → Shopify/CRM | evidence: automate customer service (us, 260, KD9, 2026-09-25, R3-us-26); conversational customer service (us, 140, KD19, 2026-09-25, C-us-4); shopify ai customer service (us, 90, KD37, 2026-09-25, R3-us-23); automatisation service client (fr, 260, KD23, 2026-09-25, R3-fr-27) — **FR translation must target "automatisation service client"** in title, H1/intro and meta description.
59. ai-for-real-estate-leads — AI for Real Estate Leads: Qualifying Enquiries Before Your Sales Team Calls → `industries/real-estate-ai-agents.html` | US | Head of Sales (developer/brokerage) | WhatsApp/voice → CRM | evidence: ai for real estate leads (us, 210, KD25, 2026-09-25, D-us-3); ai lead generation real estate (us, 260, KD22, 2026-09-25, D-us-3); chatbot for real estate agents (us, 110, KD27, 2026-09-25, D-us-2) — link the existing `lead-response-time-study` post.
60. real-estate-ai-chatbot-vs-voice-agent — AI Chatbot vs AI Voice Agent for Real Estate Developers → destination = the new real estate AI chatbot page being built in parallel; use `industries/real-estate-ai-agents.html` now, switch destination to the new chatbot page once live | US + India | Head of Sales | WhatsApp/voice → CRM | evidence: real estate chatbot (us, 390, KD19, 2026-09-25, D-us-2); real estate chatbot (in, 390, KD24, 2026-09-25, RT-in-1 — round-2 zero overturned); ai chatbot for real estate (us, 170, KD26, 2026-09-25, D-us-2).
61. whatsapp-chatbot-enterprise-india — WhatsApp Chatbot for Enterprises in India: When It Must Update Your ERP or CRM → `whatsapp-donna-agents.html` | India | Head of Sales Ops / CX | WhatsApp → ERP/CRM | evidence: whatsapp chatbot (in, 4400, KD41, 2026-09-25, C-in-1); whatsapp automation tool (in, 880, KD12, 2026-09-25, R3-in-38); whatsapp crm (in, 1900, KD33, 2026-09-25, C-in-1) — frame for enterprise buyers; the head term also draws small businesses (source CSV flags "whatsapp chatbot" itself as off-task/consumer-leaning; don't target that exact head term in title/H1, use it only as topical context).
62. erp-automation-ai-agent-tasks — ERP Automation: Which Tasks an AI Agent Can Take Off Your Team → `ai-for-manufacturers.html` | US + UK | Operations/ERP owner | ERP | evidence: erp automation (us, 480, KD24, 2026-09-25, R3-us-5); erp automation (uk, 140, KD28, 2026-09-25, R3-uk-5) — **caution:** source CSV flags "erp automation" (us) as "rajsuyash.com candidate - generic ERP definition"; this row only passes the buyer-intent rule above if written strictly task-anchored (which tasks, which buyer, which system) and never as a generic "what is ERP automation" definitional piece — if it drifts definitional, move it to rajsuyash.com instead.
63. best-ai-agents-solar-companies — Best AI Agents for Solar Energy Companies (Installers and EPCs) → `industries/solar-ai-agents.html` | US | Head of Sales (installer/EPC) | WhatsApp/voice → CRM | evidence: best ai agents for solar energy companies (us, 40, KD n/a, 2026-09-26, E-us-sol-11) — **thin**. SERP for this term shows solarVis with a dedicated "AI Sales Agent for Solar Installers" landing page, plus LuMay AI, Aurora Solar, OpenSolar, Glint Solar, TFSF Ventures blog, Fieldproxy — be fair and factual in the comparison, cite only what each competitor's public page states, no invented competitor claims.

**Move-candidate note (2026-09-25, historical):** `SEO VOXDONNA/r-to-v-move-candidates-2026-09-25.md` lists 27 rajsuyash.com posts already covering the consumer/premium/DTC/specialty-retail/outdoor-living/home-garden cluster as move candidates. This note applied to the now-retired rows #49–54; it does not constrain the buyer-intent queue #55–63, which targets B2B/enterprise buyer phrases, not consumer/DTC ones.

## Niche-gate review (2026-09-25)
V1–V4 are cross-industry task/category pillars; per the niche gate above they stay in the queue, but any worked example they use from here on must be drawn from the eight industries. No entry in the V1–V6 queue names hospitality, healthcare, HVAC/plumbing or generic e-commerce — nothing there is marked out-of-niche as a result. The already-published posts `ai-automation-hvac-plumbing`, `ai-receptionist-hospitality-case-study`, `ai-voice-agent-hospitality-wellness-bookings`, `healthcare-front-office-ai-case-studies`, `missed-calls-home-services` and `ai-voice-agent-ecommerce-2026-guide` predate the niche decision; they are out of scope for this queue review and are noted here for awareness only, not edited or retracted. V5 is the pillar this decision changes, and it is rewritten above into the eight-industry queue (the eighth industry, premium consumer brands, is documented separately in its own subsection above — filled 2026-09-25 with rows #49–54).

## V6 · Voice as a capability (was C2 — exhausted, reopen only on evidence)
Every 2026-07 C2 topic is now covered. Do not open a new voice topic unless it (a) passes the task-anchor rule and (b) the channel-balance count allows it. Voice benchmarks and voice pricing research belong to rajsuyash.com (§B clusters 7 and 8).

## Retired pillars — do not write
- **C1** AI Automation Education → rajsuyash.com (2026-09-19)
- **C3** Industry Research roundups → rajsuyash.com (2026-09-19)
- **C5** Practical Frameworks → rajsuyash.com (2026-09-19)
- **C6** Common Mistakes → rajsuyash.com (2026-09-19)
- **C7** Future Trends → rajsuyash.com (2026-09-22). Uncovered slug `agentic-ai-enterprise-2027-outlook` and `autonomous-ai-agents-enterprise-readiness` are dropped, not migrated.
- **C8** Behind the Scenes — closed; `building-voice-agent-lessons` shipped and the promotional cap makes a second one unjustified.

**Cadence (decided 2026-09-22):** Tue/Thu/Sat stays. The queue below holds roughly nine weeks at that rate, landing on the plan's 8–12 week review. Revisit then with evidence, not before.

## Niche decision (resolved 2026-09-25)
The commercial niche is **selected**: enterprise clients in the US, EU and India across the eight industries named at the top of this file. This was an owner decision taken ahead of the Phase 1 per-market research in `voxdonna-seo-implementation-plan.md` §5, so that research now validates demand and sequences the eight industries rather than choosing among them. Spread posts across the eight industries per the market rule above, and never state a keyword volume in a post.
