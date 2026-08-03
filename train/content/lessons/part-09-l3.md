### 7.10 Operations

**Business problem.** Operations teams keep the machine running: SOPs, vendor coordination, process documentation, and incident follow-ups — knowledge work scattered across tools and people's heads.

**Claude workflow.** Centralize SOPs and process docs in an Operations Project so answers come from your canonical documents, not folklore. Use connectors to where work actually happens — Slack for incident threads, Asana or monday.com (interactive MCP Apps since Jan 2026) for task boards, Jira for issue tracking, Box or Drive for documents. Use Routines (Claude Code Routines, Research Preview — daily caps of 5/Pro, 15/Max, 25/Team-Enterprise, as of August 2026, may change) or Cowork Scheduled Tasks for recurring work like weekly status digests; note Cowork scheduled tasks require the desktop app open and machine awake. Use code execution for operational metrics (cycle times, SLA adherence) from exported CSVs.

**Example prompts:**

```text
Every Monday: summarize last week's incident threads in #ops-incidents, group
by root cause, list open follow-ups from Asana, and draft the weekly ops
digest as an Artifact.
```

```text
Analyze fulfillment_export.csv: median and p95 cycle time by warehouse,
weekly trend chart, and the three orders furthest outside SLA with reasons
from the notes field.
```

**Expected outputs.** Automated weekly digests, SLA/cycle-time analyses with charts, SOP drafts consistent with existing documentation.

**ROI framing.** Recurring reporting stops consuming analyst hours each week; SOP consistency improves because updates propagate from one knowledge base instead of scattered docs.

**Best practices.** Routines are a Research Preview with documented quirks (including a reported multi-execution bug) — monitor scheduled outputs rather than assuming they ran correctly. Keep SOP knowledge files versioned and dated. For scheduled tasks, confirm run status in the Scheduled sidebar page (Anthropic Docs, 2026).

---

### 7.11 Executives

**Business problem.** Executives need decision-grade synthesis fast: board materials, market scans, and cross-functional status — but the raw material lives in other people's decks, inboxes, and dashboards.

**Claude workflow.** Use Research (GA on Pro and above) for cited, multi-source market and competitive briefings produced in minutes rather than analyst-days. Connect Google Workspace or Microsoft 365 so Claude can search your Drive/SharePoint, email, and calendar context — with the Gmail caveat that Claude creates drafts but cannot send email on your behalf (Anthropic Docs). Use a Project containing your strategy documents and board templates so generated materials match your format; deliver board narratives as Artifacts or downloadable .docx/.pdf via create files. Memory (GA, all plans since Mar 2026) retains your preferences for format and depth across sessions.

**Example prompts:**

```text
Research the current state of [adjacent market]: size estimates with sources,
the four most credible entrants in the last 18 months, and the strongest
argument for and against us entering. Cite everything; flag anything you
could not verify across two sources.
```

```text
Here are the five department updates in this Project. Produce a two-page
board pre-read: one paragraph per department, three cross-cutting risks, and
two decisions I need the board to make.
```

**Expected outputs.** Cited market briefings, consolidated pre-reads, decision memos in your house format.

**ROI framing.** The scarcest resource in the company — executive attention — stops being spent on assembly; briefing quality rises because every claim arrives with a source you can check.

**Best practices.** Ask Research to track confidence and verify claims across multiple sources (Anthropic's documented research prompting pattern). For sensitive strategy work, confirm your Enterprise retention settings and prefer Incognito for exploratory conversations. Treat cited figures as starting points for verification on market-moving decisions.

---

### 7.12 Consultants

**Business problem.** Consultants live on rapid context acquisition: a new client's industry, documents, and data every engagement, with deliverables due in weeks, not months.

**Claude workflow.** Create one Project per client engagement — knowledge isolation keeps client contexts separated, and shared Projects with View/Edit permissions let engagement teams collaborate (Team plan). Load client documents, interview notes, and prior deliverables; RAG expansion handles large document sets. Use Research for cited industry scans, code execution to analyze client data exports and build chart-ready workbooks, and Artifacts plus create files to produce polished .docx/.pptx/.pdf deliverables. Cowork (GA spring 2026; Pro/Max/Team Premium/Enterprise) can execute multi-step file workflows on granted local folders — for example, assembling a deliverable from a folder of inputs.

**Example prompts:**

```text
You are a strategy consultant. Using the interview notes and financials in
this Project, build the issue tree for the client's margin decline, then draft
the executive summary (500 words) and a findings deck outline with one chart
per key message.
```

```text
Analyze ops_data.xlsx with code execution: benchmark the client's order cycle
times against the industry ranges in benchmarks.csv and chart the gaps.
```

**Expected outputs.** Issue trees, executive summaries, benchmark analyses with charts, formatted client-ready deliverable files.

**ROI framing.** Engagement ramp-up compresses from weeks to days; junior-heavy leverage models improve because first-draft quality no longer depends on the most senior person in the room.

**Best practices.** Never mix client Projects; confirm your firm's policies on client-confidential data and run engagements under Enterprise retention controls. Ground every client-facing number in the uploaded data via code execution, not model memory. Verify connector and plan details against current documentation as of your engagement date.

---

### 7.13 Customer Support

**Business problem.** Support organizations must resolve tickets quickly and consistently while feeding product teams structured insight from thousands of conversations — two goals that usually compete for the same hours.

**Claude workflow.** Use Anthropic's documented **routing** pattern: classify incoming queries and direct them to specialized handling — simple questions to fast models, complex escalations to deeper analysis (Anthropic Engineering, "Building Effective Agents"). For human agents, a Support Project with your help-center content, macros, and escalation policy turns Claude into a grounded drafting assistant. The Intercom connector (launch partner, May 2025) lets Claude analyze conversation history and feedback patterns; HubSpot reads tickets alongside CRM context. Use code execution on ticket exports for volume/driver analysis, and Research to trace a recurring issue across conversations and connected tools.

**Example prompts:**

```text
Draft a reply to this ticket using only the help-center articles in this
Project. If the article doesn't cover the issue, say so and draft an
escalation summary for Tier 2 instead of improvising.
```

```text
Analyze last month's ticket export: top 10 contact drivers by volume and
average handle time, charted, with the three drivers whose volume grew
fastest month-over-month.
```

**Expected outputs.** Grounded reply drafts with honest escalation flags, driver analysis with charts, feedback digests for product teams.

**ROI framing.** First-response quality and consistency rise while handle time falls; the product team finally gets structured, quantified feedback instead of anecdote.

**Best practices.** The "say so if you don't know" instruction is the single highest-value line in support prompting — it converts hallucination risk into clean escalations. Keep help-center knowledge current; stale macros produce confident, wrong drafts. Never paste unredacted customer PII beyond what your org's policy permits.

---

### 7.14 Sales

**Business problem.** Sales teams lose selling time to account research, CRM hygiene, proposal drafting, and meeting preparation — and personalization at scale is the first casualty.

**Claude workflow.** Connect your CRM: HubSpot (first CRM connector, Jul 2025) reads contacts, companies, deals, and tickets with user permissions intact, and Salesforce connectivity runs through Salesforce Hosted MCP Servers (GA Apr 2026) plus MCP Apps — exact directory-listing status is ambiguous, verify in-product (Anthropic Connectors Directory, 2026). Use Research for cited pre-call account briefings (funding, leadership changes, earnings signals). Build a Sales Project with your pitch decks, pricing guardrails, case studies, and a Custom Style for outreach voice. Zapier's connector (gateway to ~7,000 apps) bridges gaps — e.g., preparing calendar-based meeting briefs. Draft proposals as Artifacts; use memory to retain account context across sessions.

**Example prompts:**

```text
Pull the Acme Corp record from HubSpot: open deals, last three activities,
and open tickets. Then research Acme's last 90 days of news. Combine into a
one-page pre-call brief with three talk tracks tied to their situation.
```

```text
Draft a proposal for the expansion deal using the template in this Project.
Stay inside the pricing guardrails; flag any discount beyond standard terms.
```

**Expected outputs.** Pre-call briefs merging CRM and public signals, compliant proposal drafts, personalized outreach at volume.

**ROI framing.** Reps reclaim research and admin hours for actual selling; proposal turnaround drops from days to hours while pricing discipline is enforced at draft time.

**Best practices.** HubSpot write actions appear in HubSpot's audit log attributed to the user — treat connector writes as if you made them yourself, and use approval gates for anything that modifies CRM records. Keep pricing guardrails as a dated Project file; stale guardrails produce confidently wrong quotes. Note the connector respects your CRM permissions — Claude never sees records you couldn't see yourself (Anthropic Docs).

---

### 7.15 Founders

**Business problem.** Founders do every job in this chapter simultaneously — pitch decks, financial models, product specs, hiring, investor updates — with no staff and no time, and every hour of assembly is an hour not spent with customers.

**Claude workflow.** Run the company out of a small set of Projects: "Fundraising" (deck, model, data-room docs), "Product" (specs, user research), "Operating" (metrics exports, board updates). Use Research for market sizing and competitor scans with citations you can defend in a partner meeting. Use code execution to build and stress-test financial models from your assumptions and to produce investor-ready chart workbooks. Draft the deck narrative as an Artifact and export formatted .pptx/.docx via create files (feature preview). Use Claude Code for the product itself — a founder with Claude Code (~$13/dev/day average usage, as of August 2026 — verify) covers an outsized share of early engineering. Use Cowork (GA spring 2026) to automate multi-step desktop workflows like assembling a data-room folder.

**Example prompts:**

```text
Act as a skeptical seed-stage VC. Here is my deck and market research. Attack
the three weakest assumptions, tell me what evidence would change your mind,
and rewrite the market-size slide using only citable sources.
```

```text
Build an 18-month financial model from these assumptions (CSV): monthly
burn, revenue scenarios at conservative/base/aggressive, runway chart, and a
one-page summary I can paste into the investor update.
```

**Expected outputs.** Stress-tested narratives, defensible market sizing, a working model with scenario charts, formatted investor materials.

**ROI framing.** Founder leverage is the purest form of ROI in this chapter: one person produces analyst-grade research, finance-grade models, and engineer-grade code, compressing the seed-stage team's first hires.

**Best practices.** Assign Claude explicit adversarial roles ("skeptical VC," "hostile diligence analyst") — role prompting materially focuses output quality (Anthropic Docs). Keep each venture domain in its own Project so context stays clean. Verify every market figure before it goes in front of investors; citations in Research outputs make that fast.


---
