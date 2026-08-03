# Part 9: Real Enterprise Use Cases

### Choosing Where to Start: The Compute/Governance Gradient

Before you adopt any of the fifteen playbooks in this chapter, you need a selection framework. Claude's plan tiers — Free, Pro, Max, Team, and Enterprise — follow what this guide calls the **compute/governance gradient**: as you move up the ladder you gain larger context windows (200K tokens on consumer plans versus 1M tokens standard on 5-series models), more capable models, and progressively stronger governance controls such as SSO/SAML, SCIM provisioning, role-based access control (RBAC), audit logs, and the Compliance API (Anthropic Docs, Jul 2026). The practical rule: match each use case to three variables — **task type** (drafting, analysis, coding, or research), **context size** (a 20-page brief fits anywhere; a 900-page contract corpus needs the 1M-token tier), and **governance needs** (regulated data requires Team or Enterprise with retention controls and audit logging). Every playbook below names the features it uses — Projects, Artifacts, connectors, Research, Claude Code, and code execution — so you can slot it onto that gradient. Start with low-risk, high-volume workflows, prove value, then escalate to governed, high-context use cases.

---

### 7.1 Product Managers

**Business problem.** Product managers drown in scattered inputs: customer feedback in Intercom, tickets in Jira and Linear, specs in Confluence or Notion, meeting notes in Slack. Synthesizing a roadmap or writing a PRD means days of manual aggregation.

**Claude workflow.** Create a Project (GA, Pro and above) loaded with your product strategy docs, persona definitions, and past PRDs as project knowledge; Projects auto-expand capacity via RAG mode when the knowledge base exceeds the 200K context window (Anthropic Docs). Connect Jira, Confluence, Linear, and Intercom via connectors (remote MCP servers) so Claude reads live boards and conversation history. Use Research (GA) for competitive scans across the web and your connected apps, then draft the PRD as an Artifact for iterative editing with stakeholders.

**Example prompts:**

```text
Pull the last 30 days of Intercom conversations tagged "billing" and the
open Jira tickets in project PAY. Group the top 5 pain themes, cite ticket
IDs, and propose which two belong in next quarter's roadmap.
```

```text
Draft a PRD for the usage-based billing feature using the template in this
Project's knowledge. Include success metrics and open questions.
```

**Expected outputs.** A themed pain-point digest with citations, a structured PRD draft, and a competitive research report with sources.

**ROI framing.** The value is compressed synthesis time: hours of cross-tool reading collapse into one governed conversation, and PRD quality improves because Claude grounds every claim in actual tickets and conversations rather than memory.

**Best practices.** Keep the Project's custom instructions at the "right altitude" — your PRD format and norms, not brittle step-by-step rules (Anthropic Engineering, Sept 2025). Give connector prompts explicit tool boundaries ("only read, never create Jira items") so approval prompts stay meaningful. Verify connector write surfaces in-product; several (Notion, Google) expanded during 2026 and capability listings change (Anthropic Connectors Directory, Jul 2026).

---

### 7.2 Software Engineers

**Business problem.** Engineering teams lose velocity to context-switching: reproducing bugs, writing tests, reviewing pull requests, and navigating unfamiliar legacy code.

**Claude workflow.** Use Claude Code (GA since 2025-05-22) in the terminal, VS Code, JetBrains, or web/mobile. Anchor each repo with a `CLAUDE.md` file describing build commands, conventions, and architecture; Claude Code loads it up front and retrieves everything else just-in-time with glob/grep — Anthropic's recommended hybrid context strategy (Anthropic Engineering, Sept 2025). Add MCP servers (GitHub, Sentry, Linear) so the agent can read issues, stack traces, and PRs. Use subagents for parallel exploration of large codebases and hooks to enforce lint/test gates. For CI, run Claude Code in GitHub Actions.

**Example prompts:**

```text
A customer reports intermittent 500s on /api/checkout since the 2.14 release.
Reproduce from the Sentry trace, identify the regression, write a failing
test, then fix it. Only make changes that are directly requested.
```

```text
Review the diff on this branch against CLAUDE.md conventions. Flag security
issues first, then correctness, then style. Do not speculate about code you
have not opened.
```

**Expected outputs.** Failing-test-plus-fix patches, convention-aware reviews, release notes generated from Linear tickets.

**ROI framing.** Claude leads SWE-bench (~97% on Opus 5, third-party benchmark — verify current figures) and enterprise coding spend (Anthropic/industry reports, 2026); observed average usage runs about $13/developer/day (as of August 2026 — verify against current Anthropic documentation). The return shows up as shorter bug-reproduction cycles and review coverage on every PR, not just the important ones.

**Best practices.** Write tests first in one context window and use git for state tracking across sessions (Anthropic Docs). Damp over-engineering explicitly. Instruct Claude to read files before proposing edits. Use `xhigh` effort for agentic coding on 4.7+/5-series models (Anthropic Docs, 2026).

---

### 7.3 Data Scientists

**Business problem.** Analysts and data scientists spend most of their time on data wrangling — cleaning CSV/XLSX exports, joining sources, and producing one-off charts — rather than on modeling and interpretation.

**Claude workflow.** Upload datasets directly (CSV, XLSX, JSON; chat uploads up to 500MB per file as of 2026 — note this was recently raised from 30MB, verify current limits) and use **code execution / create files** (GA; "create files" labeled feature preview, available on all plans): Claude runs Python with pandas and matplotlib in a sandboxed container to clean, analyze, and chart your data, then delivers downloadable .xlsx/.pdf/.docx outputs. Note the documented boundary: XLSX files **require** code execution to be read reliably. For recurring analysis on live data, connect Stripe, Amplitude, or Hex via connectors, or use Claude Code's just-in-time pattern — writing targeted queries and using `head`/`tail` to inspect large files without loading everything into context (Anthropic Engineering, Sept 2025).

**Example prompts:**

```text
Analyze churn_cohorts.csv. Clean the date columns, compute 3-month retention
by signup cohort, plot a retention heatmap, and give me a one-page PDF
summary of the three most surprising findings.
```

```text
Pull last quarter's subscription metrics from Stripe. Compare MRR growth
against the plan targets in this Project and flag the two largest variances.
```

**Expected outputs.** Cleaned datasets, reproducible analysis code you can inspect, charts, and a formatted report file.

**ROI framing.** The win is analyst leverage: ad-hoc questions that used to queue behind engineering get answered conversationally, and every analysis ships with the code that produced it, so results are auditable and rerunnable.

**Best practices.** Ask Claude to show its cleaning assumptions before analyzing. Keep raw files immutable; have Claude write derived outputs to new files. Remember context rot — for very large datasets, prefer targeted queries over pasting whole tables into the prompt (Anthropic Engineering, Sept 2025).

---

### 7.4 Designers

**Business problem.** Designers need fast translation between ideas and artifacts: flows, wireframe copy, presentation decks, and on-brand visual explorations — often across tools that don't talk to each other.

**Claude workflow.** Combine Artifacts (GA, all plans) with creative connectors. Claude renders React components, SVG, HTML pages, and Mermaid diagrams directly in the side panel, so you can prototype UI states or user-flow diagrams conversationally and iterate in place. The Figma connector (directory connector since Jul 2025; interactive MCP App since Jan 2026) turns text and images into FigJam flow charts, Gantt charts, and diagrams; the Canva connector produces branded presentation decks in real time (Anthropic Connectors Directory, Jul 2026). Note a hard boundary: Claude has **no native raster image generation** — it produces SVG and code-based visuals, and can analyze uploaded images, but does not generate photos or bitmap art (Anthropic Docs, 2026).

**Example prompts:**

```text
Build a clickable React prototype of the three-step onboarding flow: welcome,
role selection, empty-state dashboard. Use our Project's tone for the copy.
```

```text
Turn this launch plan into a FigJam user-journey map with stages, touchpoints,
and pain points flagged in red.
```

**Expected outputs.** An interactive prototype Artifact you can publish and share via link, a FigJam journey map, and a branded Canva deck draft.

**ROI framing.** Design exploration cycles compress from days of mockup rounds to a single working session; stakeholders react to interactive artifacts instead of static descriptions, which surfaces feedback earlier and cheaper.

**Best practices.** Use "Publish" for shareable prototypes, but review what's in an Artifact before publishing — a July 2026 incident briefly allowed published artifacts and shared chats to be indexed by Google before remediation, so treat public links as genuinely public (TechCrunch, Jul 2026). Keep brand tokens and voice rules in a Project so every generated screen starts on-brand.

---

### 7.5 Human Resources

**Business problem.** HR teams manage high-stakes, high-volume documents — policies, handbooks, job descriptions, performance-review cycles — while answering the same employee questions repeatedly and keeping language consistent and compliant.

**Claude workflow.** Build an HR Project whose knowledge base holds your employee handbook, benefits guides, leveling frameworks, and tone guidelines; Projects' RAG expansion handles large policy corpora, and role-based sharing (Private/View/Edit) controls who sees what (Anthropic Docs). Draft and update policies as Artifacts for clean, versionable documents. Use the Google Workspace or Microsoft 365 connectors (first-party) to search Drive/SharePoint for the current version of a policy instead of guessing, and use a Custom Style trained on past HR communications so announcements sound like your company.

**Example prompts:**

```text
Our remote-work policy in Drive was last updated in 2024. Compare it against
the handbook section in this Project, list every inconsistency, and draft a
merged v2 as an Artifact. Flag anything Legal should review.
```

```text
Write the company-wide announcement for the new parental-leave policy: warm,
plain-language, under 250 words, with a FAQ of the five questions employees
will actually ask.
```

**Expected outputs.** A policy gap analysis, a merged policy draft, and an announcement plus FAQ in your house voice.

**ROI framing.** HR reclaims hours per policy cycle and reduces inconsistent-answers risk; employees get one canonical, grounded source instead of stale wiki pages.

**Best practices.** Employee data is sensitive — run this on Team or Enterprise with retention controls, and use Incognito chat for ad-hoc sensitive conversations so sessions aren't saved to history or memory (feature documented on desktop; availability varies — verify). Never paste individual performance or health data into prompts without confirming your org's data-handling policy; Claude does not train on customer data by default, but your internal governance rules still apply (Anthropic Docs, 2026).

---

### 7.6 Recruiters

**Business problem.** Recruiters juggle role intake, candidate screening, outreach personalization, and interview debriefs — all writing-heavy, deadline-driven, and easy to let go generic.

**Claude workflow.** Create a Project per hiring area with your competency models, leveling rubrics, and employer-brand voice as knowledge. Use code execution to analyze exported applicant-tracking CSVs (pipeline conversion by stage, source quality) without touching a spreadsheet. Draft outreach and debriefs as Artifacts; use Research to build candidate-market maps (which companies employ the target profile, what compensation signals exist publicly) with citations. If your org uses Greenhouse/Lever data exports or a CRM connector such as HubSpot, ground prompts in live pipeline data rather than memory.

**Example prompts:**

```text
Here is a hiring-manager intake call transcript. Produce the job description
must-haves vs nice-to-haves, an interview loop with one competency per
interviewer, and three screening questions with rubric anchors.
```

```text
Analyze this ATS export (CSV). Compute stage-by-stage conversion for the
Senior PM req by source, chart it, and tell me which two sources to double
down on and why.
```

**Expected outputs.** Structured intake summaries, calibrated interview plans, conversion analysis with charts, personalized outreach drafts.

**ROI framing.** Time-to-fill pressure eases because screening rubrics and outreach stop being blank-page tasks; pipeline analytics become self-serve instead of a quarterly spreadsheet project.

**Best practices.** Screen prompts for typos and specificity — Anthropic's own tutorial notes models respond to well-formed input (Anthropic tutorial). Keep candidate personally identifiable information minimized in prompts and run recruiting workflows under Enterprise data-retention controls; store rubrics, not candidate dossiers, in Project knowledge.

---

### 7.7 Marketing

**Business problem.** Marketing teams must produce a constant stream of on-brand content — campaigns, emails, landing pages, social — while keeping claims accurate and voice consistent across channels and regions.

**Claude workflow.** Set up a Marketing Project containing brand guidelines, messaging frameworks, approved claims, and past top-performing assets; add a Custom Style built from your best copy so every draft starts on-voice. Use prompt chaining — Anthropic's documented pattern of outline → gate-check against criteria → draft — for long-form assets (Anthropic Engineering, "Building Effective Agents"). Use Research for market and competitor scans with citations, connectors (Google Drive, Slack, Notion) to pull briefs where they live, and Artifacts to iterate landing-page copy or even working HTML/React page mockups. Use code execution to analyze campaign-export CSVs.

**Example prompts:**

```text
Using the messaging framework in this Project, write the launch email sequence
(3 emails) for the Enterprise tier. Gate-check each draft against the approved
claims list before finalizing. Flag any claim not on the list.
```

```text
Analyze Q2 campaign exports (CSV). Rank channels by cost per qualified lead,
chart the trend, and recommend where to shift 20% of budget.
```

**Expected outputs.** On-voice email sequences with claim compliance flags, channel-performance analysis, publishable page prototypes.

**ROI framing.** Content throughput rises without headcount, and the claims gate-check reduces legal review cycles — the expensive part of marketing compliance — because unapproved claims are caught at draft time.

**Best practices.** Tell Claude what TO do stylistically rather than listing prohibitions (Anthropic Docs). Provide 3–5 diverse exemplar assets as few-shot anchors rather than a laundry list of rules. Keep the approved-claims list current in Project knowledge; it is your single source of truth.

---

### 7.8 Finance

**Business problem.** Finance teams reconcile numbers across systems, build board and variance reports, and answer the same "why did this move?" questions monthly — work that is repetitive but intolerant of error.

**Claude workflow.** Upload Excel/CSV exports and use code execution: Claude cleans the data, computes variances, and produces downloadable .xlsx workbooks and .pdf summaries (remember: XLSX input requires code execution). The Stripe connector pulls live subscription, payment, and revenue data; NetSuite appears in the connector ecosystem (Anthropic Connectors Directory, Jul 2026 — verify availability in-product). Build a Finance Project holding your chart of accounts, reporting templates, and last cycle's commentary so each month's narrative starts from context, not scratch. For deeper questions ("what drove the services-margin dip?"), use Research across connected apps and the web.

**Example prompts:**

```text
Here are actuals.xlsx and budget.xlsx. Compute variance by department for
July, flag anything over ±5% with likely drivers from the notes column, and
output a formatted variance workbook plus a one-page PDF summary.
```

```text
Pull July revenue and refund data from Stripe and reconcile it against the
ledger export in this chat. List every unmatched transaction over $500.
```

**Expected outputs.** A variance analysis workbook, reconciliation exception list, and board-ready summary document.

**ROI framing.** Close and reporting cycles shorten, and analyst attention shifts from assembling numbers to explaining them; every figure comes with the code that computed it, which auditors appreciate.

**Best practices.** Always ask Claude to show its reconciliation logic and totals before trusting outputs; treat Claude's arithmetic-through-code as reliable and its mental arithmetic as not. Keep this workflow on Enterprise with data-retention controls and audit logs for financial data (SOC 2 Type II, ISO 27001 certified — Anthropic Docs, 2026). Verify volatile connector scopes and limits against current documentation.

---

### 7.9 Legal

**Business problem.** Legal teams face document volume: contracts to review, playbooks to apply consistently, regulatory changes to track — with zero tolerance for hallucinated citations or missed clauses.

**Claude workflow.** Use a Legal Project with your contract playbooks, fallback positions, and template library as knowledge (up to 500K context on Enterprise, with RAG expansion beyond that). Upload contracts as PDFs — noting the documented boundary: PDFs up to 100 pages get full vision+text analysis; 101–1000 pages are processed text-only (Anthropic Docs, 2026). For multi-document review, structure long inputs with XML document tags and ask Claude to quote relevant passages before analyzing — Anthropic's grounding technique for reducing hallucination on long documents (Anthropic Docs). Use Research to monitor regulatory developments with citations, and Cowork plugins (legal plugins documented in the 2026 plugin ecosystem) for repeatable review workflows.

**Example prompts:**

```text
Review this MSA against the playbook in this Project. First quote each
relevant clause in <scratchpad> tags, then assess: deviation, risk level,
and our standard fallback language. Do not summarize clauses you did not quote.
```

```text
Compare the indemnification and limitation-of-liability clauses across these
three vendor agreements (tagged doc1–doc3). Produce a red-flag table.
```

**Expected outputs.** Clause-by-clause deviation reports grounded in quoted text, cross-agreement comparison tables, regulatory monitoring briefs with citations.

**ROI framing.** First-pass review time per contract drops from hours to minutes of attorney supervision, and playbook consistency stops depending on which reviewer drew the assignment.

**Best practices.** The quote-first grounding step is non-negotiable for legal work. Run on Enterprise with retention controls; privileged material demands your org's strictest governance tier. Claude assists review; it does not replace attorney judgment — build that checkpoint into the workflow explicitly.

---

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
