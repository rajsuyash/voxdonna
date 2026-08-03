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
