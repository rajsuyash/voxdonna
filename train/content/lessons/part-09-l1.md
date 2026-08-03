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
