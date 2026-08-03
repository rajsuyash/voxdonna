#### 9. Customer Support

**Recommended setup.** Enterprise for governance at scale; routing architecture on the API (classify ticket type → specialized handler prompt); Haiku 4.5 for high-volume classification, Sonnet 5/Opus 5 for complex resolution; Zendesk/Intercom via connector or MCP; Batch API (−50% cost) for offline ticket analytics.

**Example prompt (classifier step of a routing chain).**

```
Classify this ticket into exactly one category: billing, bug, how-to,
feature-request, abuse. Return Structured Output: {category, confidence,
needs_human: true|false}. Escalate to a human when confidence < 0.8 or the
customer mentions legal action.
Ticket: <ticket>...</ticket>
```

**Best practices.** Routing exists precisely because optimizing one prompt for all ticket types degrades each type (Anthropic Engineering, Dec 2024). Use Structured Outputs (GA) for machine-readable handoffs — note that prefilled responses are deprecated on Claude 4.6+ (they now return a 400 error), so migrate any legacy JSON-forcing prefill tricks. Keep tool sets small and unambiguous: "If a human engineer can't definitively say which tool should be used, an AI agent can't be expected to do better" (Anthropic Engineering, Sep 2025).

**Common mistakes.** Legacy "CRITICAL: You MUST…" tool-trigger language, which causes over-triggering on current models; bloated tool menus; skipping the human-escalation gate; and measuring nothing — establish success criteria and empirical tests before tuning prompts (Anthropic Docs — Prompt engineering overview).

#### 10. Data Analysis

**Recommended setup.** Code execution / "create files" (GA, all plans) for CSV/XLSX analysis with downloadable .xlsx/.docx outputs; Claude Code for large datasets on disk; the code execution tool on the API for programmatic pipelines.

**Example prompt (Claude Code, large dataset).**

```
Do not load the full CSV into context. Write targeted queries and use head,
tail, and pandas to profile sales_2026.csv: schema, row count, null rates,
then monthly revenue by region. Store intermediate results to files.
Finish with a matplotlib chart and a 10-line findings summary.
```

**Best practices.** The just-in-time pattern above — query, store results, never load the full data object — is Anthropic's documented approach for large data (Anthropic Engineering, Sep 2025). Ask Claude to write its methodology before running it so you can sanity-check; request verification of surprising numbers against the raw file.

**Common mistakes.** Uploading an XLSX and asking questions without code execution enabled (a top capability-boundary failure); assuming PPTX/ZIP inputs work; trusting aggregates over millions of rows that were never actually computed — require executed code, not estimates; context rot from dumping entire datasets into the prompt.

#### 11. Consulting

**Recommended setup.** Team/Enterprise; one Project per engagement with project knowledge and custom instructions; Research for market scans; connectors for the client's Drive/Slack/Notion where permitted; Artifacts + "create files" for polished deliverables (downloadable .docx/.pptx/.xlsx/.pdf).

**Example prompt.**

```
<engagement>Ops cost diagnostic, 3-week project, logistics client.</engagement>
<materials>[interview notes ×6, cost CSV, org chart]</materials>
Week-1 deliverable: a hypothesis tree for the top 3 cost drivers. For each
hypothesis: supporting evidence (quote the interview line), disconfirming
evidence, confidence level, and the analysis that would settle it.
Format: Markdown artifact, then export the final version as .docx.
```

**Best practices.** The hypothesis-tree structure mirrors Anthropic's documented research prompting pattern and forces evidence-grounded reasoning. Keep engagement memory inside the Project; use evaluator-optimizer passes on executive summaries (criteria: BLUF structure, quantified claims, no hedging). Maintain a hypothesis or research-notes file across long engagements — structured note-taking is Anthropic's recommended long-horizon memory technique (Anthropic Engineering, Sep 2025).

**Common mistakes.** Recommendations with no quoted evidence; one chat for the entire engagement (context rot, mixed threads — use `/clear`-equivalents and separate chats per workstream); publishing artifacts with client-confidential data — remember published Artifacts are public links, and a July 2026 incident briefly made shared links indexable by search engines before remediation (TechCrunch, Jul 2026); and delivering analysis on data Claude never actually computed.

---

### Chapter Summary

The six patterns — chaining, routing, parallelization, orchestrator-workers, evaluator-optimizer, and autonomous agents — are one framework with two faces: they describe how Anthropic builds Claude's own features (Research, Cowork, Claude Code), and they describe how you should structure your own advanced work. Choose the simplest pattern that meets a measured need, give every agent a way to verify its output, and treat context as the finite resource it is. In Part B, the recurring formula across all eleven domains is identical: ground in quoted evidence, decompose into steps, verify against explicit criteria, and respect the documented capability boundaries. Master that formula and the specific setups above become starting points you will quickly outgrow — which is the goal.

#### Capstone exercise

Pick one recurring deliverable in your role. (1) Identify which of the six patterns it naturally uses. (2) Rebuild it as an explicit workflow: setup (model, Project, connectors), a chained prompt sequence, and a verification gate. (3) Run it twice — once naively, once as designed — and compare. Document the difference; that document is the beginning of your team's workflow playbook.


---
