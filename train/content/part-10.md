# Part 10: Advanced Workflows

You already know how to write a good prompt. This chapter teaches you how to assemble prompts, features, and agents into *workflows*: repeatable, multi-step systems that reliably produce professional results. Part A gives you the architectural framework — Anthropic's six agentic workflow patterns — and shows you where each pattern already lives inside Claude's products. Part B applies the framework to eleven professional domains, with recommended setups, example prompts, and the mistakes Anthropic's own documentation warns against.

> **Volatility note:** model names, prices, limits, and feature status labels in this chapter are current as of August 2026 — verify against current Anthropic documentation before teaching or purchasing decisions.

---

### Part A: The Six Agentic Workflow Patterns

Anthropic's engineering post "Building effective agents" (Schluntz & Zhang, Dec 2024) defines the canonical vocabulary for this material. Two definitions matter before anything else:

- A **workflow** is a system where LLMs and tools are orchestrated through *predefined code paths* — you decide the steps in advance.
- An **agent** is a system where the LLM *dynamically directs its own process and tool usage*, deciding for itself what to do next. Anthropic's compact definition: "LLMs autonomously using tools in a loop" (Anthropic Engineering, "Effective context engineering for AI agents," Sep 2025).

The single most important sentence in the entire post is the opening advice: *"When building applications with LLMs, we recommend finding the simplest solution possible, and only increasing complexity when needed. This might mean not building agentic systems at all."* Every pattern below adds capability *and* cost, latency, and failure modes. Start with a single, well-written prompt; graduate to a pattern only when you have a measured reason.

The building block underneath all six patterns is the **augmented LLM**: a model enhanced with retrieval, tools, and memory. In Claude's products, those augmentations are Connectors (remote MCP servers), the memory system, and tool use in Claude Code or the API.

#### Pattern 1: Prompt Chaining

**Definition.** Prompt chaining decomposes a task into a fixed sequence of steps, where each LLM call processes the output of the previous one. You can insert programmatic checks — a "gate" — on any intermediate step, so a bad intermediate output stops the chain instead of corrupting everything downstream (Anthropic Engineering, Dec 2024).

**When to use it.** Use chaining when the task decomposes cleanly into fixed subtasks you can name in advance. The pattern trades latency (several sequential calls) for accuracy (each call is simpler and more focused). Anthropic's canonical examples are writing-centric: generate marketing copy, then translate it; write an outline, gate-check it against criteria, then write the full document.

**Claude product mapping.** You execute prompt chains manually in claude.ai by structuring multi-turn conversations ("First produce the outline. Stop." → review → "Now draft section 1"). In Claude Code, a skill file (`SKILL.md`) encodes the chain as a reusable `/command`, and hooks can act as gates — for example, a `PostToolUse` hook that runs a linter after every edit blocks the chain when checks fail (Anthropic Docs — Claude Code hooks). On the API, chaining is ordinary sequential Messages API calls, with Structured Outputs (GA) guaranteeing machine-checkable handoffs between steps.

#### Pattern 2: Routing

**Definition.** Routing classifies an input and directs it to a specialized follow-up task. "This workflow allows for separation of concerns, and building more specialized prompts. Without this workflow, optimizing for one kind of input can hurt performance on other inputs" (Anthropic Engineering, Dec 2024).

**When to use it.** Use routing when incoming work falls into distinct categories that deserve different handling — different prompts, different tools, or different models. Anthropic's examples: routing support queries by type (billing, refund, technical), and routing easy questions to a smaller, cheaper model while sending hard questions to a frontier model.

**Claude product mapping.** Claude Code subagents are routing made concrete: a custom subagent in `.claude/agents/` has its own system prompt, tool set, and **model** (`sonnet|opus|haiku|fable`), so the main agent can classify work and delegate it — the docs explicitly note you can "control costs by routing tasks to faster, cheaper models like Haiku" (Anthropic Docs — Claude Code sub-agents). In the claude.ai apps, the model picker plus Projects with different custom instructions is the manual equivalent.

#### Pattern 3: Parallelization

**Definition.** Parallelization runs multiple LLM calls simultaneously, in two variations: **sectioning** (split a task into independent subtasks run in parallel) and **voting** (run the same task multiple times for diverse outputs and higher confidence) (Anthropic Engineering, Dec 2024).

**When to use it.** Use sectioning when subtasks are independent — reviewing three documents, analyzing five competitors. Use voting when you need diverse perspectives or a confidence signal, such as evaluating a high-stakes draft several times and comparing verdicts.

**Claude product mapping.** Anthropic's Research feature (GA for Pro/Max/Team/Enterprise) parallelizes subagents that search different sources simultaneously — parallelization cut research time by up to 90% in Anthropic's internal system (Anthropic Engineering, Jun 2025). In Claude Code, background agents (`claude --bg "investigate the flaky test"`), multiple concurrent sessions, and headless fan-out loops (`claude -p` in a shell loop) are the practitioner versions; parallel tool calling is steerable via prompting (Anthropic Docs — Prompting best practices). In chat, you can approximate sectioning by opening one Project chat per subtask.

#### Pattern 4: Orchestrator-Workers

**Definition.** A central LLM "dynamically breaks down tasks, delegates them to worker LLMs, and synthesizes their results." Unlike chaining, the subtasks are *not* known in advance — the orchestrator decides them at runtime (Anthropic Engineering, Dec 2024).

**When to use it.** Use this pattern for complex tasks where you cannot predict the subtasks up front. Anthropic's examples: coding agents that must change an unpredictable set of files, and search tasks that must gather information from an unpredictable set of sources.

**Claude product mapping.** This is literally how **Research** is built (see the Research workflow in Part B): a lead agent plans, spawns specialized subagents, and synthesizes. **Cowork** (GA spring 2026) applies the same architecture to local files, connectors, and browser tasks. In **Claude Code**, the main agent orchestrates subagents natively — "provide well-defined subagent tools and let Claude delegate" (Anthropic Docs — Prompting best practices); agent teams (Experimental) extend this to coordinated multi-session work with a team lead, at roughly 7× the token cost of a standard session.

#### Pattern 5: Evaluator-Optimizer

**Definition.** "One LLM call generates a response while another provides evaluation and feedback in a loop" (Anthropic Engineering, Dec 2024). The generator never sees a human; it iterates against the evaluator's critique.

**When to use it.** Use evaluator-optimizer when two conditions hold: there are *clear evaluation criteria*, and iterative refinement *measurably improves* the output. Anthropic's examples: literary translation and complex search that benefits from multiple rounds. If you cannot articulate what "better" means, the loop has nothing to optimize.

**Claude product mapping.** In Claude Code, the documented **Writer/Reviewer two-session pattern** — one session writes, a fresh session reviews against criteria — is this pattern, and verification skills (`/verify`, `/run`) plus test suites act as the evaluator. Anthropic's guidance that giving Claude "a way to verify its work" is "the single highest-leverage thing you can do" (Anthropic Docs — Best practices) is the evaluator-optimizer principle in one sentence. In chat, you run the loop manually: generate, then ask Claude in a new message to critique its own output against explicit criteria, then regenerate.

#### Pattern 6: Autonomous Agents

**Definition.** Agents are LLMs using tools in a loop: they plan, act, observe environment feedback, and continue until a stopping condition. They are appropriate for open-ended problems where the required steps genuinely cannot be predicted (Anthropic Engineering, Dec 2024).

**When to use it — and the cautions.** Only when the problem is open-ended *and* you can verify results. Anthropic's own warnings: agents are expensive; errors compound in sandboxes; use guardrails, ground-truth testing, and human checkpoints. An autonomous agent without a verification path is a liability, not a feature.

**Claude product mapping.** **Claude Code** is the flagship autonomous agent: "Unlike a chatbot that answers questions and waits, Claude Code can read your files, run commands, make changes, and autonomously work through problems" (Anthropic Docs — Best practices), with checkpoints, permission modes, sandboxing, and hooks as the guardrails. **Cowork** is the no-code equivalent for knowledge work. **Claude Code on the web** (Research Preview) runs autonomous cloud sessions on Anthropic-managed VMs, monitorable from the mobile app.

#### Pattern selection table

| Pattern | Steps known in advance? | Core benefit | Claude product expression |
|---|---|---|---|
| Prompt chaining | Yes | Accuracy via focused steps | Skills, hooks as gates, sequential API calls |
| Routing | Categories known | Specialization; cost control | Subagents with per-agent models; model picker |
| Parallelization | Yes, independent | Speed; diverse perspectives | Research subagents; `--bg`, `-p` fan-out |
| Orchestrator-workers | No | Handles unpredictable decomposition | Research, Cowork, Claude Code subagent orchestration |
| Evaluator-optimizer | Criteria known | Iterative quality gains | Writer/Reviewer pattern, `/verify`, test loops |
| Autonomous agents | No, open-ended | Full automation | Claude Code, Cowork, cloud sessions |

#### Try it

1. Take a task you currently do in one giant prompt (e.g., a monthly report). Rewrite it as a three-step prompt chain: outline → gate-check against a criteria list → draft. Compare quality.
2. Run an evaluator-optimizer loop in chat: generate a 300-word product description, then ask Claude to score it against five criteria you define, then regenerate. Note which criteria actually changed the output.
3. In Claude Code, run the documented explore → plan → implement → commit flow on a small feature, and observe where the orchestrator-workers pattern appears spontaneously (Explore and Plan subagents).

---

### Part B: Eleven Domain Workflows

Each workflow below gives you a recommended setup, copy-paste prompts, best practices, and common mistakes drawn from Anthropic's documented guidance. Model names and plan gates are as of August 2026 — verify.

#### 1. Research

**Recommended setup.** Research feature (GA; Pro/Max/Team/Enterprise) for agentic multi-source investigation with citations; Google Workspace and Slack connectors for internal sources; Opus 5 or Fable 5 for complex synthesis; a Project holding your domain background. On the API/Claude Code, build orchestrator-workers with subagents.

**Why the multi-agent design matters.** Anthropic's production Research system is orchestrator-workers: a lead agent plans and saves its plan to memory, spawns parallel specialized subagents that search iteratively with interleaved thinking, and a citation agent attributes claims. Measured results from Anthropic's own engineering account (Jun 2025):

| Finding | Number |
|---|---|
| Multi-agent vs. single-agent performance on internal research eval | **+90.2%** |
| Research time reduction from parallelization | up to 90% |
| Token usage vs. ordinary chat | **~15×** (agents generally ~4×) |
| Share of performance variance explained by token usage | 80% |
| Task-completion time saved by improving tool descriptions | 40% |

The lesson cuts both ways: multi-agent research is dramatically better *for genuinely broad questions*, and dramatically more expensive. Do not spend 15× tokens on a question one search could answer.

**Anthropic's eight prompting lessons for research agents** (Anthropic Engineering, Jun 2025): (1) think like your agents — simulate the system with the exact prompts and tools in the Console; (2) teach the orchestrator how to delegate — each subagent needs an objective, an output format, tool/source guidance, and clear task boundaries; (3) scale effort to query complexity — one agent and 3–10 tool calls for simple fact-finding, 2–4 subagents and 10–15 calls for comparisons, 10+ subagents for complex research, with these rules embedded in the prompt; (4) tool design is critical — give explicit tool-choice heuristics; (5) let agents improve themselves — current models are effective prompt engineers for their own tools; (6) start wide, then narrow — short broad queries first; (7) guide the thinking process — use thinking as a controllable scratchpad and reflect after tool results; (8) parallel tool calling transforms both speed and performance. The meta-principle: instill good heuristics rather than rigid rules.

**Example prompt.**

```
Search for this information in a structured way. As you gather data, develop
several competing hypotheses. Track your confidence levels in your progress
notes. Verify every key claim against at least two independent sources, and
quote the source passage before relying on it.

Question: How are mid-market US SaaS companies pricing AI features in 2026,
and how has that changed since 2024?

Deliverable: 1,500-word brief with a hypothesis tree, confidence levels per
claim, and inline citations.
```

**Best practices.** Define success criteria before you start; ask Claude to quote relevant passages *before* answering (grounding reduces hallucination on long documents); put long source documents at the top of the prompt and the query at the end — Anthropic measured up to ~30% quality improvement from this ordering (Anthropic Docs — Long context prompting).

**Common mistakes.** (a) Vague research questions that fail the Golden Rule — if a colleague with minimal context would be confused, Claude will be too. (b) Using an agent for a single-fact lookup (cost blowout). (c) Rigid step-by-step scripts instead of heuristics — Anthropic explicitly prefers general instructions because Claude's reasoning often exceeds what a human would prescribe. (d) Trusting single-source claims without cross-verification.

#### 2. Coding

**Recommended setup.** Claude Code (GA; any paid plan) in the terminal or VS Code extension; a `CLAUDE.md` under 200 lines; subagents for investigation; hooks for lint/test gates; effort `xhigh` for agentic coding (Anthropic Docs — Prompting best practices). GitHub Actions integration (GA) for `@claude` PR workflows.

**Example prompts.**

```
read /src/auth and understand how we handle sessions and login
```
```
I want to add Google OAuth. What files need to change? Create a plan.
Then implement the OAuth flow from your plan, write tests for the callback
handler, run the test suite and fix any failures.
```

**Best practices.** Follow the documented four-phase loop: explore → plan → implement → commit. Give Claude a way to verify its work (tests, running app, screenshots) — the single highest-leverage action. `/clear` between unrelated tasks; if you have corrected Claude more than twice, clear and restart with a more specific prompt. Use git for state tracking and let checkpoints (`/rewind`) protect you.

**Common mistakes** (from Anthropic's best-practices and agentic-systems guidance): the *kitchen-sink session* (one endless conversation for everything — context rot degrades recall as tokens grow); *correcting over and over* instead of restarting cleanly; an *over-specified CLAUDE.md* (long files consume context and reduce adherence); the *trust-then-verify gap* (no tests, no review); *infinite exploration*; overengineering — damp it explicitly: "Only make changes that are directly requested"; test-gaming — "Implement a solution that works correctly for all valid inputs, not just the test cases"; and never let Claude speculate about code it has not opened.

#### 3. Writing

**Recommended setup.** Any plan; a Project with your style guide and exemplar pieces in project knowledge; a Custom Style (GA) built from your writing samples; Opus 5 for long-form. Use prompt chaining — the canonical writing workflow.

**Example prompts.**

```
Step 1 of 2. Read the source material in <scratchpad>, then produce a
<outline> for a 1,200-word blog post. Style rules: clear, engaging language;
focus on implications for the reader; avoid copying the source word-for-word.
Stop after the outline.
```
```
Step 2 of 2. The outline is approved. Write the full <blog_post_draft>,
following the outline and style rules exactly.
```

**Best practices.** Chain, don't cram: outline → gate-check against criteria → draft. Provide 3–5 diverse, canonical few-shot examples wrapped in `<example>` tags — one of the most reliable steering techniques (Anthropic Docs — Prompting best practices). Tell Claude what TO do ("smoothly flowing prose paragraphs") rather than what not to do.

**Common mistakes.** Stuffing a laundry list of edge cases into the prompt instead of curated examples; negative-only style instructions; contradictory instructions left unresolved — Claude will try to follow both; and over-verification prompting on Opus 5, where explicit "verify your work" instructions can cause over-verification (remove them when migrating from older models).

#### 4. Product Management

**Recommended setup.** Team or Enterprise; Projects per product with PRDs and roadmaps in knowledge; connectors for Jira, Linear, Slack, Confluence (Connectors are remote MCP servers; Directory GA since Jul 2025); Research for market scans; Artifacts for one-pagers and roadmaps you can share and let colleagues remix.

**Example prompt.**

```
<context>Attached: Q3 roadmap, last 4 sprint retros, top 20 support tickets.</context>
<instructions>
1. Cluster the support tickets by theme with counts.
2. Map each cluster to roadmap items; flag roadmap items no ticket mentions.
3. Recommend three scope changes with a one-paragraph rationale each,
   citing ticket clusters by number.
</instructions>
Deliver as a Markdown artifact.
```

**Best practices.** Keep durable context in the Project rather than re-pasting it; use the analysis/code execution tool (GA, all plans) for ticket-volume math; share PRDs as published Artifacts for comment-driven iteration.

**Common mistakes.** Asking for prioritization without supplying the evidence base (Claude cannot invent your ticket data); skipping the quote-then-analyze grounding step on long backlogs; ignoring file limits — XLSX exports require code execution enabled, and PPTX cannot be *input* at all (Anthropic Docs — file support).

#### 5. Marketing

**Recommended setup.** Pro or Team; a Custom Style per brand voice; a Project with brand guidelines, persona docs, and 3–5 exemplar assets; Google Drive connector for asset libraries; Artifacts for drafts and Mermaid campaign diagrams.

**Example prompt.**

```
<task>Write 5 variants of a launch email for <product>.</task>
<persona>IT directors at 500–2,000-seat companies, skeptical of AI hype.</persona>
<constraints>Max 120 words each; one CTA; no superlatives without proof;
match the voice in <examples>.</constraints>
<examples>[2 approved past emails]</examples>
Then, as a separate step, translate the winning variant into German.
```

**Best practices.** The generate-then-translate chain above is Anthropic's own canonical prompt-chaining example (Anthropic Engineering, Dec 2024). Use evaluator-optimizer for high-stakes assets: define scoring criteria (clarity, on-brand, CTA strength) and loop generate → score → regenerate. Curate canonical examples rather than edge-case lists.

**Common mistakes.** One mega-prompt asking for all channels at once; style instructions phrased as prohibitions; A/B variants with no persona or constraints, which produces interchangeable mush.

#### 6. UX

**Recommended setup.** Figma connector (remote MCP) to pull design context; Artifacts (React/HTML, GA) for interactive prototypes you can publish; image uploads (≤8000px) for screenshot critique — put images *before* text in the prompt and label them (`Image 1:`) so you can reference them; consider a crop/zoom tool for detail inspection, which Anthropic reports gives consistent uplift on image evaluations (Anthropic Docs — Vision).

**Example prompt.**

```
Image 1: [checkout screenshot]  Image 2: [confirmation screenshot]
You are a senior UX reviewer. For each image, quote the specific UI text or
element you are critiquing, then give severity-ranked findings for the
checkout flow against WCAG-minded heuristics. End with the three highest-
impact fixes.
```

**Best practices.** Ground critique in quoted elements before generalizing; iterate on a single Live Artifact prototype rather than regenerating from scratch each round; keep prompts task-focused rather than prescribing a rigid heuristic checklist when the model's judgment suffices.

**Common mistakes.** Text-before-image ordering (weaker results); uploading tiny or blurry screenshots — images under ~200px and illegible text are documented error sources; expecting person identification or exact spatial coordinates, which are known vision limitations.

#### 7. Legal

**Recommended setup.** Team or Enterprise (no training on customer data by default; Enterprise adds data-retention controls, audit logs, and the Compliance API); Projects per matter with 500K Enterprise project context; long-document prompting discipline.

**Example prompt.**

```
<document><source>MSA-v4-final.pdf</source>
<document_content>[contract text]</document_content></document>
<instructions>
1. In <scratchpad>, quote every clause touching liability, indemnification,
   or termination, with section numbers.
2. Then compare quoted clauses against our standard positions (attached) and
   flag deviations in a table: clause, our position, deviation, risk level.
Do not summarize clauses you did not quote.
</instructions>
```

**Best practices.** Quote-first extraction is Anthropic's documented anti-hallucination technique for long documents: extract relevant quotes in `<scratchpad>`, then answer (Anthropic prompt-eng tutorial, Ch. 8). Put documents at the top of the prompt, questions at the end. Wrap multiple documents in `<document>` tags with `<source>` metadata.

**Common mistakes.** Asking for conclusions without the quote step; exceeding the PDF vision limit — PDFs up to 100 pages get vision+text, 101–1000 pages are text-only (as of Aug 2026 — verify); uploading PPTX or ZIP archives, which are not supported inputs; treating Claude's output as legal advice rather than attorney work product support.

#### 8. Sales

**Recommended setup.** Team; Salesforce and HubSpot connectors plus Slack; Projects per account or segment with call notes; memory (GA, all plans since Mar 2026) for your messaging preferences; voice mode (Beta) for talk-through prep.

**Example prompt.**

```
Using the attached call notes and the account record from Salesforce:
1. Summarize the customer's stated pain points in their own words (quote them).
2. Map each pain point to one product capability with a one-line proof point.
3. Draft a 150-word follow-up email: reference their words, one ask, no jargon.
```

**Best practices.** Ground personalization in quoted customer language; keep one Project per major account so context accumulates across touches; use Research for pre-call account briefs on public information.

**Common mistakes.** Generic outreach with no account context (fails the Golden Rule); pasting CRM exports as XLSX without enabling code execution; letting Claude fabricate proof points — supply them or forbid unverified claims explicitly.

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
