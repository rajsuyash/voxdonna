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
