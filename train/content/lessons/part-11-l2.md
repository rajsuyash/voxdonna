### 9.4 Role Prompting via the `system` Parameter

Setting a role in the system prompt focuses Claude's behavior and tone, and Anthropic's guidance is that "even a single sentence makes a difference" (Anthropic Docs — Prompting best practices):

```python
message = client.messages.create(
    model="claude-opus-5",
    system="You are a helpful coding assistant specializing in Python.",
    messages=[{"role": "user", "content": "..."}],
)
```

The legacy docs phrasing — role prompting turns Claude "from a general assistant into your virtual domain expert" — still describes the effect accurately, though that page now redirects into Anthropic's consolidated "Prompting best practices" reference. Role prompting belongs in the `system` parameter, not the user message, so it persists across turns and doesn't get diluted by user input. Anthropic's interactive tutorial (github.com/anthropics/prompt-eng-interactive-tutorial) dedicates its Chapter 3 to this technique if you want hands-on practice.

---

### 9.5 XML Tags and Delimiters

When a prompt mixes instructions, context, examples, and variable input, wrap each content type in its own XML tag — `<instructions>`, `<context>`, `<input>` — to reduce misinterpretation (Anthropic Docs — Prompting best practices). Best practices:

- Use **consistent, descriptive** tag names throughout a prompt (don't alternate `<data>` and `<input>` for the same thing).
- **Nest tags for hierarchy**: multiple documents go inside `<documents>`, each wrapped in `<document index="1">` with metadata subtags:

```xml
<documents>
  <document index="1">
    <source>Q2-board-deck.pdf</source>
    <document_content>
      ...extracted text...
    </document_content>
  </document>
</documents>
```

This `<document>` structure with `<document_content>` and `<source>` subtags is Anthropic's recommended pattern for long and multi-document prompts. Remember the caveat from §9.2: tags remain recommended, but their rationale increasingly includes human maintainability, not just model parsing.

---

### 9.6 Few-Shot Prompting

Few-shot examples are "one of the most reliable ways to steer Claude's output format, tone, and structure" (Anthropic Docs — Prompting best practices). The current guidance:

- Provide **3–5 examples** for best results. Fewer gives weak signal; more wastes attention budget.
- Make examples **relevant, diverse, and structured** — wrap them in `<example>` tags inside `<examples>`.
- Curate **canonical** examples that portray expected behavior — Anthropic's framing: for an LLM, examples are "the pictures worth a thousand words." Do **not** stuff a laundry list of edge cases into the prompt; edge-case catalogs are a documented failure mode.
- You can ask Claude itself to evaluate your examples for relevance and diversity, or to generate additional ones.

Example skeleton:

```xml
<examples>
  <example>
    <input>Order #8841 arrived damaged; customer wants replacement.</input>
    <output>{"intent": "replacement_request", "sentiment": "negative", "priority": "high"}</output>
  </example>
  <!-- 2-4 more diverse examples -->
</examples>
```

Few-shot composes with thinking: if your examples include reasoning inside `<thinking>` tags, Claude generalizes that reasoning style into its own thinking blocks.

---

### 9.7 Chain-of-Thought in the Adaptive-Thinking Era

This is the section where pre-2026 folklore most actively hurts you.

#### What changed

Current models (Opus 4.7+, Opus 5, Sonnet 5, Fable 5, Mythos 5 — as of August 2026) use **adaptive thinking**: `thinking: {"type": "adaptive"}`, where Claude dynamically decides when and how much to think based on the `effort` parameter and query complexity. Manual extended thinking with `budget_tokens` is deprecated on 4.6 models and **rejected with a 400 error on Claude 4.7+**. Anthropic reports that "in internal evaluations, adaptive thinking reliably drives better performance than extended thinking" (Anthropic Docs — Prompting best practices). On Opus 5, thinking is on by default; disabling it is only allowed at effort `high` or below.

#### Prompting for reasoning, current practice

**Prefer general instructions over prescriptive steps.** Anthropic's guidance is explicit: "A prompt like 'think thoroughly' often produces better reasoning than a hand-written step-by-step plan. Claude's reasoning frequently exceeds what a human would prescribe." Writing a rigid 7-step reasoning procedure into your prompt now constrains a reasoning process that is often better than your script.

**Manual chain-of-thought is a fallback.** When thinking is off (e.g., latency-critical paths), ask Claude to think through the problem and separate reasoning from output with structured tags:

```xml
Work through this problem inside <thinking> tags, then give your final
response inside <answer> tags. Before you finish, verify your answer
against the constraints in <requirements>.
```

**Model-specific nuances (as of August 2026 — verify):** Opus 4.5 with thinking disabled is sensitive to the literal word "think" — use "consider," "evaluate," or "reason through" instead. On Opus 5, explicit verification instructions ("double-check your work") can cause **over-verification**; remove them when migrating prompts from 4.x models.

#### Steering adaptive thinking

Thinking behavior itself is prompt-steerable. To reduce thinking frequency on latency-sensitive paths:

```text
Thinking adds latency and should only be used when it will meaningfully
improve answer quality. When in doubt, respond directly.
```

To guide interleaved thinking in tool-use loops:

```text
After receiving tool results, carefully reflect on their quality and
determine optimal next steps before proceeding.
```

#### Scaling effort to query complexity

Anthropic's multi-agent research post adds a useful companion heuristic for agentic prompts: embed explicit rules that scale effort to complexity rather than applying one intensity everywhere. Their production guidance: simple fact-finding warrants one agent and 3–10 tool calls; comparisons warrant 2–4 subagents and 10–15 calls; genuinely complex research warrants 10+ subagents (Anthropic Engineering Blog — "How we built our multi-agent research system," Jun 2025). The broader principle they state: "instill good heuristics rather than rigid rules" — the same right-altitude lesson as §9.2, applied to delegation. For research-style prompts specifically, Anthropic's docs recommend a structured pattern: search in a structured way, develop several competing hypotheses as you gather data, track confidence levels in progress notes, and verify information across multiple sources before concluding.

#### Effort levels

Adaptive thinking is steered primarily by the `effort` parameter (ladder: `low`, `medium`, `high`, `xhigh`, `max`; default `high` on Opus 5/Sonnet 5 in the API and Claude Code). Anthropic's guidance for Opus 4.7+: use `xhigh` for coding/agentic use cases, minimum `high` for intelligence-sensitive work; `max` can overthink. Critically: **if you see shallow reasoning at low effort, raise the effort level rather than trying to prompt around it.** Effort is the control surface; prompting is the seasoning.

---
