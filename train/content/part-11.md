# Part 11: Prompt Engineering Masterclass

Prompting Claude well in 2026 is a different skill than it was even eighteen months ago. The 5-series model family — Claude Opus 5, Sonnet 5, Fable 5, and Mythos 5 (invite-only, Project Glasswing) — thinks adaptively by default, rejects several legacy API parameters, and follows plain instructions far more literally than earlier generations. Much of the prompting folklore you will find in pre-2026 blog posts is now neutral at best and counterproductive at worst. This chapter teaches you Anthropic's current, officially documented prompting guidance from first principles to advanced techniques — and flags, wherever relevant, which older habits to unlearn.

Throughout the chapter, status tags indicate feature availability: (GA), (Beta), (Preview), (Research Preview), (Experimental), (Enterprise only), (Team/Enterprise only). Volatile facts — model availability, parameter support — are marked "as of August 2026 — verify against current Anthropic documentation."

---

### 9.1 Before You Write a Single Prompt

Anthropic's own prompt engineering documentation starts with a prerequisite list, not a technique list. Before you iterate on a prompt, you need three things (Anthropic Docs — Prompting best practices, fetched Aug 2026):

1. **A clear definition of success criteria** for your use case. "Good output" is not a criterion; "extracts all invoice line items with ≥99% field accuracy" is.
2. **A way to empirically test against those criteria** — an eval, even a simple one (a spreadsheet of 20 inputs with expected outputs counts).
3. **A first-draft prompt** you want to improve.

Two implications follow. First, prompt engineering is an iterative, measurement-driven process, not a talent. Second, not every failure is a prompting problem. Sometimes the right fix is a different model, a higher effort level, more context, or a different latency/cost tradeoff. Keep that escape hatch in mind before you spend a week tuning phrasing.

---

### 9.2 Prompt Anatomy

#### The Golden Rule

Anthropic's golden rule of prompt clarity (Anthropic Docs — Prompting best practices):

> Show your prompt to a colleague with minimal context on the task and ask them to follow it. If they'd be confused, Claude will be too.

The mental model Anthropic recommends: Claude is "a brilliant but very new employee" who lacks context on your team's norms, acronyms, file formats, and unwritten rules. Be clear, direct, and specific about the desired output format and constraints. When the order or completeness of steps matters, provide instructions as sequential numbered steps — not as a dense paragraph of prose.

#### The "right altitude" for system prompts

A system prompt (the `system` parameter in the API, or the instructions field in Claude Code, Cowork, and agent products) should sit at the **right altitude**: specific enough to guide behavior reliably, flexible enough to give Claude good heuristics rather than brittle rules (Anthropic Engineering Blog — "Effective context engineering for AI agents," Sept 2025).

Two failure modes bracket the right altitude:

- **Too low (brittle):** hardcoded if-else logic covering every case. These prompts break on any input outside the enumerated cases and become unmaintainable.
- **Too high (vague):** abstract guidance like "be helpful and thorough" that assumes shared context the model does not have.

The target is crisp heuristics: "When a refund request cites a delivery delay, check the order's tracking status first; if the carrier confirms a delay >48h, approve the refund without escalation."

#### Section structure

Anthropic recommends organizing system prompts into **distinct sections**, delineated with XML tags or Markdown headers. A canonical anatomy (Anthropic Engineering Blog, Sept 2025):

```xml
<background_information>
  Who Claude is acting as, the product, the audience, domain facts.
</background_information>

<instructions>
  Core behavioral rules and heuristics.
</instructions>

## Tool guidance
  When to use which tool; decision heuristics between tools.

## Output description
  Format, length, tone, structure of responses.
```

> **Caveat (Medium-confidence nuance):** Anthropic itself notes that "the exact formatting of prompts is likely becoming less important as models become more capable." XML tags and headers remain the recommended practice, but their value is shifting from "the model needs this to parse you" toward human maintainability and unambiguous structure. Don't cargo-cult elaborate tag hierarchies; do keep prompts cleanly sectioned.

#### Try it #1

Take a real system prompt from your work (or write a 5-line one for a support chatbot). Apply the Golden Rule: give it to a colleague unfamiliar with the project and note every question they ask. Then restructure it into the four sections above (`<background_information>`, `<instructions>`, Tool guidance, Output description), resolving each question in the appropriate section. Compare output quality on three fixed test inputs before and after.

---

### 9.3 Context Engineering: The Discipline Around the Prompt

Prompt engineering is what you write. **Context engineering** is everything the model sees. Anthropic defines it as "the natural progression of prompt engineering... the set of strategies for curating and maintaining the optimal set of tokens (information) during LLM inference" — spanning system instructions, tools, MCP data, external documents, and message history (Anthropic Engineering Blog, Sept 2025).

The core principle:

> Find the smallest possible set of high-signal tokens that maximizes the likelihood of the desired outcome.

#### Context rot

Bigger context is not free. Because attention is computed pairwise across tokens, models have a finite **attention budget**. Anthropic cites needle-in-a-haystack research showing **context rot**: as the number of tokens in the context window increases, the model's ability to accurately recall information from that context decreases — even on models with a 1M-token window (standard on 5-series models; 200k on Haiku 4.5 and consumer plans, as of August 2026).

Practical consequences: deduplicate retrieved passages, prune stale tool results, and prefer one authoritative excerpt over five redundant ones. Treat every token as spending from a budget with diminishing marginal returns.

#### Three long-horizon techniques

For work that exceeds what fits comfortably in one window, Anthropic documents three patterns (Anthropic Engineering Blog, Sept 2025):

1. **Compaction.** When nearing the context limit, summarize the conversation history and restart with the distilled summary. Anthropic recommends tuning the compaction prompt for **recall first** (lose nothing important), then for precision. Note the counterintuitive finding from multi-window agentic work: starting a brand-new context window with filesystem state discovery can beat compaction for coding agents.
2. **Structured note-taking (agentic memory).** The agent maintains persistent notes outside the context window — e.g., a `NOTES.md` file, or the memory tool released in public beta alongside Sonnet 4.5 (Beta) — and re-reads them as needed.
3. **Sub-agent architectures.** Specialized subagents explore with clean, focused contexts and return distilled summaries (Anthropic's research system targets roughly 1,000–2,000 tokens back to the orchestrator). The main context stays high-signal.

#### Just-in-time retrieval

Rather than pre-loading everything into the prompt, give the model **lightweight identifiers** — file paths, stored queries, links — and let it retrieve content when needed (**progressive disclosure**). Claude Code's hybrid pattern is the reference implementation: a `CLAUDE.md` file provides durable, up-front context, while glob/grep and targeted queries pull specifics just-in-time. For data analysis, the same pattern means the model writes targeted queries and uses `head`/`tail` on results "without ever loading the full data objects into context" (Anthropic Engineering Blog, Sept 2025).

---

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

### 9.8 Structured Output Techniques

**Prefilled assistant responses are no longer supported starting with Claude 4.6 models** — the last-turn prefill trick (seeding `{"` to force JSON) returns a 400 error on current models (Anthropic Docs — Prompting best practices). Migration paths:

| Old technique (≤4.5) | Current practice (4.6+) |
|---|---|
| Prefill `{` to force JSON/YAML | **Structured Outputs** (GA) — enforce schema server-side |
| Prefill to skip preamble | System instruction: "Respond directly without preamble..." |
| Prefill to continue a partial completion | Move the partial text into the user message and ask for continuation |

Older Anthropic pages and third-party guides describing prefill-based "JSON mode" are outdated for current models — treat them as historical.

For general format control, Anthropic's hierarchy (Docs — Prompting best practices):

1. **Tell Claude what TO do, not what not to do.** "Your response should be composed of smoothly flowing prose paragraphs" beats "Do not use markdown."
2. Use **XML format indicators** (`<report>`, `<summary>`) to mark output regions.
3. **Match your prompt style to the desired output style** — a prompt written in terse bullet points invites terse bulleted output.
4. Be detailed about formatting preferences rather than hoping for defaults.

---

### 9.9 Long-Context Prompting

For inputs of 20k+ tokens, Anthropic documents three techniques with measurable effects (Anthropic Docs — Prompting best practices):

1. **Documents first, query last.** Put longform data at the *top* of the prompt, above your query, instructions, and examples. "Queries at the end can improve response quality by up to 30 percent in tests." This is one of the few prompting changes with a published effect size — adopt it everywhere.
2. **Structure with XML tags** using the `<document>`/`<document_content>`/`<source>` pattern from §9.5.
3. **Quote-grounding.** Ask Claude to first quote the relevant parts of the documents (e.g., in `<scratchpad>` tags), then perform the task. Grounding the answer in extracted quotes reduces hallucination on long documents.

> **Caveat (Medium confidence):** An open GitHub issue on Anthropic's tutorial argues the anti-hallucination effect comes from the metacognitive instruction (consider whether the evidence answers the question) rather than evidence-gathering per se. Anthropic has not resolved the dispute; the combined quote-then-answer pattern remains the official recommendation.

For multi-window workflows (large agentic coding tasks): use the first window for framework setup (tests, init scripts), have the model write tests in structured formats, use git for state tracking, and provide verification tools (e.g., a browser-testing MCP server).

A worked long-context skeleton, combining all three techniques:

```xml
<documents>
  <document index="1">
    <source>vendor-contract-2026.pdf</source>
    <document_content>...</document_content>
  </document>
</documents>

<instructions>
  First, inside <scratchpad> tags, quote the exact passages relevant to the
  question below. Then answer based only on those quotes, citing the document
  index for each claim.
</instructions>

<question>What liability caps apply to data breaches under this contract?</question>
```

Note the ordering: documents at the top, the actual query at the very bottom — the single change associated with the up-to-30% quality gain.

---

### 9.10 The Prompt Generator and Metaprompt

You don't have to write structured prompts by hand. Anthropic's **prompt generator** in the Console Dashboard ("Generate a Prompt") converts a plain-language task description into a structured, XML-tagged prompt — typically producing a skeleton with `<scratchpad>` reasoning space, an `<outline>` stage, and a full draft section with explicit style rules for long-form writing. Treat the output as a first draft you edit, not a finished artifact.

For programmatic use, Anthropic maintains a **metaprompt notebook** (`misc/metaprompt.ipynb`) in the anthropic-cookbook GitHub repo, alongside `generate_test_cases.ipynb` and `prompt_caching.ipynb` — a "prompt that writes prompts" plus the eval scaffolding to test them.

> **Confidence note (Medium-High):** the cookbook notebook paths are indexed from repository documentation rather than fetched line-by-line; the Console prompt generator itself is High confidence. Verify exact notebook filenames against the current repo if you build a course exercise on them.

Two craft details from Anthropic's interactive tutorial are worth institutionalizing when you use generated prompts: scrub prompts for typos (small details matter — Claude is, in the tutorial's phrasing, "smarter when you sound smart"), and beware ordering bias — when you offer Claude two options in a prompt, it is more likely to pick the second. Audit generated prompts for accidental option-ordering before shipping them.

---

### 9.11 Prompt Libraries and Reusable Templates

Anthropic's Prompt Library (docs.anthropic.com/en/prompt-library/library) contains dozens of optimized prompts across work and play categories (Website Wizard, Excel Expert, Lesson Planner, and so on), each split into a **System** and **User** prompt — itself a lesson in template anatomy. A well-built reusable template has:

1. **A system prompt** holding role, stable instructions, and output contract.
2. **A user template** with clearly marked variable slots (`{{customer_message}}`) wrapped in XML tags.
3. **3–5 canonical few-shot examples** demonstrating the contract.
4. **An eval set** — the inputs and expected outputs that define "working."

Store templates in version control, treat changes like code changes, and re-run the eval set after any model upgrade — the 4.x → 5-series migration changed how several instructions behave (see §9.13).

#### Try it #2

Pick one prompt from Anthropic's Prompt Library closest to your team's work. Run it as-is on three real inputs, then rewrite it as a reusable template with the four-part anatomy above. Where the library prompt conflicts with current 5-series guidance (e.g., prescriptive step-by-step reasoning), modernize it and note the difference in output.

---

### 9.12 Vision Prompting

Claude's single most important vision rule (Anthropic Docs — Vision, fetched Aug 2026):

> Claude works best when images come before text.

Place the image(s) ahead of your question — the visual analogue of "documents first, query last." For multiple images in one request, label each (`Image 1:`, `Image 2:`) so you can reference them by name in the prompt and follow-ups.

Quality and limits (as of August 2026 — verify): images up to 8000×8000 px; ~28×28 px per visual token; up to 100 images per request on 200k-context models (600 on others). Ensure text in images is legible — automatic resizing and lossy JPEG/WebP compression can silently degrade it, so inspect the actual images sent. Known limitations: no person identification, approximate spatial coordinates and counting, errors on low-quality, rotated, or sub-200px images. For detail-heavy work, giving Claude a **crop tool** to zoom into regions shows "consistent uplift on image evaluations," with a published cookbook recipe.

---

### 9.13 The 12 Most Common Prompt Mistakes (and the 5-Series Myth Table)

Anthropic's documentation and engineering blog collectively flag a dozen recurring failure modes. Each below is stated with its fix.

1. **Vague, under-specified prompts.** Fails the Golden Rule. Fix: specificity about output, constraints, and audience.
2. **Negative instructions.** "Do not use markdown" → "Write smoothly flowing prose paragraphs." Tell Claude what *to* do.
3. **Bloated tool sets with ambiguous decision points.** "If a human engineer can't definitively say which tool should be used, an AI agent can't be expected to do better." Fix: prune tools, add explicit tool-choice heuristics.
4. **Laundry lists of edge-case examples.** Fix: 3–5 diverse canonical examples.
5. **Brittle hardcoded if-else logic in system prompts.** Fix: right-altitude heuristics.
6. **Overly vague system prompts.** The opposite altitude failure. Fix: concrete behavioral guidance.
7. **Contradictory instructions left unresolved.** Claude will try to follow both. Fix: audit for conflicts; state precedence explicitly.
8. **Aggressive trigger language.** "CRITICAL: You MUST ALWAYS use tool X..." causes over-triggering on newer models. Fix: calm, conditional heuristics.
9. **Legacy anti-laziness prompting.** Instructions written to stop 3.x/4.x models from under-triggering or under-thinking cause over-triggering and overthinking on 4.6+/5-series. Fix: delete them; raise effort instead.
10. **Overengineering (agentic coding).** Anthropic ships sample prompts against it: "Avoid over-engineering. Only make changes that are directly requested..." Fix: scope instructions explicitly.
11. **Test-gaming / hardcoding.** Fix: "Implement a solution that works correctly for all valid inputs, not just the test cases."
12. **Speculating about unseen code.** Fix: "Never speculate about code you have not opened" — require reading before editing.

#### Myth vs. current practice

Much pre-2026 prompting folklore is now counterproductive on 5-series models. Use this table when migrating old prompts or reviewing inherited ones:

| Pre-2026 folklore | Current practice (5-series, as of Aug 2026) |
|---|---|
| Hand-write a detailed step-by-step reasoning plan into the prompt | "Think thoroughly" — general instructions beat prescriptive steps; Claude's reasoning exceeds human scripts |
| Prefill the assistant turn (`{"`) to force JSON | Structured Outputs (GA); prefill returns 400 on 4.6+ |
| Tune `budget_tokens` for thinking, "start minimal and increase" | Adaptive thinking + `effort` ladder; `budget_tokens` returns 400 on 4.7+ |
| Add "double-check your answer" everywhere | Causes over-verification on Opus 5; remove when migrating |
| Use "CRITICAL/MUST/ALWAYS" to force tool use | Causes over-triggering; use conditional heuristics |
| Anti-laziness prompts ("don't be lazy, write the full file") | Causes overthinking on current models; raise effort instead |
| Disable thinking and prompt manual CoT for hard tasks | Keep adaptive thinking on at effort `high`/`xhigh`; manual CoT is the fallback, not the default |
| Elaborate prompt formatting is load-bearing | Formatting matters less as models improve; structure prompts for clarity and maintainability |

#### Try it #3

Find a prompt in your organization written before 2026 (or write one using the folklore column above: step-by-step reasoning script, CRITICAL language, "double-check" instructions). Run it on five test inputs with a 5-series model at default effort. Then apply the migration table: delete legacy instructions, switch reasoning to "think thoroughly," and set effort to `high` or `xhigh`. Re-run and compare — most teams see the simplified prompt match or beat the original while being a third of the length.

---

### 9.14 Chapter Summary

Prompt engineering for current Claude models reduces to a few durable disciplines: define success criteria and evals before tuning; write clear, right-altitude system prompts in clean sections; treat context as a finite budget and engineer it deliberately (compaction, note-taking, subagents, just-in-time retrieval); use roles, XML structure, 3–5 canonical examples, and quote-grounding; put documents and images before questions; and — above all — prompt for the adaptive-thinking era. General reasoning instructions, the effort ladder, and Structured Outputs replace the step-by-step scripts, budget tuning, and prefill tricks of the pre-2026 playbook. When in doubt, simplify the prompt and raise the effort.


---
