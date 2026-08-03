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

:::exercise Try it #1
Take a real system prompt from your work (or write a 5-line one for a support chatbot). Apply the Golden Rule: give it to a colleague unfamiliar with the project and note every question they ask. Then restructure it into the four sections above (`<background_information>`, `<instructions>`, Tool guidance, Output description), resolving each question in the appropriate section. Compare output quality on three fixed test inputs before and after.
:::

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
