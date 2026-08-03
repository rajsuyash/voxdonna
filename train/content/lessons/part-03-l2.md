### 3. Speed vs. Intelligence: The Core Tradeoff

Anthropic publishes an official latency ladder, and it is exactly inverse to the capability ladder (Anthropic Docs, Aug 2026):

**Latency (fastest → slowest):** Haiku 4.5 → Sonnet 5 → Opus 5 → Fable 5
**Capability (highest → lowest):** Fable 5 → Opus 5 → Sonnet 5 → Haiku 4.5

The practical translation:

- **Haiku 4.5** delivers "near-frontier intelligence" at the lowest latency and price. Use it when the task is mechanical and volume is high: classification, extraction, routing, first-pass drafts, autocomplete-style assistance.
- **Sonnet 5** is "the best combination of speed and intelligence" and the correct default for most production workloads. Community routing consensus agrees: start on Sonnet 5, escalate only when the workload proves it needs more (Cosmic JS, Jul 2026 — medium confidence).
- **Opus 5** buys judgment: multi-step agentic coding, ambiguous enterprise reasoning, tasks where a wrong answer costs more than the token bill. Anthropic's own guidance: "If you're unsure which model to use, start with Claude Opus 5 for complex agentic coding and enterprise work" (Anthropic Docs, Aug 2026).
- **Fable 5** is for workloads that need the highest available capability — long-running autonomous agents above all — and where its 2x premium over Opus 5 pays for itself.

One hidden factor in cost comparisons: Claude 4.7+ models and Mythos Preview use a **newer tokenizer that produces roughly 30% more tokens for the same text** (Anthropic Docs — Pricing, Aug 2026). If you are comparing a 4.5-era model's cost-per-task against a 5-series model, measure on your own payloads — headline per-token prices understate the difference.

:::exercise Try it #1: Measure the tradeoff yourself
1. Pick one real task from your workload (e.g., "summarize this 40-page contract into 10 bullet points of obligations").
2. Run the identical prompt through Haiku 4.5, Sonnet 5, and Opus 5 via the API or claude.ai model selector.
3. Record three numbers per model: wall-clock latency, total tokens billed (check `usage` in the API response), and a 1–5 quality score you assign blind.
4. Compute cost = (input tokens × input price + output tokens × output price) / 1,000,000.
5. Ask: did Opus 5's quality delta justify ~2.5x Sonnet's price? That answer, on your data, is your routing policy.
:::

---

### 4. Long-Context Capabilities

Context window is the total amount of text (yours plus the model's reply) a model can consider in one request. As of August 2026:

- **Fable 5, Opus 5, Sonnet 5: 1M tokens.** On Opus 5, 1M is both the default *and* the maximum — there is no smaller variant to configure.
- **Haiku 4.5: 200k tokens.**
- **Consumer plans** (Free/Pro/Max) are listed at 200k context on the official pricing page, though third parties report up to 1M on Sonnet 5 in-app; treat the consumer number as surface-dependent and verify (Anthropic pricing page, Aug 2026 — conflict noted).

Two facts make 1M context economically different from earlier generations. First, there is **no long-context surcharge** on Claude 4.6+ models: "A 900k-token request is billed at the same per-token rate as a 9k-token request" (Anthropic Docs — Pricing, Aug 2026). You pay for tokens, not for window size. Second, maximum output scales with the tier: **128k output tokens** on the 5-series (64k on Haiku 4.5), and the Batch API supports up to 300k output tokens on Opus 5 and Sonnet 5 via the `output-300k-2026-03-24` beta header (Beta).

One million tokens is roughly 750,000 words — several large codebases, a full discovery document set, or months of support tickets. The discipline that matters at this scale is not *whether* it fits, but whether stuffing the window is cheaper and better than retrieval. Anthropic's cost guidance still favors routing and caching over brute-force context: prompt caching cuts repeated input to 0.1x base price on cache reads, and the Batch API takes 50% off both input and output for asynchronous work (Anthropic Docs — Pricing, Aug 2026).

---

### 5. Thinking: Extended vs. Adaptive

"Thinking" is Claude's ability to reason internally before answering. In 2026 the control mechanism changed fundamentally, and this is the breaking change most likely to hit your codebase.

#### The old way: manual extended thinking (deprecated on new models)

On older models you enabled thinking explicitly with a token budget:

```json
"thinking": {"type": "enabled", "budget_tokens": 10000}
```

This manual mode is **deprecated on Claude 4.6 models** and **rejected with a 400 error on Claude 4.7 and later**, including the 5-series and Mythos Preview. It remains supported only where it is the *only* thinking mode: Haiku 4.5, Sonnet 4.5, Opus 4.5, and earlier Claude 4 models. There, `budget_tokens` must be at least 1,024 and less than `max_tokens` (Anthropic Docs — Extended thinking, Aug 2026).

#### The new way: adaptive thinking and the effort ladder

Adaptive thinking (`"type": "adaptive"`) lets the model decide how much to think; you steer it with an **effort** setting rather than a token budget:

```json
"output_config": {"effort": "high"}
```

The effort ladder is: `low` → `medium` → `high` → `xhigh` → `max`. Default is `high` on Opus 5 and Sonnet 5 in the API and in Claude Code. On **Fable 5, adaptive thinking is always on** — you cannot disable it. On **Opus 5, thinking is on by default**, and you may only disable it at effort `high` or below; requesting `thinking: {"type": "disabled"}` at `xhigh` or `max` returns a 400 error — a breaking change versus Opus 4.8 (Anthropic release notes, Jul 2026 — medium-high confidence). Haiku 4.5 has no adaptive thinking at all.

#### Parameter deprecations that ride along

On Claude 4.7+ models and Mythos Preview, setting `temperature`, `top_p`, or `top_k` to non-default values returns a 400 error (Anthropic Docs — Model deprecations, Aug 2026). Steering randomness is replaced by steering effort. **Migration checklist:**

1. Remove `budget_tokens` / `thinking.type: "enabled"` from any call targeting 4.7+ or 5-series models.
2. Replace with `output_config.effort` at the lowest level that passes your quality bar.
3. Remove non-default `temperature`/`top_p`/`top_k`.
4. Gate any `thinking: "disabled"` calls on Opus 5 to effort ≤ `high`.

---
