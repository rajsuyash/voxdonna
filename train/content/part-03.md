# Part 3: Claude Models — The Complete Guide

This chapter gives you a complete working knowledge of the Claude model family as it exists today: which models are available, what each costs, how context windows and thinking modes work, where the family came from, and — most importantly — how to pick the right model for a given task, team, and budget. By the end, you will be able to defend a model-selection decision to both an engineer and a CFO.

> **Volatility notice:** model pricing, availability, and benchmark standings in this chapter are accurate as of August 2026. Model economics change frequently — verify against current Anthropic documentation before quoting figures in contracts or budgets.

---

### 1. The Current Model Family

As of August 2026, Anthropic offers four self-serve Claude tiers plus one invitation-only tier. The naming convention is a role name plus a version number: **Haiku** (fastest, cheapest), **Sonnet** (balanced), **Opus** (frontier capability for complex work), and **Fable** (the most capable widely released model). **Mythos** sits at the top but is not self-serve (Anthropic Docs, Aug 2026).

| Model (ID) | Status | Price (input/output per MTok) | Context | Max output | Thinking | Latency | Best for |
|---|---|---|---|---|---|---|---|
| **Claude Fable 5** (`claude-fable-5`) | (GA) | $10 / $50 | 1M | 128k | Adaptive — always on | Slower | Highest-capability workloads; long-running agents |
| **Claude Opus 5** (`claude-opus-5`) | (GA, Jul 24, 2026) | $5 / $25 | 1M (default and maximum) | 128k | Adaptive — on by default | Moderate | Complex agentic coding and enterprise work |
| **Claude Sonnet 5** (`claude-sonnet-5`) | (GA, Jun 30, 2026) | $2 / $10 intro through Aug 31, 2026; $3 / $15 from Sep 1, 2026 | 1M | 128k | Adaptive | Fast | Most production workloads; best speed/intelligence balance |
| **Claude Haiku 4.5** (`claude-haiku-4-5-20251001`) | (GA) | $1 / $5 | 200k | 64k | Manual extended thinking (budget_tokens) | Fastest | High-volume, mechanical tasks; near-frontier intelligence at lowest cost |
| **Claude Mythos 5** (`claude-mythos-5`) | Limited availability — invite-only under Project Glasswing | $10 / $50 | — | — | — | — | Approved customers only; not generally available |

(Anthropic Docs — Models overview and Pricing, fetched Aug 2026)

Key facts to internalize from this table:

- **"MTok" means one million tokens.** A token is roughly three-quarters of an English word; input and output are billed at different rates, with output always more expensive because generation is the computationally costly part.
- **The price ladder is roughly 10x across the family**: Haiku 4.5 at $1/$5, Sonnet 5 at $2–3/$10–15, Opus 5 at $5/$25, Fable 5 at $10/$50. Every step up buys capability, not speed.
- **Opus 5 is the subscriber flagship** — it is the default model on Claude Max and the strongest model on Claude Pro — even though Fable 5 sits above it on the capability ladder (MarkTechPost, Jul 2026).
- **Mythos 5 is invitation-only** under a program called Project Glasswing and has no self-serve access path. If a stakeholder asks for it, the answer is "talk to your Anthropic account team" (Anthropic Docs, Aug 2026).

> **Dated callout:** Sonnet 5's introductory API pricing of $2/$10 per MTok ends **August 31, 2026**. Standard pricing of $3/$15 takes effect September 1, 2026. Any cost model built on intro pricing will underestimate by 50% after that date (Anthropic Docs — Pricing, Aug 2026).

#### Model IDs are pinned snapshots

Every Claude model ID is a pinned snapshot — it always points to the same model weights, never silently changes under you. Starting with the Claude 4.6 generation, IDs use a dateless format (`claude-opus-5`) that is *still* a pinned snapshot, not an evergreen pointer. Pre-4.6 models used dated IDs (`claude-haiku-4-5-20251001`), and short aliases like `claude-haiku-4-5` are convenience pointers to those dated IDs (Anthropic Docs, Aug 2026). In production, pin exact IDs and upgrade deliberately — this is what makes regression testing possible.

---

### 2. Model Evolution: 2025–2026 Timeline

Understanding where the family has been explains why the API behaves the way it does today.

| Date | Event |
|---|---|
| 2025 | Claude 4 generation establishes the Haiku/Sonnet/Opus tiering; Opus 4.1 ships Aug 5, 2025 |
| Jan 5, 2026 | Claude 3 generation (Opus 3, Haiku 3) retires |
| Jun 9, 2026 | **Fable 5 and Mythos 5 launch** |
| Jun 12, 2026 | Fable 5/Mythos 5 suspended by a US government export-control order |
| Jun 15, 2026 | Opus 4 and Sonnet 4 retire on Anthropic platforms (still on Bedrock/Google) |
| Jun 30, 2026 | **Sonnet 5 ships**; becomes default across all claude.ai tiers including Free |
| Jul 1, 2026 | Fable 5 restored globally |
| Jul 24, 2026 | **Opus 5 launches** at $5/$25 — unchanged from Opus 4.8 pricing |
| Aug 5, 2026 | **Opus 4.1 retires** (see §7) |
| Sep 1, 2026 | Sonnet 5 pricing moves from $2/$10 to $3/$15 |

(Fable/Mythos timeline: secondary sources, consistent across 3+ outlets — treat exact dates as medium confidence; model retirements and launches: Anthropic Docs and official release notes, high confidence.)

Two structural shifts matter more than any single date. First, the **4.6 generation introduced adaptive thinking** and began deprecating manual control knobs (see §5). Second, the **5-series standardized 1M-token context**, collapsing what used to be a premium add-on into the default.

#### Earliest retirement windows

Anthropic guarantees at least 60 days' notice before retirement and publishes "not sooner than" availability dates (Anthropic Docs — Model deprecations, Aug 2026):

| Model | Guaranteed available until at least |
|---|---|
| Haiku 4.5 | Oct 15, 2026 |
| Sonnet 5 | Jun 30, 2027 |
| Fable 5 | Jun 9, 2027 |
| Opus 5 | Jul 24, 2027 |

Note that Haiku 4.5's window opens within about two months of this writing — plan for a Haiku 4.6+ or Haiku 5 successor in your Q4 2026 dependency reviews.

---

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

#### Try it #1: Measure the tradeoff yourself

1. Pick one real task from your workload (e.g., "summarize this 40-page contract into 10 bullet points of obligations").
2. Run the identical prompt through Haiku 4.5, Sonnet 5, and Opus 5 via the API or claude.ai model selector.
3. Record three numbers per model: wall-clock latency, total tokens billed (check `usage` in the API response), and a 1–5 quality score you assign blind.
4. Compute cost = (input tokens × input price + output tokens × output price) / 1,000,000.
5. Ask: did Opus 5's quality delta justify ~2.5x Sonnet's price? That answer, on your data, is your routing policy.

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

### 6. Vision Capabilities

All current Claude models accept text plus image input (GA). The limits and economics (Anthropic Docs — Vision, Aug 2026):

| Limit | Value |
|---|---|
| Images per request (API) | 100 for 200k-context models; 600 for all other models |
| Images per message (claude.ai) | 20 |
| Max image size | 8000 × 8000 px; 10 MB/image on API (5 MB on Bedrock/Google) |
| Formats | JPEG, PNG, GIF, WebP (first frame of animations only) |

Image token cost is computed as ⌈width/28⌉ × ⌈height/28⌉ visual tokens. On Claude 4.7 and later, a **high-resolution vision tier** applies automatically: long edge up to 2,576 px and up to 4,784 visual tokens per image, versus the 1,568 px / 1,568-token standard tier on older models.

Know the documented limitations before you design a workflow around vision: Claude cannot name or identify people in images; counting and spatial reasoning are approximate; it cannot detect whether an image is AI-generated; and it must not be used for diagnostic interpretation of medical scans such as CT or MRI (Anthropic Docs — Vision, Aug 2026).

---

### 7. Benchmarks — Read with Care

Benchmark numbers for Claude models vary sharply by harness, scaffold, and date, so every figure below carries its source and a confidence flag. Treat rankings within a few points as noise; boards update monthly.

| Benchmark | Result | Source & date | Confidence |
|---|---|---|---|
| SWE-bench Verified | **Opus 5 97.0%**; GPT-5.6 Sol 96.2%; Fable 5 95.0%; Opus 4.8 88.6% | vals.ai third-party tracker, Jul 31, 2026 | Medium — third-party harness; Anthropic's own numbers differ |
| SWE-bench Verified (internal) | Sonnet 5 82.1% vs Sonnet 4.6 76.4% | Anthropic-reported via secondary blogs, Jul 2026 | Medium-low |
| SWE-bench Pro | Fable 5 80.3%; Opus 5 79.2% | Vendor-reported, Jun–Jul 2026 | Medium-low |
| Artificial Analysis Intelligence Index | Fable 5 ~60 (#1) | Artificial Analysis via secondary, Jul 2026 | Medium |
| Artificial Analysis Coding Agent Index | GPT-5.6 Sol 80 (#1); Fable 5 77 | Artificial Analysis, Jul 2026 | Medium |
| ARC-AGI-3 | Opus 5 30.2% vs GPT-5.6 Sol 7.8% | Anthropic-reported via Decrypt, Jul 2026 | Medium-low |

(Cross-verification rule applied: third-party percentages are presented with attribution; the only Anthropic-official comparison is the latency/capability ordering.)

The honest instructor summary: on the largest third-party coding board (vals.ai SWE-bench Verified), Claude holds the top two spots as of late July 2026, and Opus 5 scores near Fable 5 at half the price — which is precisely why Opus 5, not Fable 5, is the subscriber flagship. Do not build procurement decisions on any single percentage.

---

### 8. Deprecations You Must Act On

- **`claude-opus-4-1-20250805` retires August 5, 2026** — two days after this chapter's research date. It was deprecated June 5, 2026; the designated replacement is `claude-opus-4-8`, and Opus 5 is the strategic target at identical $5/$25 pricing. If any production workload still calls Opus 4.1 ($15/$75 — three times Opus 5's price), migrating is both an availability and a cost fix (Anthropic Docs — Model deprecations, Aug 2026).
- **`claude-mythos-preview` is deprecated** — migrate to `claude-mythos-5` if you are in the Glasswing program.
- **Already retired in 2026:** Opus 4 and Sonnet 4 (June 15, on Anthropic platforms; still available on Bedrock/Google), Sonnet 3.7, Haiku 3.5, Haiku 3, and Opus 3.
- **API parameters:** `temperature`, `top_p`, `top_k` (non-default) and manual `budget_tokens` thinking return 400 errors on 4.7+/5-series models (see §5).

Anthropic commits to at least 60 days' notice before retirements. Build a quarterly check of the deprecations page into your platform ops runbook.

---

### 9. The Model Selection Framework

Anthropic's official cost guidance is a three-way routing rule: "Choose Haiku for simple tasks, Sonnet for most production workloads, and Opus for the most complex reasoning" (Anthropic Docs — Pricing, Aug 2026). The enterprise version adds Fable at the top and governance as a first-class axis.

#### Decision tree

```
1. Is the task judgment-critical, multi-step, or long-running-agentic?
   ├── YES → 2. Does it need the highest available capability (or >100k-step agents)?
   │          ├── YES → Fable 5          (2x Opus price; always-on thinking)
   │          └── NO  → Opus 5           (thinks by default; effort to taste)
   └── NO → 3. Is it mechanical/high-volume (classify, extract, route, draft)?
              ├── YES → Haiku 4.5        (fastest, cheapest; 200k context)
              └── NO  → Sonnet 5         (default; best quality per dollar)

Context override:   need >200k input → drop Haiku 4.5 (200k cap), step up to Sonnet 5+
Latency override:   interactive/real-time UX → never above Sonnet 5 without measurement
Governance checks:  pin exact model IDs; confirm retirement window covers contract term;
                    confirm vision/data-residency constraints (inference_geo:"us" = 1.1x);
                    confirm deprecated-parameter compliance (no budget_tokens/temperature on 5-series)
```

#### Per-role recommendations

| Role / workload | Primary model | Fallback / escalation | Rationale |
|---|---|---|---|
| Software engineer (agentic coding, Claude Code) | Opus 5 | Sonnet 5 for routine edits; Fable 5 for multi-hour autonomous runs | Judgment-critical; thinking on by default |
| Analyst (long-document Q&A, due diligence) | Sonnet 5 | Opus 5 for ambiguous synthesis | 1M context at best quality/$; no surcharge |
| Support operations (triage, classification, routing) | Haiku 4.5 | Sonnet 5 for edge cases | Volume × lowest latency; 200k is ample |
| Customer-facing chatbot (latency-sensitive) | Sonnet 5 (effort `low`/`medium`) | Haiku 4.5 for FAQ-tier | Fast tier; steer effort instead of temperature |
| Legal/compliance review | Opus 5 | Fable 5 for novel/high-stakes matters | Error cost dominates token cost |
| Data pipeline / batch ETL summarization | Haiku 4.5 via Batch API | Sonnet 5 for low-confidence outputs | Batch = 50% off; escalate only on failure |
| Executives / general productivity (claude.ai) | Default Sonnet 5 | Opus 5 (Pro/Max tiers) when stakes rise | Ships as the claude.ai default for a reason |

Whatever you route, apply the two universal levers before upgrading models: **prompt caching** (0.1x on cache reads) and the **Batch API** (50% off asynchronous work). Escalate models only after these are exhausted (Anthropic Docs — Pricing, Aug 2026).

#### Try it #2: Build your routing policy

1. List your team's five most frequent Claude tasks and tag each with: task type (mechanical / balanced / judgment), typical input size (<200k / >200k), latency requirement (interactive / batch), and error cost (low / high).
2. Walk each task down the decision tree and record the chosen model plus the branch taken.
3. For any task routed above Sonnet 5, write one sentence justifying the premium in terms of error cost — if you cannot, demote it.
4. For judgment tasks on Opus 5, run the Try it #1 measurement at effort `medium` vs `high` and pick the cheapest passing effort.
5. Document the result as a one-page routing table in your team wiki, with a calendar reminder for **September 1, 2026** (Sonnet 5 repricing) and a quarterly deprecations-page review.

---

### Chapter Summary

The 2026 Claude family is a clean ladder: **Haiku 4.5** for speed and volume, **Sonnet 5** as the default, **Opus 5** for judgment, **Fable 5** for the frontier, and **Mythos 5** behind an invitation. Context is 1M tokens across the 5-series with no surcharge; thinking is adaptive and steered by effort, with manual budgets and sampling parameters deprecated on new models; benchmarks favor Claude on third-party coding boards but demand attribution and skepticism. Choose models by task type, context size, cost, and governance — measure on your own data, route rather than default to premium, and revisit the decision quarterly as pricing and retirements move.


---
