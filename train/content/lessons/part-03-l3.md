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

:::exercise Try it #2: Build your routing policy
1. List your team's five most frequent Claude tasks and tag each with: task type (mechanical / balanced / judgment), typical input size (<200k / >200k), latency requirement (interactive / batch), and error cost (low / high).
2. Walk each task down the decision tree and record the chosen model plus the branch taken.
3. For any task routed above Sonnet 5, write one sentence justifying the premium in terms of error cost — if you cannot, demote it.
4. For judgment tasks on Opus 5, run the Try it #1 measurement at effort `medium` vs `high` and pick the cheapest passing effort.
5. Document the result as a one-page routing table in your team wiki, with a calendar reminder for **September 1, 2026** (Sonnet 5 repricing) and a quarterly deprecations-page review.
:::

---

### Chapter Summary

The 2026 Claude family is a clean ladder: **Haiku 4.5** for speed and volume, **Sonnet 5** as the default, **Opus 5** for judgment, **Fable 5** for the frontier, and **Mythos 5** behind an invitation. Context is 1M tokens across the 5-series with no surcharge; thinking is adaptive and steered by effort, with manual budgets and sampling parameters deprecated on new models; benchmarks favor Claude on third-party coding boards but demand attribution and skepticism. Choose models by task type, context size, cost, and governance — measure on your own data, route rather than default to premium, and revisit the decision quarterly as pricing and retirements move.


---
