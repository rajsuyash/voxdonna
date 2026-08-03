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
