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

:::exercise Try it
1. Take a task you currently do in one giant prompt (e.g., a monthly report). Rewrite it as a three-step prompt chain: outline → gate-check against a criteria list → draft. Compare quality.
2. Run an evaluator-optimizer loop in chat: generate a 300-word product description, then ask Claude to score it against five criteria you define, then regenerate. Note which criteria actually changed the output.
3. In Claude Code, run the documented explore → plan → implement → commit flow on a small feature, and observe where the orchestrator-workers pattern appears spontaneously (Explore and Plan subagents).
:::

---
