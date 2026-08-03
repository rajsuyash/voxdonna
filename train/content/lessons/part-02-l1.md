### 2.1 What Claude Is and Who Makes It

Claude is a family of large language models — AI systems trained to understand and generate text, code, and other structured content — built by Anthropic, an AI safety and research company. You interact with Claude through apps (web, desktop, mobile), through embedded experiences such as Claude Code in your terminal or editor, and through the Claude Developer Platform (the API) that lets your own software call Claude programmatically.

What distinguishes Claude as a product line is that it has converged into a single **agentic platform**. The same underlying capabilities — reasoning, tool use, memory, and permission-gated action — appear whether you are chatting on claude.ai, running a Cowork task on your desktop, or orchestrating agents via the API. The models themselves are organized into a capability ladder (Anthropic Docs, Aug 2026):

| Model | Positioning | Latency |
|---|---|---|
| Claude Fable 5 | Most capable widely released model; long-running agents | Slower |
| Claude Opus 5 | Complex agentic coding and enterprise work | Moderate |
| Claude Sonnet 5 | Best combination of speed and intelligence; default in apps | Fast |
| Claude Haiku 4.5 | Fastest model with near-frontier intelligence | Fastest |

A fifth model, Claude Mythos 5, exists only as an invitation-only offering under Project Glasswing and is not generally available (Anthropic Docs, Aug 2026).

Anthropic's official guidance on selection is direct: start with Opus 5 for complex agentic and enterprise work, use Fable 5 for workloads needing the highest capability, use Sonnet for most production workloads, and Haiku for simple, high-volume tasks (Anthropic Docs, Aug 2026). Chapter 5 turns this into a full decision framework.

### 2.2 The Claude Ecosystem at a Glance: One Mental Model

Because Claude ships as many products, beginners often learn each surface as a separate thing — and then struggle when features "move" between them. Don't. Learn **one mental model** that applies everywhere:

> **Claude = instructions + tools + memory + permissions.**

1. **Instructions.** What Claude should do and how. This ranges from your single prompt, to custom Styles, to Project instructions, to `CLAUDE.md` files in Claude Code, to the system prompt in an API call.
2. **Tools.** What Claude can act with. Web search, code execution, file creation, connectors (which are remote MCP servers — MCP, the Model Context Protocol, is the open standard Claude uses to connect to external systems), and browser or desktop control.
3. **Memory.** What persists across conversations: synthesized memory summaries (available on all plans, including Free, since March 2026), Project knowledge, and chat-history search.
4. **Permissions.** What Claude is allowed to do without asking: folder grants in Cowork, connector scopes, admin policies in Team/Enterprise, and tool-allow rules in Claude Code.

Every product in this guide is a different arrangement of these four primitives. Chat is instructions plus a curated tool set. Cowork adds local files and scheduled execution. Claude Code exposes the full permission system to developers. The API lets you build your own arrangement. When a new feature launches — and features launch roughly monthly — ask: *which of the four primitives did it change?*

:::exercise Try it #1: Map your own workflow
Pick one recurring task from your job (e.g., "weekly status report" or "triage incoming tickets"). Write one line for each primitive:

- **Instructions:** What would a perfect prompt/instruction set say?
- **Tools:** What data or apps would Claude need (email, drive, web, spreadsheet)?
- **Memory:** What should Claude remember between runs (team names, format preferences)?
- **Permissions:** Which actions should require your explicit approval?

Keep this note. In Chapters 4–7 you will implement it as a Project, then as a Cowork scheduled task, and (for developers) as an agent.
:::

### 2.3 How This Guide Is Organized and Learning Paths

This guide assumes no prior Claude knowledge and progresses to expert-level administration and development. All chapters use consistent terminology, status tags — (GA), (Beta), (Preview), (Research Preview), (Experimental), (Enterprise only) — and inline dates for volatile facts.

| Path | Chapters | You are… |
|---|---|---|
| Beginner | 1–6 | New to AI assistants; start with Chat, prompting, Projects |
| Knowledge worker | 1–8, 12 | Using Claude daily for documents, research, analysis |
| Administrator | 1–3, 9–11 | Managing a Team or Enterprise deployment, security, compliance |
| Developer | 1–3, 7, 13–16 | Building with the API, Claude Code, Agent SDK, MCP |

Every path should read this chapter and Chapter 3: plan limits and product surfaces change often, and knowing what exists is prerequisite to everything else.

---
