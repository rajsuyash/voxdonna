# Part 2: Introduction to Claude & Product Overview

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

#### Try it #1: Map your own workflow

Pick one recurring task from your job (e.g., "weekly status report" or "triage incoming tickets"). Write one line for each primitive:

- **Instructions:** What would a perfect prompt/instruction set say?
- **Tools:** What data or apps would Claude need (email, drive, web, spreadsheet)?
- **Memory:** What should Claude remember between runs (team names, format preferences)?
- **Permissions:** Which actions should require your explicit approval?

Keep this note. In Chapters 4–7 you will implement it as a Project, then as a Cowork scheduled task, and (for developers) as an agent.

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

## Chapter 3: Complete Product Overview

### 3.1 The Product Lineup

#### Claude Web (claude.ai)

The browser app is the canonical surface and the first to receive most features. Core elements (all GA): a chat sidebar with Projects and Artifacts, a model picker, the "Search and tools" menu for Styles and tools, web search, memory, file uploads, code execution with downloadable file creation (.docx, .pptx, .xlsx, .pdf), and connectors. Key app features, with plan gating, are covered in Chapter 6 (dim02 research, Aug 2026).

#### Claude Desktop (Mac and Windows)

The desktop app (free download at claude.ai/download; macOS 11+ and Windows 10+ x64, with ARM64 support added March 2026) syncs your chats, projects, and memory, and adds three surfaces as tabs: **Chat**, **Cowork**, and **Code**. Desktop-only capabilities include a global Quick Entry shortcut, built-in dictation, local MCP extensions, and — on paid plans — Cowork's access to granted local folders. Cowork's local-file features require macOS (Apple Silicon) or Windows Pro/Enterprise/Education; Intel Macs and Windows Home get Chat and Code only (dim02 research, Aug 2026).

#### Claude Mobile (iOS and Android)

The mobile app covers chat, voice mode (Beta — two-way spoken conversation, rebuilt July 2026 to run on Opus/Sonnet/Haiku with connectors and 11 languages; free users get Haiku plus one connected app), dictation, Research, and Dispatch — assigning and monitoring desktop Cowork tasks from your phone (Research Preview, launched March 2026). Since July 2026, Cowork sessions themselves also run on web and mobile as cloud-hosted remote sessions (Beta, Max first, then Pro) (Engadget, Jul 2026; dim09 timeline).

#### Claude API / Claude Developer Platform

The Developer Platform is how organizations embed Claude in their own software. The core is the **Messages API**, with official SDKs, streaming, tool use, structured outputs, prompt caching, a Batch API (50% discount), a Files API (Beta), a server-side code execution tool, and the Claude Agent SDK for building agents with subagents, hooks, and Skills. All current models support 1M-token context windows on the API (200k for Haiku 4.5) and adaptive thinking steered by an effort ladder (Anthropic Docs, Aug 2026). Chapters 13–16 cover this path in depth.

### 3.2 Plans: Free, Pro, Max, Team, Enterprise

Claude subscriptions follow a compute gradient: higher tiers buy more usage, more models, and (at the business tiers) governance.

| | Free | Pro | Max | Team | Enterprise |
|---|---|---|---|---|---|
| Price (as of Aug 2026 — verify) | $0 | $20/mo ($17/mo annual) | From $100/mo (5x or 20x Pro usage) | Per-seat pricing — verify current rates | Custom (contact sales) |
| Claude Code | — | ✓ | ✓ | ✓ | ✓ |
| Projects | — | ✓ (unlimited) | ✓ | ✓ | ✓ |
| Research | — | ✓ | ✓ | ✓ | ✓ |
| Cowork | — | ✓ | ✓ | Premium seat tier | ✓ |
| Fable 5 access | — | Usage credits | 50% of weekly limits | ✓ | ✓ |
| Voice mode (Beta) | Haiku + 1 connector | ✓ | ✓ | ✓ | ✓ |
| SSO/SAML, SCIM, audit logs, Compliance API | — | — | — | Partial | ✓ |

Key facts per tier (Anthropic pricing page, Aug 2026):

- **Free ($0):** Chat on all surfaces, web search, memory, file creation and code execution, connectors including remote MCP, and extended thinking. No Claude Code, no Projects.
- **Pro ($20/mo, or $17/mo billed annually at $200 upfront):** Adds Claude Code, Cowork, Claude Design, Research, unlimited projects, more models, and Microsoft 365 integration.
- **Max (from $100/mo):** Choose 5x or 20x the Pro usage allowance, higher output limits, early access to new features, and priority access during high traffic. Reporting consistently places the 5x tier at $100/mo and 20x at $200/mo, monthly billing only — verify on the official page, as the page itself states only "From $100."
- **Team:** Shared workspaces, collaboration features (shared projects with role-based permissions and an activity feed), and Claude Code for all members. Sources conflict on per-seat pricing and seat minimums (figures ranging from $20–$30 per seat/month with 2–5 seat minimums); **this guide deliberately does not quote a Team price — verify current per-seat pricing on claude.com/pricing before budgeting** (cross-verification, Aug 2026).
- **Enterprise (Enterprise only):** Custom pricing. Adds SSO/SAML with domain capture, SCIM provisioning, audit logs, the Compliance API, custom data retention, admin analytics and spend controls, expanded context, and a HIPAA-ready offering. The Enterprise differentiator is governance, not the model — Chapters 9–11 are devoted to it.

Usage on paid plans is governed by rolling 5-hour session windows plus weekly caps; Anthropic doubled the 5-hour limits for paid plans in May 2026. Exact limits are not published in full and change — check your account's usage page (dim01 research, Aug 2026).

> **Volatility callout:** Plan prices, limits, and model availability in this section are as of August 2026 — verify against current Anthropic documentation. Sonnet 5's introductory API pricing ends September 1, 2026, and Team pricing was in flux throughout 2026.

### 3.3 Release Cadence and How to Stay Current

Claude ships on a fast cadence: roughly monthly model or feature releases through 2025–2026, with prices, limits, and even model names changing quarterly. Within 60 days of this writing, Sonnet 5's introductory API price expires (2026-09-01) and Opus 4.1 retires from the API (2026-08-05, after a June deprecation notice). Anthropic commits to at least 60 days' notice before retiring models, and publishes "not sooner than" retirement dates for current models (Anthropic Docs — Model deprecations, Aug 2026).

Staying current is therefore a skill in itself:

1. **Bookmark the release notes** — the Claude Developer Platform release notes and the claude.ai changelog (mirrored by aggregators such as releasebot.io) are the authoritative record of what changed and when.
2. **Watch the deprecations page** before building on any model ID; prefer current-generation pinned IDs (from the 4.6 generation onward, model IDs are dateless pinned snapshots, not moving aliases).
3. **Re-check pricing quarterly.** Any number in this guide carrying an "as of" date is a snapshot.
4. **For admins:** subscribe to Anthropic's enterprise communications; entitlements, spend alerts, and admin analytics (added July 2026) surface changes that affect your deployment.

#### Try it #2: Build your personal update routine

1. Open the Anthropic models overview page and write down today's model lineup and each model's "not sooner than" retirement date.
2. Open the pricing page and record the current price of one model you use (or plan to use).
3. Set a quarterly recurring calendar reminder: "Claude check — models, prices, plan limits."
4. Compare your notes with this chapter's tables. Anything that already differs is your first lesson in why this guide dates every volatile claim.

### 3.4 What's New: 2025–2026 Timeline Highlights

The table below condenses the ecosystem's evolution; full status tags apply as labeled (dim09 timeline, Aug 2026).

| Date | Launch | Status |
|---|---|---|
| Feb 2025 | Claude 3.7 Sonnet (hybrid reasoning); Claude Code research preview | GA / Research Preview |
| May 2025 | Claude Opus 4 & Sonnet 4; Claude Code GA; web search GA; Integrations (remote MCP) | GA |
| Jul 2025 | Connectors Directory (~75 connectors at launch) | GA |
| Aug 2025 | Claude for Chrome research preview (browser agent) | Research Preview → Beta |
| Sep 2025 | Sonnet 4.5; Claude Agent SDK rename; API memory tool & context editing; memory for Team/Enterprise; incognito chats | GA / Beta (API features) |
| Oct 2025 | Haiku 4.5; Claude Skills; Claude Code on the web | GA / Beta |
| Nov 2025 | Opus 4.5 with effort parameter (Beta) | GA |
| Dec 2025 | Claude in Chrome extended to all paid users | Beta |
| Jan 2026 | Claude Cowork research preview; Claude for Healthcare (HIPAA-ready) | Research Preview / GA |
| Feb 2026 | Opus 4.6 (adaptive thinking, 1M context beta); Sonnet 4.6; Cowork on Windows beta | GA / Beta |
| Mar 2026 | Memory on all plans incl. Free; Cowork Dispatch; computer use in Cowork | GA / Research Preview |
| Apr 2026 | Cowork GA (spring 2026); Opus 4.7; Claude Design; Routines in Claude Code | GA / Research Preview |
| May 2026 | Claude Security public beta (Enterprise only); Opus 4.8; effort control on all plans; 5-hour limits doubled; Managed Agents public beta | GA / Beta |
| Jun 2026 | Claude Fable 5 GA (Mythos 5 restricted); Sonnet 5 GA, default on Free/Pro | GA / Restricted |
| Jul 2026 | Cowork on web + mobile with remote sessions (Beta); voice mode rebuild (Beta); Opus 5 GA; Enterprise admin analytics; MCP 2026-07 spec rollout | GA / Beta |

Two patterns matter for how you should plan. First, everything trends agentic: 2025 added tools to a chat product; 2026 turned the chat product into a platform where Cowork, Routines, and Claude Code share the same primitives — which is why §2.2's mental model works everywhere. Second, features cascade down tiers over time (memory reached Free users roughly six months after Team/Enterprise; effort control launched on all plans with Opus 4.8). If a gated feature matters to you, it may be cheaper to wait a quarter than to upgrade — but verify, because gating changes are announced in the release notes.

*(All dates and statuses in §3.4 per dim09 research, Aug 2026; items marked Research Preview/Beta may change limits, pricing, or availability.)*


---
