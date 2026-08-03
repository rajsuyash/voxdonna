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
