### 3.3 Release Cadence and How to Stay Current

Claude ships on a fast cadence: roughly monthly model or feature releases through 2025–2026, with prices, limits, and even model names changing quarterly. Within 60 days of this writing, Sonnet 5's introductory API price expires (2026-09-01) and Opus 4.1 retires from the API (2026-08-05, after a June deprecation notice). Anthropic commits to at least 60 days' notice before retiring models, and publishes "not sooner than" retirement dates for current models (Anthropic Docs — Model deprecations, Aug 2026).

Staying current is therefore a skill in itself:

1. **Bookmark the release notes** — the Claude Developer Platform release notes and the claude.ai changelog (mirrored by aggregators such as releasebot.io) are the authoritative record of what changed and when.
2. **Watch the deprecations page** before building on any model ID; prefer current-generation pinned IDs (from the 4.6 generation onward, model IDs are dateless pinned snapshots, not moving aliases).
3. **Re-check pricing quarterly.** Any number in this guide carrying an "as of" date is a snapshot.
4. **For admins:** subscribe to Anthropic's enterprise communications; entitlements, spend alerts, and admin analytics (added July 2026) surface changes that affect your deployment.

:::exercise Try it #2: Build your personal update routine
1. Open the Anthropic models overview page and write down today's model lineup and each model's "not sooner than" retirement date.
2. Open the pricing page and record the current price of one model you use (or plan to use).
3. Set a quarterly recurring calendar reminder: "Claude check — models, prices, plan limits."
4. Compare your notes with this chapter's tables. Anything that already differs is your first lesson in why this guide dates every volatile claim.
:::

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
