# Appendix A: Glossary & FAQ

This glossary defines the core terms used throughout this guide. Entries are alphabetical; status tags — (GA), (Beta), (Preview), (Research Preview), (Experimental), (Enterprise only) — reflect availability as of August 2026. Verify against current Anthropic documentation before relying on a status for procurement or compliance decisions.

### A

**Adaptive thinking** (GA) — The reasoning mode on Claude 4.7+/5-series models that replaces manual `budget_tokens` extended thinking; you steer it with the effort parameter rather than a fixed token budget. On Fable 5 it is always on, and on Opus 5 thinking is on by default (Anthropic Docs, Jul 2026).

**Admin Console** — The Enterprise/Team web interface where owners manage SSO/SAML, SCIM, spend controls, model entitlements, audit logs, and data-retention settings (Anthropic, Aug 2026).

**Agent** — A loop in which Claude plans, calls tools, observes results, and iterates toward a goal with reduced human turn-taking, as opposed to single-shot chat. Cowork, Claude Code, and API-built agents are the three main flavors in the ecosystem.

**Agent SDK** (GA) — Anthropic's framework (npm `@anthropic-ai/claude-agent-sdk`, pip `claude-agent-sdk`) for building agents programmatically, renamed from Claude Code SDK in September 2025; supports subagents, hooks, and Skills (Anthropic, Sep 2025).

**Artifacts** (GA) — Substantial generated content (Markdown, HTML, React, SVG, Mermaid, code, PDF) rendered in a side panel beside the chat, editable and publishable via public link. Available on all plans including Free (Anthropic, Aug 2024).

**Audit logs** (Enterprise only) — Metadata-only records of workspace activity retained for 180 days, exportable for compliance review and integrable with OpenTelemetry monitoring (Anthropic, Aug 2026).

### B

**Batch API** (GA) — An asynchronous Messages API mode that processes large job queues at 50% off input and output pricing, with up to 300k output tokens on supported 5-series/4.6+ models via a beta header (Anthropic Docs, 2026).

### C

**CLAUDE.md** — A project- or user-level Markdown file Claude Code reads automatically at session start to load standing instructions, conventions, and context. It is the primary way to give Claude Code durable project memory.

**Claude Code** (GA since May 22, 2025) — Anthropic's agentic coding tool, running in the terminal, VS Code, JetBrains, and on web/mobile, that reads and edits code, runs commands, and manages git workflows. Included in all paid plans (Anthropic, 2026).

**Code execution tool** (GA) — A server-side capability that lets Claude run code in a sandboxed environment to analyze files or create XLSX/DOCX/PPTX/PDF outputs; available on all claude.ai plans and the API (Anthropic, 2026).

**Compliance API** (Enterprise only) — An API that lets organizations programmatically export usage and content data for regulatory archiving and e-discovery (Anthropic, Aug 2026).

**Connectors** (GA) — Integrations built on the Model Context Protocol that connect Claude to remote services (Google Workspace, Microsoft 365, Slack, Jira, Salesforce, GitHub, and 800+ others) via OAuth. Authenticated per user, so Claude never gets broader access than the connecting user (Anthropic, Jul 2025).

**Context editing** (Beta) — An API feature (with the memory tool, under the `context-management-2025-06-27` beta header) that automatically clears or summarizes stale tool results to keep long agent runs within the context window (Anthropic, Sep 2025).

**Context window** — The maximum total tokens (input plus output) a model can consider at once: 1M tokens standard on 5-series models, 200k on Haiku 4.5 and consumer chat plans (Anthropic Docs, 2026).

**Cowork** (GA, spring 2026) — Anthropic's general-purpose agent for knowledge work, a third desktop-app surface alongside Chat and Code, that executes multi-step tasks with scheduled-task support. Entered research preview in January 2026 and reached web/mobile in July 2026 (Anthropic, 2026).

### D

**Domain capture** (Enterprise only) — A control that automatically routes users who sign up with a verified corporate email domain into the organization's managed workspace (Anthropic, Aug 2026).

### E

**Effort parameter** (GA) — The `output_config.effort` setting (ladder: low, medium, high, xhigh, max) that controls how hard adaptive-thinking models reason; default is `high` on Opus 5/Sonnet 5 and in Claude Code. Also exposed in the CLI as `--effort` (Anthropic Docs, Jul 2026).

**Extended thinking** (deprecated on 4.6+, rejected on 4.7+) — The older manual reasoning mode using `thinking.type: "enabled"` with `budget_tokens`; still valid only on Haiku 4.5 and earlier 4.x models. Requests using it on Claude 4.7 or later return a 400 error (Anthropic Docs, 2026).

### F

**Files API** (Beta) — An API for uploading files up to 500MB and referencing them across messages, rather than embedding base64 content in each request (Anthropic Docs, 2026).

### H

**Hooks** (GA) — User-defined shell commands in Claude Code that fire on lifecycle events (e.g., before/after tool calls) to enforce policy, run linters, or log activity. Configured via settings files and the `/hooks` command.

### I

**Incognito chats** (GA) — Conversations that are not saved to history and excluded from memory, available to all users since September 2025 (Anthropic, Sep 2025).

### L

**Live Artifacts** (GA) — Persistent, updatable artifacts inside Cowork sessions, introduced April 2026, that the agent keeps current as a task progresses rather than regenerating one-shot outputs (getmasset.com, May 2026).

### M

**MCP (Model Context Protocol)** (GA) — The open protocol, created by Anthropic, that standardizes how AI applications connect to tools and data via hosts, clients, and servers over stdio or Streamable HTTP with OAuth 2.1. An official server registry is in Preview as of July 2026.

**MCP Apps** — Applications or surfaces (such as claude.ai and Claude Desktop) that act as MCP hosts, loading connectors and local MCP servers to extend Claude's capabilities.

**Memory** (GA) — Claude's ability to retain preferences and facts across conversations and to search and reference past chats; rolled out to all plans by March 2026 and manageable in Settings → Capabilities (Anthropic, 2026).

**Messages API** (GA) — The core REST endpoint (`POST /v1/messages`) for Claude: a `model`, required `max_tokens`, alternating user/assistant messages, and optional system prompt, tools, streaming, and caching parameters (Anthropic Docs, 2026).

**Model entitlements** (Enterprise only) — Admin controls, added in the July 2026 governance release, that set default models and restrict which models users or groups may access (Orbilon Tech, Jul 2026).

### P

**Projects** (GA) — Persistent workspaces on claude.ai that bundle chats, custom instructions, and knowledge files with a 200K context window (500K on Enterprise); a RAG mode auto-expands effective capacity up to 10x. Available on paid plans, not Free (Anthropic, Jun 2024).

**Prompt caching** (GA) — An API feature that caches repeated prompt prefixes (5-minute writes at 1.25x base input price, 1-hour writes at 2x) and serves cache reads at 0.1x, cutting cost and latency for long static contexts (Anthropic Docs, 2026).

### R

**RAG (Retrieval-Augmented Generation)** — A pattern in which a system retrieves relevant documents and injects them into the prompt so the model answers from current, private data. Claude Projects implement a managed form of RAG over project knowledge.

**Rate limits** — Caps on API usage measured in requests and tokens per minute, varying by model and usage tier; separate from the 5-hour session and weekly usage limits on subscription plans. *As of August 2026 — verify current tiers against Anthropic documentation.*

**Research** (GA) — An agentic feature in which Claude plans and runs multi-step web and workspace searches, then synthesizes a cited report; available on paid plans and mobile (Anthropic, 2025).

**Routines** (Research Preview) — Saved Claude Code automations (prompt + repos + connectors) triggered on a schedule, API webhook, or GitHub event, running locally or in Anthropic's cloud. Daily caps: Pro 5, Max 15, Team/Enterprise 25 — *as of August 2026; limits and behavior can change during preview* (Anthropic, Apr 2026).

### S

**SCIM** (Enterprise only) — System for Cross-domain Identity Management: automated provisioning and de-provisioning of users and groups from an identity provider (e.g., Okta, Entra ID) into the Claude workspace (Anthropic, Aug 2026).

**Skills** (GA) — Packaged, reusable capability bundles (instructions plus scripts/resources) that Claude loads when relevant; in Claude Code, a skill at `.claude/skills/name/SKILL.md` also creates a slash command. Custom commands were merged into Skills in 2026 (Anthropic, 2026).

**SSO/SAML** (Enterprise only) — Single sign-on via the SAML standard, letting employees authenticate to Claude through the corporate identity provider; typically deployed with domain capture (Anthropic, Aug 2026).

**Streaming** (GA) — Server-Sent Events delivery of API responses token-by-token (`stream: true`), from `message_start` through `message_stop`, so applications render output progressively. Note that errors can arrive mid-stream as in-band error events after HTTP 200 (Anthropic Docs, 2026).

**Structured outputs** (GA) — Constraining Claude's response to a JSON schema so downstream code can parse it reliably; exposed in Claude Code via `--json-schema` and on the API (Anthropic, 2026).

**Styles** (GA) — Saved response-formatting preferences on claude.ai (tone, structure, length) selected from the "Search and tools" menu and applied across chats (Anthropic, 2025).

**Subagents** (GA) — Specialized agents that Claude Code or Agent SDK agents delegate subtasks to, each with its own prompt, tools, and context; defined via the `/agents` command or `--agents` JSON flag (Anthropic, 2025).

**System prompt** — The top-level `system` parameter in an API request (or custom instructions in apps) that sets Claude's persona, rules, and constraints for the whole conversation.

### T

**Tokens** — The subword units Claude reads and writes; both context windows and billing are measured in tokens (per million tokens, MTok). Claude 4.7+ models use a newer tokenizer producing ~30% more tokens for the same text — relevant when comparing costs across generations (Anthropic Docs, 2026).

**Tool use (function calling)** (GA) — Declaring tools with a name, description, and JSON Schema input so Claude can return structured `tool_use` blocks for your code to execute, then consume `tool_result` content; the foundation of agents and connectors (Anthropic Docs, 2026).

### V

**Voice mode** (Beta) — Two-way spoken conversation on iOS, Android, desktop, and web, expanded July 2026 with paid-plan access to Sonnet/Opus and connected-app context; Free tier is limited to Haiku with a single connection. Usage counts toward plan limits (Engadget, Jul 2026).

### W

**Workspace** — The administrative container for an organization's Claude deployment: its seats, SSO/SCIM configuration, spend controls, retention policy, and (for API accounts) ZDR scope.

### Z

**ZDR (Zero Data Retention)** (contract-gated) — A commercial arrangement for qualified enterprise/API accounts in which inputs and outputs are not stored at rest after the response. Scope covers the Messages and Token Counting APIs and excludes Batch, Files, Skills, code execution, and MCP connectors; Fable 5 and Mythos 5 require 30-day retention and are ZDR-incompatible (Anthropic Docs, 2026).

---

## Chapter 17: Frequently Asked Questions

Answers reflect the ecosystem as of August 2026. Pricing, limits, and plan entitlements change frequently — verify against current Anthropic documentation or your account team before acting.

### 1. Getting started

**Q1. What can I do on the Free plan?**
Free includes chat on web, desktop, iOS, and Android, plus web search, memory, file creation with code execution, connectors (remote MCP), and extended thinking. It does not include Claude Code, Projects, or Research (Anthropic pricing page, Aug 2026).

**Q2. Which model should I start with?**
Anthropic's official guidance: start with Opus 5 for complex agentic coding and enterprise work, and use Fable 5 for workloads needing the highest available capability. For everyday cost efficiency, Sonnet 5 is the best combination of speed and intelligence, and Haiku 4.5 suits simple, high-volume tasks (Anthropic Docs, Jul 2026).

**Q3. Do I need to install anything to use Claude?**
No — claude.ai runs in any modern browser, with optional desktop and mobile apps. Only Claude Code requires installation (native installer or npm), after which it runs in your terminal or IDE (Anthropic, 2025).

**Q4. What file types can I upload to a chat?**
PDF (best under 100 pages; 101–1000 pages is text-only), DOCX, TXT, MD, CSV, XLSX, JSON, and images (JPEG/PNG/GIF/WebP up to 8000×8000 px) are supported. Video, audio, and PPTX are not accepted as input, and XLSX analysis requires the code execution tool (Anthropic, 2026).

**Q5. What are Projects and who gets them?**
Projects are persistent workspaces with custom instructions and a knowledge base (200K context, 500K on Enterprise), with a RAG mode that expands effective capacity up to 10x. They are available on Pro, Max, Team, and Enterprise — not Free (Anthropic, Jun 2024).

### 2. Plans & billing

**Q6. How much do the consumer plans cost?**
Free is $0; Pro is $20/month or $17/month billed annually; Max offers 5x Pro usage at $100/month or 20x at $200/month, monthly billing only. *As of August 2026 — verify on anthropic.com/pricing before quoting* (Anthropic, Aug 2026).

**Q7. How much does the Team plan cost?**
Sources conflict: Standard seats are reported at $20–25/seat/month annually ($25–30 monthly) and Premium at $100–125/seat/month annually, with minimum seat counts reported as both 2 and 5. Because sources disagree, contact Anthropic sales or verify on claude.com/pricing before budgeting — *this is a known conflict zone as of August 2026*.

**Q8. What does Enterprise cost?**
Anthropic's official page lists Enterprise at $20/seat/month billed annually with a 20-seat minimum, with usage billed as you go at API rates; this figure comes from a single official page, so treat it as medium confidence and confirm with sales. HIPAA-ready terms are available only on sales-assisted plans (Anthropic, Aug 2026).

**Q9. Is API billing separate from my subscription?**
Yes. API usage is billed in prepaid credits per million tokens and is entirely separate from Pro/Max/Team subscriptions, which are flat seat fees with usage limits (Anthropic, 2026).

**Q10. What are the API prices for the current models?**
Per million input/output tokens: Fable 5 $10/$50, Opus 5 $5/$25, Sonnet 5 $2/$10 (introductory through August 31, 2026, then $3/$15 from September 1, 2026), Haiku 4.5 $1/$5. Batch API halves both rates. *As of August 2026 — the Sonnet 5 change is imminent, verify current pricing* (Anthropic Docs, Aug 2026).

**Q11. How do usage limits work on paid plans?**
Plans enforce rolling 5-hour session windows plus weekly caps, with Max multipliers (5x/20x) scaling the session window; Claude Code shares the same pool as claude.ai chat. Anthropic doubled 5-hour limits and removed peak-hour throttling in May 2026 — *mechanics evolve, verify current behavior* (agentcat.com, Jun 2026).

### 3. Features & limits

**Q12. How big is the context window?**
5-series models (Fable 5, Opus 5, Sonnet 5) offer 1M tokens on the API with no long-context surcharge; Haiku 4.5 and the consumer plan table list 200k. Third parties report 1M available in-app on Sonnet 5, but the official consumer table says 200k — *unresolved; verify for your plan* (Anthropic Docs, Aug 2026).

**Q13. What's the file upload size limit in chat?**
Chat uploads were recently raised to 500MB per file (older documentation said 30MB — note the change); paid plans allow roughly 20 files per conversation, Free about 5. The Files API for developers also supports up to 500MB (Anthropic, 2026).

**Q14. Can Claude remember things between conversations?**
Yes — memory rolled out to all plans by March 2026, and Claude can search and reference past chats while respecting project boundaries. You can disable it in Settings → Capabilities, or use Incognito chats for sessions that leave no history (Anthropic, 2026).

**Q15. What are connectors and which apps are supported?**
Connectors are remote MCP servers that link Claude to external tools via OAuth; the Directory (launched July 14, 2025) listed 800+ integrations by July 2026, including Google Workspace, Microsoft 365, Slack, Jira, Confluence, Salesforce, HubSpot, GitHub, and Zapier. Claude's access never exceeds the connecting user's permissions (Anthropic, Jul 2026).

**Q16. Can Claude generate images?**
No. Image generation is not available as of August 2026 — reports are based on leaks only, not any released feature. Claude accepts images as input (vision) but does not produce them.

**Q17. What is voice mode and who gets it?**
Voice mode (Beta) provides two-way spoken conversation on all platforms; since the July 2026 expansion, paid users can speak with Sonnet/Opus and pull context from connected apps, while Free users are limited to Haiku with a single connection. Spoken usage counts toward plan limits (Engadget, Jul 2026).

**Q18. What are Routines and what are their limits?**
Routines (Research Preview) are scheduled or triggered Claude Code automations running locally or in Anthropic's cloud, with daily caps of 5 (Pro), 15 (Max), and 25 (Team/Enterprise). *As a preview feature, limits and behavior can change — verify before automating critical workflows* (Anthropic, Apr 2026).

### 4. Enterprise & security

**Q19. Does Anthropic train on my data?**
No — Anthropic does not train on customer data by default, and consumer plans include a model-training opt-out. Enterprise adds contractual data-retention controls (Anthropic, Aug 2026).

**Q20. What compliance certifications does Claude hold?**
Claude Enterprise is covered by SOC 2 Type II, ISO 27001, and ISO 42001, with GDPR and CCPA compliance; a HIPAA-ready offering exists on sales-assisted Enterprise plans (Anthropic, Aug 2026).

**Q21. What is Zero Data Retention and can I get it?**
ZDR means inputs and outputs are not stored at rest after the response, available only via commercial agreement for qualified accounts. It covers the Messages and Token Counting APIs but excludes Batch, Files, Skills, code execution, and MCP connectors, and Fable 5/Mythos 5 are incompatible with ZDR-only workspaces (Anthropic Docs, 2026).

**Q22. How long does Anthropic retain API data?**
The default API retention is 7 days, with a 30-day option available via a DPA opt-in. Audit logs on Enterprise retain metadata-only activity records for 180 days (Anthropic, 2026).

**Q23. What admin controls exist on Enterprise?**
SSO/SAML with domain capture, SCIM provisioning, RBAC, spend controls with alerts at 75% and 90% of budget, audit logs with OpenTelemetry monitoring, a Compliance API, data-retention controls, and model defaults/entitlements (added July 2026) (Anthropic, Aug 2026).

**Q24. Is my organization protected if I publish an artifact or share a chat?**
Shared chats and published artifacts generate public links, and in July 2026 some were briefly indexed by Google due to a missing noindex directive before remediation. Treat share links as public: review organization policy before publishing, and revoke links via Settings → Privacy (TechCrunch, Jul 2026).

### 5. Claude Code & API

**Q25. What is CLAUDE.md and why should I use it?**
CLAUDE.md is a Markdown file Claude Code reads at session start to load project conventions, commands, and standing instructions. It is the standard way to give the agent durable project memory and to keep team conventions consistent across contributors (Anthropic, 2025).

**Q26. How do subagents and hooks differ?**
Subagents are specialized agents Claude Code delegates subtasks to, each with its own context and tool set; hooks are shell commands that fire on lifecycle events to enforce policy or run checks. Together they let you decompose work and guardrail it without changing the main agent's prompt (Anthropic, 2025).

**Q27. What does Claude Code typically cost a team?**
Average Claude Code consumption is reported around $13 per developer per day; actual spend varies with model choice and autonomy level. *As of August 2026 — monitor via the admin usage dashboards, which include per-user analytics* (Anthropic, 2026).

**Q28. How do I authenticate to the API?**
Send your key (`sk-ant-…`) in the `x-api-key` header — not `Authorization: Bearer` — plus an `anthropic-version` header (e.g., `2023-06-01`) and `Content-Type: application/json`. SDKs for 8 languages read the key automatically from the `ANTHROPIC_API_KEY` environment variable (Anthropic Docs, 2026).

**Q29. How do I control reasoning effort on the new models?**
On 4.7+/5-series models, use the effort parameter (`low` → `max`) with adaptive thinking; the old `budget_tokens` extended-thinking mode is rejected with a 400 error on these models. On Opus 5, disabling thinking is only permitted at effort `high` or below (Anthropic Docs, Jul 2026).

### 6. Troubleshooting

**Q30. My API request returns a 400 error mentioning thinking, temperature, or top_p — why?**
Claude 4.7+ models and Mythos Preview reject manual `budget_tokens` extended thinking and non-default `temperature`, `top_p`, or `top_k` values with 400 errors. Remove those parameters and use the effort ladder instead (Anthropic Docs, 2026).

**Q31. My streaming connection opened fine but produced an error mid-response — what happened?**
Streaming responses open with HTTP 200 and can deliver errors such as `overloaded_error` as in-stream events, so status-code-only handling will miss them. Always parse stream events for error types and implement retries with backoff (Anthropic Docs, 2026).

**Q32. Why does my connector fail in Claude when it works locally?**
Remote connectors are reached from Anthropic's cloud, not your machine, so servers behind a VPN, firewall, private DNS, or IP allowlist will fail. Expose the endpoint publicly with OAuth 2.1, or use a local MCP server via the desktop app instead (Sunpeak.ai, Jul 2026).

**Q33. Claude hit a limit mid-task — what are my options?**
Subscription limits reset on rolling 5-hour windows plus weekly caps; you can wait for the reset window, switch to a lighter model (Haiku 4.5) for mechanical steps, or move bursty workloads to the API where limits are tier-based. Enterprise admins can raise user-level spend limits in the Admin Console (Anthropic, 2026).

**Q34. Why is my bill higher than expected after switching to a 4.7+ model?**
Claude 4.7+ models use a newer tokenizer that produces roughly 30% more tokens for identical text, so headline per-token price cuts overstate real savings. Re-baseline your cost-per-task measurements when migrating model generations (Anthropic Docs, 2026).

**Q35. A model I depend on is being deprecated — how much warning do I get?**
Anthropic promises at least 60 days' notice before model retirements, with published "not sooner than" availability dates (e.g., Opus 5 guaranteed through at least July 24, 2027). Pin model IDs explicitly and monitor the deprecations page; dateless IDs from the 4.6 generation onward are pinned snapshots, not moving pointers (Anthropic Docs, Aug 2026).


---
