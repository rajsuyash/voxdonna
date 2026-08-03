# Appendix C: Quick Reference Cheat Sheets

Print these pages. They compress the entire guide into scannable cards you can keep beside your keyboard. Every fact is sourced from current Anthropic documentation; items marked **⚠ as of Aug 2026** are volatile — verify against current Anthropic documentation before quoting them to others.

---

### Sheet 1 — Model Picker

Pricing is per million tokens (input/output), API rates, **⚠ as of Aug 2026** (Anthropic Docs — Pricing, Aug 2026).

| Model (GA) | Context | Max output | Cost tier ($/MTok in/out) | Latency | Use for |
|---|---|---|---|---|---|
| **Fable 5** `claude-fable-5` | 1M | 128k | $10 / $50 (premium) | Slower | Long-running agents; highest available capability |
| **Opus 5** `claude-opus-5` | 1M | 128k | $5 / $25 (high) | Moderate | Complex agentic coding, enterprise work, judgment-critical paths |
| **Sonnet 5** `claude-sonnet-5` | 1M | 128k | $2 / $10 intro → **$3 / $15 on 2026-09-01** (mid) | Fast | Default for most production workloads; best quality-per-dollar |
| **Haiku 4.5** `claude-haiku-4-5` | 200k | 64k | $1 / $5 (low) | Fastest | Mechanical, high-volume, latency-sensitive tasks |
| Mythos 5 | 1M | — | $10 / $50 | — | **Invite-only** (Project Glasswing); not self-serve |

**Routing rule (official guidance):** "Choose Haiku for simple tasks, Sonnet for most production workloads, and Opus for the most complex reasoning" (Anthropic Docs, Aug 2026). Escalate to Fable 5 only where its capability repays the 2× premium over Opus.

**Gotchas:**
- Consumer plans (Free/Pro/Max) list a 200k context window; 1M is standard on 5-series via API (Anthropic Pricing, Aug 2026).
- Claude 4.7+ models use a newer tokenizer producing ~30% more tokens for the same text — factor this into cost comparisons.
- Opus 4.1 retires 2026-08-05; migrate to `claude-opus-4-8` or Opus 5.
- Manual `budget_tokens` thinking is **rejected with a 400 error** on 4.7+/5-series — use adaptive thinking with `output_config.effort` (low/medium/high/xhigh/max).

---

### Sheet 2 — Plan Picker

| Who you are | Plan | Why |
|---|---|---|
| Individual trying Claude | **Free** ($0) | Chat, web search, memory, file creation/code execution, connectors, extended thinking. No Claude Code. |
| Professional individual | **Pro** — $20/mo or $17/mo annual ⚠ as of Aug 2026 | Adds Claude Code, Cowork, Research, unlimited projects, more models |
| Heavy individual user | **Max 5x / 20x** — $100 / $200 per month ⚠ as of Aug 2026 | 5× or 20× Pro usage, higher output limits, early feature access, priority at peak traffic |
| Small team (shared work) | **Team** (per-seat; Standard + Premium tiers; Premium ≈ 5× Standard usage + Cowork) | Per-member allowances, shared Projects, admin basics. ⚠ Exact Team seat pricing conflicts across sources — verify on claude.com/pricing before quoting |
| Regulated org / IT-governed | **Enterprise** (custom pricing) | SSO/SAML + domain capture, SCIM, RBAC, audit logs (180-day, metadata-only), Compliance API, data retention controls, spend controls |

**Key mechanics:** paid-plan usage is metered by a rolling 5-hour session window plus weekly caps; Claude Code and claude.ai chat share the same pool. API billing (prepaid credits) is separate from subscriptions. Enterprise pricing is custom — contact sales; one official page suggests ~$20/seat/mo annual with a 20-seat minimum plus usage at API rates (Medium confidence — verify).

---

### Sheet 3 — Keyboard Shortcuts & UI Quick Actions

⚠ **Secondary-source flag:** this list comes from secondary reporting, not a verified official support article — treat as indicative (eliteaiadvantage.com, May 2026).

**claude.ai web / desktop:**

| Shortcut | Action |
|---|---|
| `Cmd/Ctrl + K` | Quick-nav / search chat history |
| `Cmd/Ctrl + Shift + N` | New chat |
| `Cmd/Ctrl + Shift + O` | Project switcher |
| `Cmd/Ctrl + /` | Shortcut overlay |
| `Cmd/Ctrl + ↑` | Edit last message |
| `Cmd/Ctrl + Enter` | Send · `Shift + Enter` = newline |

**Claude Code terminal (official docs):** `/` lists all commands and skills · `Tab` completion · `↑` history · `Shift+Tab` cycles permission modes · `Esc` stops Claude mid-action · `Esc Esc` or `/rewind` restores a checkpoint · `Ctrl+G` opens the plan in your editor · `Ctrl+B` backgrounds a running task · `Ctrl+E` on a permission prompt shows a risk explanation · `Alt+T` toggles thinking · `Option+K` / `Alt+K` in VS Code inserts an `@file.ts#5-10` reference.

---

### Sheet 4 — File Upload Limits

(Claude Help Center, Aug 2026. The 500 MB chat limit is a 2026 increase — older guides citing 30 MB are outdated.)

| Item | Limit | Gotchas |
|---|---|---|
| Chat uploads | **500 MB per file**, up to 20 files per chat | Free tier reportedly ~5 files/chat (third-party; not officially published) |
| Project files | **30 MB per file**, unlimited count | Total must fit the context window; text-extraction only (except PDFs) |
| Code-execution sandbox files | 30 MB per file in/out | Two official pages conflict with the 500 MB figure — likely context-dependent ⚠ |
| PDFs | ≤100 pages: text **+ vision**; 101–1000 pages: text only; >1000 rejected | Non-PDF docs: text only, embedded images ignored. Reference PDF-viewer page numbers |
| Images | JPEG/PNG/GIF/WebP; ≤8000×8000 px; 20/message | ≥1000×1000 px recommended; first frame of animations only |
| Supported docs | PDF, DOCX, CSV, TXT, HTML, ODT, RTF, EPUB, JSON, XLSX | **XLSX requires "code execution and file creation" enabled** |
| Not supported as input | PPTX, ZIP, audio, video | Claude can *create* .pptx via code execution; transcribe audio/video externally |
| API specifics | 10 MB/image; 100 images/request (200k models), 600 (others); PDF 32 MB/request, 100 pages | Files API (Beta): 500 MB/file, persists by `file_id` until deleted; not on Bedrock/Google |
| Image generation | **Not available** — no raster generation/editing | Use SVG, Mermaid, charts via Artifacts instead |

---

### Sheet 5 — Prompt Anatomy: 10-Point Pre-Send Checklist

Run every important prompt through this list (Anthropic Docs — Prompting best practices, Aug 2026):

1. **Golden Rule test** — would a colleague with minimal context understand this prompt? If not, rewrite.
2. **Task stated first, directly** — one sentence: exactly what you want done.
3. **Success criteria defined** — what does a good answer look like? Say it.
4. **Format specified** — length, structure, tone; tell Claude what TO do, not what not to do.
5. **Context before the question** — long documents at the top, query at the end (up to ~30% quality gain in Anthropic tests).
6. **Sections delimited** — XML tags or Markdown headers (`<instructions>`, `<context>`, `<document>`) when mixing instruction + data + examples.
7. **3–5 diverse examples** — wrapped in `<example>` tags when format/tone matters; don't laundry-list edge cases.
8. **Role set if useful** — even one system-prompt sentence ("You are a senior tax accountant") focuses behavior.
9. **No contradictions or typos** — Claude follows both halves of a contradiction; "smarter when you sound smart."
10. **Thinking matched to model** — on 5-series, prefer "think thoroughly" over hand-written step-by-steps; skip "think step by step" when thinking is already on; remove explicit "verify your answer" instructions on Opus 5 (causes over-verification).

---

### Sheet 6 — Connector Quick-Setup (Top 10)

All connectors are remote MCP servers; setup is **Settings → Connectors → toggle/Connect → OAuth consent**. Admin gate: Team/Enterprise owners can set Always allow / Needs approval / Blocked per connector (Anthropic docs + directory FAQ).

| Connector | Auth | One-line setup | Watch out for |
|---|---|---|---|
| Google Workspace (Gmail/Drive/Calendar) | Google OAuth | Toggle on → Google sign-in consent | Gmail is **draft-only**; Workspace admin must mark Claude a trusted app |
| Microsoft 365 | Microsoft Entra ID (delegated OAuth) | Org Owner enables → Global Admin grants tenant consent → users connect | 3 gates; write tools added Jul 2026 (Teams read-only) |
| Slack | Slack OAuth | Directory one-click; interactive MCP App since Jan 2026 | Drafts reviewed before posting; private channels need explicit grant |
| Notion | OAuth via `https://mcp.notion.com/mcp` | Directory → OAuth (inherits your Notion permissions) | Write surface expanded mid-2026 ⚠ verify in product |
| Jira & Confluence | Atlassian OAuth (mcp.atlassian.com) | Directory connect → consent | Inherits Atlassian permissions; no event triggers |
| GitHub | GitHub OAuth / PAT | Add as **custom connector** via GitHub's remote MCP server | Not a first-party directory toggle ⚠ status changes often |
| HubSpot | HubSpot OAuth | Directory connect; respects HubSpot permissions | No sensitive-data properties; writes logged in HubSpot audit log |
| Salesforce | External Client App + OAuth | Via Salesforce Hosted MCP Servers (GA Apr 2026) / MCP Apps | Directory-listing status ambiguous ⚠ |
| Linear | Linear OAuth | Directory connect | Launch partner; create/update issues |
| Zapier | Zapier OAuth | Directory connect → pick Zaps | Gateway to ~7,000+ apps |

**Custom connector (any remote MCP server):** Settings → Customize → Connectors → "+ Add custom connector" → name + HTTPS URL (+ optional OAuth Client ID/Secret). Must be reachable from Anthropic's cloud (no localhost/VPN). Free plan: 1 custom connector; paid plans: more. **Enterprise:** deploy allowlists via `managed-mcp.json` through MDM.

---

### Sheet 7 — Claude Code Command Card

**Install (native, recommended — auto-updates):**

```bash
curl -fsSL https://claude.ai/install.sh | bash        # macOS / Linux / WSL
irm https://claude.ai/install.ps1 | iex               # Windows PowerShell
brew install --cask claude-code                        # Homebrew
npm install -g @anthropic-ai/claude-code               # npm (Node 22+; installs same binary)
```

**Top CLI invocations & flags:**

| Command | Purpose |
|---|---|
| `claude` | Interactive session in current project |
| `claude "task"` / `claude -p "query"` | One-shot / headless print mode (scriptable) |
| `claude -c` / `claude -r` | Continue last / resume a session |
| `--model sonnet\|opus\|haiku\|fable` | Pick model · `--effort low…max` sets thinking effort |
| `--permission-mode default\|acceptEdits\|plan\|auto\|dontAsk\|bypassPermissions` | Autonomy dial |
| `--output-format json\|stream-json` | Machine-readable output for CI |
| `--max-turns N` · `--max-budget-usd X` | Hard guardrails for unattended runs |
| `--cloud "task"` / `--teleport` | Start a web (cloud) session / pull it into terminal |
| `claude mcp add --transport http <name> <url>` | Add an MCP server |

**Top slash commands & skills:** `/init` (generate CLAUDE.md) · `/clear` (reset context between tasks) · `/compact` · `/rewind` (restore checkpoints) · `/model` · `/effort` · `/usage` · `/permissions` · `/mcp` · `/agents` · `/memory` · `/doctor` · `/code-review` · `/install-github-app`. Custom skills = `SKILL.md` in `.claude/skills/<name>/`, invoked as `/<name>`.

**CLAUDE.md essentials:** four scopes — managed policy → user (`~/.claude/CLAUDE.md`) → project (`./CLAUDE.md`) → local (`./CLAUDE.local.md`, gitignored). Keep each file **under 200 lines**; use `@path` imports (max 4 hops); path-scoped rules live in `.claude/rules/*.md` with `paths:` frontmatter. Put in: build/test commands, architecture map, conventions, verification steps.

---

### Sheet 8 — API Starter Card

**Auth (3 required headers):**

```bash
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-5","max_tokens":1024,
       "messages":[{"role":"user","content":"Hello"}]}'
```

API keys (`sk-ant-…`) are created in the Console, shown once, read automatically from the `ANTHROPIC_API_KEY` env var by all 8 official SDKs. **One-liners:**

- **Streaming:** `"stream": true` — SSE events `message_start → content_block_delta → message_stop`; watch for in-stream `overloaded_error` even after HTTP 200.
- **Tool use:** define `tools[]` with `name`, `description`, `input_schema`; Claude returns a `tool_use` block — **your code executes it** and returns a `tool_result` with the matching `tool_use_id`.
- **Prompt caching:** `cache_control: {"type":"ephemeral"}` on content blocks (≤4 breakpoints); writes 1.25× (5-min) or 2× (1-hour) base input, **reads 0.1×** ⚠ as of Aug 2026.
- **Batch API:** `POST /v1/messages/batches` — **50% off** input+output, results within 24h.
- **Adaptive thinking:** `"thinking": {"type":"adaptive"}` + `"output_config": {"effort":"high"}`; `budget_tokens` errors (400) on 4.7+ models.
- **Structured outputs (GA):** `output_config.format` with your JSON schema; SDK: `client.messages.parse(..., output_format=Model)`.

**Error codes:**

| Code | Type | Do |
|---|---|---|
| 400 | `invalid_request_error` | Fix the request; don't retry (deprecated params = 400 on new models) |
| 401 | `authentication_error` | Check the `x-api-key` header and key validity |
| 403 | `permission_error` | Key lacks access to the model/feature |
| 429 | `rate_limit_error` | Your rate; back off per `retry-after` header |
| 500 | `api_error` | Transient server error; retry |
| 529 | `overloaded_error` | Anthropic-wide capacity; retry with capped exponential backoff + jitter (can arrive mid-stream) |

---

### Your First 30 Days with Claude — Team Rollout Checklist

**Week 1 — Foundation (Admin)**
1. Choose the plan (Sheet 2); enable SSO/SAML + SCIM on Enterprise.
2. Set org policies: connector approvals, spend controls, data-retention settings.
3. Enable Google Workspace and/or Microsoft 365 connectors (complete the admin-consent gates).
4. Pick 3–5 pilot users across roles; define success criteria for the pilot.
5. Baseline security review: confirm "no training on customer data by default" and audit-log settings.

**Week 2 — Onboarding (Pilots)**
6. Install desktop app; pilots complete 3 starter tasks: a draft with Styles, a file analysis (Sheet 4), a connected-app query.
7. Create the first shared Project with team knowledge files (≤30 MB each).
8. Engineers install Claude Code, run `/init`, and commit a starter CLAUDE.md (<200 lines).
9. Everyone saves 2–3 reusable prompts using the Sheet 5 checklist.

**Week 3 — Workflow integration**
10. Connect Jira/Linear/GitHub per Sheet 6; set per-action approval policies.
11. Engineers adopt the explore → plan → implement → commit loop; add one custom skill and one PreToolUse hook.
12. Measure: track `/usage` and admin spend reports; expect ~$13/developer/active day average for Claude Code ⚠ as of Aug 2026.

**Week 4 — Scale & govern**
13. Review pilot against Week 1 success criteria; adjust seat tiers (Standard vs Premium).
14. Publish an internal prompt library and connector allowlist (`managed-mcp.json` on Enterprise).
15. Train the wider team with this chapter's cheat sheets; name a Claude champion per department.
16. Schedule a monthly review of usage, audit logs, and new-feature releases.
