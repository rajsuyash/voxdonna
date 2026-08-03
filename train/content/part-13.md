# Part 13: Claude Code — The Complete Guide

Claude Code is Anthropic's agentic coding tool: a terminal-first assistant that reads your files, runs commands, edits code, executes tests, and works through multi-step engineering tasks autonomously while you watch, redirect, or step away. Unlike a chatbot that answers questions and waits, Claude Code operates in an agent loop — it plans, acts with real tools against your real filesystem and shell, observes results, and continues until the task is done or it needs your decision (Anthropic Docs, Jul 2026). It reached general availability (GA) on 2025-05-22 and is available to any paid Claude account (Pro, Max, Team, or Enterprise) or a Claude Console (API) account; the free Claude.ai plan does not include Claude Code access (Anthropic Docs, Aug 2026).

This chapter takes you from zero — installation — to enterprise-grade deployment: CLI and slash commands, IDE integrations, memory files, agentic subagents, hooks, MCP, permissions and sandboxing, headless automation, GitHub Actions, cloud sessions, cost management, and two end-to-end workflows. Where facts are volatile (pricing, limits, version numbers), you will see explicit callouts to verify against current documentation.

### 11.1 Installing Claude Code

#### Native installer (recommended)

The recommended installation is a native binary that auto-updates in the background (Anthropic Docs, Aug 2026):

```bash
# macOS, Linux, WSL
curl -fsSL https://claude.ai/install.sh | bash
```

```powershell
# Windows PowerShell
irm https://claude.ai/install.ps1 | iex
```

System requirements: macOS 13.0+, Windows 10 1809+, Ubuntu 20.04+, Debian 10+, or Alpine 3.19+; 4 GB+ RAM; x64 or ARM64 (Anthropic Docs, Aug 2026).

#### Package managers and npm

| Method | Command | Notes |
|---|---|---|
| Homebrew | `brew install --cask claude-code` (stable) or `claude-code@latest` | macOS/Linux |
| WinGet | `winget install Anthropic.ClaudeCode` | Windows |
| apt / dnf / apk | signed repositories with `stable` and `latest` channels | Linux |
| npm | `npm install -g @anthropic-ai/claude-code` | Requires Node.js 22+ (as of v2.1.198); downloads the same native binary via per-platform optional dependencies — the installed `claude` binary does not itself invoke Node |

For npm upgrades, use `npm install -g @anthropic-ai/claude-code@latest` and avoid `npm update -g` (Anthropic Docs, Aug 2026).

#### Version pinning and integrity

The native installer can pin a version (`curl -fsSL https://claude.ai/install.sh | bash -s 2.1.89`), and the `autoUpdatesChannel` setting selects `"latest"` (default) or `"stable"`. Each release publishes a signed `manifest.json` with SHA256 checksums, signed with an Anthropic GPG key. Verify your install with:

```bash
claude --version   # e.g. 2.1.211 (Claude Code)
claude doctor      # environment diagnostics
```

> **Try it — Install and verify.** Install Claude Code with the native installer, then run `claude --version` and `claude doctor`. Note any warnings `doctor` reports and fix one of them before continuing.

### 11.2 CLI essentials

Start an interactive session in any project directory:

```bash
cd /path/to/your/project && claude
```

Core invocations (Anthropic Docs, Aug 2026):

| Command | Behavior |
|---|---|
| `claude` | Interactive mode |
| `claude "task"` | Run a one-time task |
| `claude -p "query"` | Print (headless) mode: run one-off query, then exit |
| `claude -c` | Continue the most recent conversation |
| `claude -r` | Resume a previous conversation |
| `claude --cloud "task"` | Start a new cloud session on claude.ai/code |
| `claude --teleport` | Pull a cloud session into your terminal |
| `claude --bg "task"` | Run a background agent |
| `claude -w` / `--worktree` | Run in an isolated git worktree |

Key flags you will use daily:

- `--output-format text|json|stream-json` — structured output for scripts and CI.
- `--input-format` / `--include-partial-messages` / `--json-schema` — structured input and schema-constrained output.
- `--max-turns`, `--max-budget-usd` — hard limits for autonomous runs.
- `--model sonnet|opus|haiku|fable` and `--fallback-model` — model selection (model availability and aliases as of August 2026 — verify against current Anthropic documentation).
- `--agents '<json>'` / `--agent <name>` — define or select subagents inline.
- `--permission-mode default|acceptEdits|plan|auto|dontAsk|bypassPermissions` — see §11.9.
- `--allowedTools` / `--disallowedTools`, `--add-dir`, `--mcp-config`, `--strict-mcp-config`.
- `--effort low|medium|high|xhigh|max|ultracode` — adaptive thinking effort.
- `--append-system-prompt` — extend the system prompt (useful in CI).
- `--bare` — skip auto-discovery of hooks, skills, plugins, MCP servers, auto memory, and CLAUDE.md so scripted calls start faster.
- `--fork-session`, `--resume`, `--remote-control`, `--chrome`, `--ide`, `--safe-mode`.

Inside the interactive terminal UI: press `Shift+Tab` to cycle permission modes; `Esc` stops Claude mid-action; `Esc Esc` or `/rewind` opens the rewind menu (every action creates a checkpoint, so you can restore conversation state, code state, or both). Type `/` for command completion, `↑` for history, `Ctrl+G` to open the plan in your editor, `Ctrl+B` to background a running task, and `Ctrl+E` on a permission prompt for a risk explanation (Anthropic Docs, Jul 2026).

#### Slash commands are now skills

Session-management commands (`/clear`, `/help`, `/exit`, `/init`, `/memory`, `/permissions`, `/sandbox`, `/hooks`, `/mcp`, `/agents`, `/model`, `/effort`, `/compact`, `/context`, `/usage`, `/status`) remain. Custom slash commands have been **merged into skills**: a file at `.claude/commands/deploy.md` and a skill at `.claude/skills/deploy/SKILL.md` both create `/deploy` (Anthropic Docs, Aug 2026). Skills support YAML frontmatter (`description`, `disable-model-invocation`, `allowed-tools`, `context: fork`, `agent`, `model`, `effort`, `argument-hint`), `$ARGUMENTS` substitution, and dynamic context injection with `` !`command` `` backtick syntax.

Bundled skills include `/doctor` (diagnostics), `/code-review`, `/batch`, `/debug`, `/loop` (repeat a task on an interval), and `/claude-api`, plus verification skills `/run` and `/verify` (v2.1.145+). Example skill:

```markdown
---
description: Summarize uncommitted changes
---
Review this diff and summarize the intent, risks, and missing tests:

!`git diff HEAD`
```

Save it as `~/.claude/skills/summarize-changes/SKILL.md` and invoke `/summarize-changes`.

### 11.3 IDE integrations

#### VS Code extension (GA)

The native VS Code extension is the recommended way to use Claude Code in VS Code. It bundles its own copy of the CLI (the standalone CLI install is only needed to run `claude` in the integrated terminal), requires VS Code 1.94.0+, and works with any paid Claude subscription or Console account — no API key needed. Capabilities: review and edit Claude's plans before accepting them, auto-accept edits, @-mention files with line ranges from your selection (`Option+K`/`Alt+K` inserts a reference like `@file.ts#5-10`), conversation history, and multiple conversations in separate tabs or windows. It also installs into Cursor and other VS Code forks via Open VSX (Anthropic Docs, Aug 2026).

#### JetBrains plugin

A JetBrains plugin exists and shares the same configuration directory (`~/.claude/`) and permission-mode labeling as the VS Code extension (Anthropic Docs, Aug 2026). *Caveat: dedicated JetBrains feature-parity details (supported IDEs, diff viewing) were not captured in our research — verify against the current JetBrains plugin documentation.*

### 11.4 Memory: CLAUDE.md, rules, and auto memory

Memory files are how you give Claude Code persistent, durable knowledge about your project and your preferences. There are four scopes, loaded in a hierarchy (Anthropic Docs, Aug 2026):

| Scope | Location | Purpose |
|---|---|---|
| Managed policy (Enterprise only) | macOS: `/Library/Application Support/ClaudeCode/CLAUDE.md`; Linux/WSL: `/etc/claude-code/CLAUDE.md`; Windows: `C:\Program Files\ClaudeCode\CLAUDE.md` | Org-wide instructions admins deploy; cannot be overridden |
| User | `~/.claude/CLAUDE.md` | Your personal preferences across all projects |
| Project | `./CLAUDE.md` or `./.claude/CLAUDE.md` | Team-shared project instructions (commit to git) |
| Local | `./CLAUDE.local.md` | Personal project notes (add to `.gitignore`) |

CLAUDE.md files in the directory hierarchy *above* the working directory load in full at launch; files in *subdirectories* load on demand when Claude reads files there. Key mechanics:

- **Imports**: `@path/to/import` pulls in another file, up to four hops deep. Claude Code reads `CLAUDE.md`, not `AGENTS.md` — if your repo uses AGENTS.md, create a CLAUDE.md that imports it.
- **Size discipline**: target under 200 lines per file; longer files consume context and reduce adherence.
- **Path-scoped rules**: `.claude/rules/*.md` files with `paths:` YAML frontmatter apply only when Claude works with files matching those patterns — ideal for monorepos (`claudeMdExcludes` can skip unwanted files).
- **Auto memory** (on by default): Claude takes its own per-project notes in `~/.claude/projects/<project>/memory/MEMORY.md`; the first 200 lines or 25KB load at the start of every conversation. Toggle via `/memory` or the `autoMemoryEnabled` setting.
- **Managed embedding**: the `claudeMd` key in managed-settings.json embeds org instructions directly.
- Run `/init` in a new project to generate a starter CLAUDE.md.

### 11.5 Repository understanding: agentic exploration, not an index

A common misconception: Claude Code does **not** build a persistent index or embedding database of your repository. It explores your codebase **agentically and on demand** at query time, using its built-in tools (Glob, Grep, Read) and the read-only **Explore** subagent, guided by your CLAUDE.md files (Anthropic Docs, Aug 2026). "Claude Code reads your project files as needed. You don't have to manually add context."

Practical consequences:

1. Ask questions the way you would ask a senior engineer: `How does logging work?`, `Why does this code call foo() instead of bar() on line 333?`
2. Control exploration depth with the Explore agent's thoroughness levels: **quick**, **medium**, or **very thorough**.
3. In very large repos, point Claude at the right subtree first (`read /src/auth and understand how we handle sessions`) rather than asking it to "understand the whole codebase" — the failure mode Anthropic calls "infinite exploration."
4. For typed languages, optional LSP-based code-intelligence plugins give Claude precise symbol navigation instead of text-based search.
5. `/init` bootstraps project understanding by generating a CLAUDE.md; auto memory accumulates discoveries across sessions.

### 11.6 Everyday coding workflows

Anthropic's documented best-practice workflow is a four-phase loop — **explore → plan → implement → commit** — with verification at every step. "Give Claude a way to verify its work… the single highest-leverage thing you can do" (Anthropic Docs, Jul 2026).

- **Code generation**: `add a hello world function to the main file` scales up to full features when you first ask Claude to read the relevant subsystem and propose a plan (use plan mode, §11.9).
- **Refactoring**: `refactor the authentication module to use async/await instead of callbacks`. Multi-file edits are native — Claude uses Edit/Write tools across files, and every action creates a checkpoint you can rewind.
- **Debugging**: `there's a bug where users can submit empty forms - fix it`. Claude locates the relevant code, understands context, implements a fix, and runs tests if available. The `/debug` skill structures this.
- **Testing**: `write unit tests for the calculator functions`, or fold tests into implementation: `write tests for the callback handler, run the test suite and fix any failures`.
- **Code review**: `review my changes and suggest improvements`, or the bundled `/code-review` skill; in CI, GitHub Actions and `/autofix-pr` automate review loops (§11.11).
- **Verification against the running app**: `/run` and `/verify` confirm changes against the live application, not just the test suite (v2.1.145+).

Context discipline matters: `/clear` between unrelated tasks, and if you have corrected Claude more than twice, run `/clear` and restart with a more specific prompt (Anthropic Docs, Jul 2026).

> **Try it — The four-phase loop on a real bug.** In a project with a test suite: (1) in plan mode, ask Claude to explore the module containing a known bug; (2) ask for a written fix plan and critique it; (3) approve the plan and have Claude implement it with a failing test first; (4) ask Claude to run the suite, fix failures, and commit with a descriptive message. Use `/rewind` once during the exercise to experience checkpoint restore.

### 11.7 Agentic coding: subagents and hooks

#### Subagents

Subagents are independent Claude Code agents that run in their own context window with a custom system prompt, specific tool access, and independent permissions. Use them to preserve main-conversation context, enforce constraints, and control costs by routing tasks to faster, cheaper models like Haiku (Anthropic Docs, Aug 2026).

Built-in subagents include **Explore** (read-only search and analysis; inherits the main model, capped at Opus on the API), **Plan**, **general-purpose**, and helpers like `statusline-setup` and `claude-code-guide`. Custom subagents are Markdown + YAML files in `.claude/agents/` (project) or `~/.claude/agents/` (personal):

```markdown
---
name: code-improver
description: Suggests concrete code improvements
model: haiku
tools: Read, Grep, Glob
---
You review code and propose small, high-leverage improvements…
```

Frontmatter fields: `name`, `description`, `tools`, `disallowedTools`, `model` (`sonnet|opus|haiku|fable|<id>|inherit`), `permissionMode`, `maxTurns`, `skills`, `mcpServers`, `hooks`, `memory`, `background`, `effort`, `isolation: worktree`, and `initialPrompt`.

Limits and behavior (as of August 2026 — verify against current documentation, as these were introduced across recent versions):

- At most **200 subagents per session** (`CLAUDE_CODE_MAX_SUBAGENTS_PER_SESSION`, v2.1.212+).
- **20 concurrent** subagents (`CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS`, v2.1.217+).
- Nesting **depth 3** (`CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH`).
- Since v2.1.198, subagents **run in the background by default**; invoke them via natural language, `@-mention`, or `claude --agent <name>`; resume one via SendMessage; `/subtask` forks the conversation (v2.1.212+).
- `claude --bg "investigate the flaky test"` launches background agents directly.

An **experimental** "agent teams" mode coordinates multiple sessions with shared tasks, messaging, and a team lead (`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`); it consumes roughly 7× more tokens than standard sessions and is disabled by default (Anthropic Docs, Aug 2026).

#### Hooks

Hooks are user-defined automations that execute automatically at specific points in the Claude Code lifecycle: shell commands, HTTP endpoints, MCP tool calls, LLM-prompt evaluators, or (experimental) agent evaluators. Roughly **30 lifecycle events** are exposed — `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PermissionDenied`, `PostToolUse`, `PostToolUseFailure`, `Notification`, `SubagentStart`, `SubagentStop`, `TaskCreated`, `TaskCompleted`, `Stop`, `PreCompact`, `PostCompact`, `SessionEnd`, `WorktreeCreate`, `FileChanged`, `ConfigChange`, and more (Anthropic Docs, Aug 2026). Five handler types: `command`, `http`, `mcp_tool`, `prompt`, `agent`.

Hooks receive JSON on stdin and return JSON on stdout. Exit code 2 is a blocking error — a `PreToolUse` hook exiting 2 blocks the tool call. `PreToolUse` can also return structured decisions: `permissionDecision: allow|deny|ask|defer` plus `updatedInput` to rewrite the call. Hooks are defined in `settings.json` under `"hooks"`, in plugin `hooks/hooks.json`, or in skill/agent frontmatter; `async: true` runs them in the background, and enterprises can enforce `allowManagedHooksOnly`.

Canonical example — block destructive commands:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "jq -e 'select(.tool_input.command | test(\"rm -rf\")) | {permissionDecision: \"deny\"}' || true" }]
      }
    ],
    "PostToolUse": [
      { "matcher": "Edit|Write", "hooks": [{ "type": "command", "command": "./scripts/run-linter.sh" }] }
    ]
  }
}
```

A read-only SQL guardrail (subagent + PreToolUse hook exiting 2 on INSERT/UPDATE/DELETE) and an async test runner after Write/Edit are documented end-to-end in the hooks reference.

### 11.8 MCP in Claude Code

The Model Context Protocol (MCP) is the open standard for connecting AI tools to external systems. Claude Code is a full MCP client supporting stdio, HTTP, SSE, and WebSocket transports, and can connect to hundreds of external tools and data sources (Anthropic Docs, Aug 2026):

```bash
# HTTP server with OAuth
claude mcp add --transport http notion https://mcp.notion.com/mcp

# stdio server with env vars
claude mcp add --env AIRTABLE_API_KEY=YOUR_KEY --transport stdio airtable -- npx -y airtable-mcp-server
```

Three configuration scopes:

| Scope | File | Notes |
|---|---|---|
| local (default) | `~/.claude.json` | Private to you, this project |
| project | `.mcp.json` | Shared via version control; requires approval |
| user | `~/.claude.json` | Available across all your projects |

Management commands: `claude mcp list|get|remove|login|logout|add-json|add-from-claude-desktop|reset-project-choices`, plus the in-session `/mcp` panel with OAuth 2.0 flows. **Tool search is enabled by default** — MCP tools are deferred rather than loaded into context upfront (tune with `ENABLE_TOOL_SEARCH` and `alwaysLoad`). MCP output warns above 10k tokens and caps at 25k by default (`MAX_MCP_OUTPUT_TOKENS`).

Claude Code can itself **run as an MCP server** — `claude mcp serve` — so other MCP clients can drive it. Enterprises manage servers via `managed-mcp.json` plus `allowedMcpServers`/`deniedMcpServers`. Documented practical examples include Sentry error monitoring (`https://mcp.sentry.dev/mcp`), the GitHub remote MCP server, and PostgreSQL via DBHub.

### 11.9 Permissions and sandboxing

#### Permission modes and rules

Claude Code's permission system is enforced by the tool, not the model: rules are evaluated in order **deny → ask → allow**, and six modes govern the default posture (Anthropic Docs, Aug 2026):

| Mode | Behavior |
|---|---|
| `default` (labeled Manual) | Prompts on first use of each tool |
| `acceptEdits` | Auto-accepts file edits |
| `plan` | Plan mode: read-only exploration until you approve a plan |
| `auto` | Auto-approves tool calls with background safety checks (a classifier model reviews commands before they run) |
| `dontAsk` | Auto-denies anything not pre-approved |
| `bypassPermissions` | Skips prompts entirely — only in isolated containers/VMs (`--dangerously-skip-permissions`) |

Fine-grained rules target tools and arguments: `Bash(npm run build)`, `Read(./.env)`, `WebFetch(domain:example.com)`, `mcp__puppeteer__*`, `Agent(Explore)`. Built-in read-only Bash commands (`ls`, `cat`, `grep`, read-only `git`) run without prompts. Settings precedence: **managed settings > command line > local project > shared project > user**, and a workspace-trust dialog gates project-level allow rules. An autonomous lint-fix run looks like: `claude --permission-mode auto -p "fix all lint errors"`.

#### Sandboxing (GA on macOS/Linux/WSL2)

The sandboxed Bash tool lets Claude run most shell commands without stopping to ask permission, because the operating system enforces the boundary for every command and its child processes: macOS **Seatbelt**, Linux/WSL2 **bubblewrap + socat** (Anthropic Docs, Aug 2026). Native Windows is not supported.

Key configuration: `sandbox.enabled`, `filesystem.allowWrite/denyWrite/denyRead/allowRead`, `network.allowedDomains/deniedDomains`, and `sandbox.credentials` to deny or `mask` credentials (with `injectHosts` and `network.tlsTerminate`). **Auto-allow mode** automatically permits sandboxable commands; commands that cannot be sandboxed fall back to the regular permission flow. `allowUnsandboxedCommands: false` enables strict sandbox mode. Enterprise lockdown example:

```json
{ "sandbox": { "enabled": true, "failIfUnavailable": true, "allowUnsandboxedCommands": false } }
```

Documented limitations: no TLS inspection by default, potential Unix-socket escalation, and it is not a complete isolation boundary — treat it as a strong guardrail, not a security container.

### 11.10 Headless mode and the Agent SDK

**Headless mode** runs Claude non-interactively for scripts and CI:

```bash
claude -p "List all API endpoints" --output-format json
claude -p "summarize yesterday's commits" --output-format stream-json --max-turns 5 --max-budget-usd 0.50
```

Supporting flags include `--input-format stream-json`, `--json-schema` (structured output), `--no-session-persistence`, and `--bare` (fast startup with no auto-discovery). A documented fan-out pattern:

```bash
for file in $(cat files.txt); do
  claude -p "Migrate $file from React to Vue…" --allowedTools "Edit,Bash(git commit *)"
done
```

The **Claude Agent SDK** (Python and TypeScript) exposes the same agent loop, tools, hooks, subagents, MCP, and permissions programmatically; to drive the same loop from another language, run the CLI as a subprocess with `-p` and `--output-format json` (Anthropic Docs, Aug 2026). Licensing note: unless previously approved, Anthropic does not allow third-party developers to offer claude.ai login or rate limits for their products, including agents built on the Agent SDK.

### 11.11 GitHub Actions

The Claude Code GitHub Action (GA) — `anthropics/claude-code-action@v1`, built on the Agent SDK — responds to `@claude` mentions in PRs and issues: analyzing code, creating pull requests, implementing features, and fixing bugs (Anthropic Docs, Aug 2026). Set it up interactively with `/install-github-app` in the terminal.

```yaml
- uses: anthropics/claude-code-action@v1
  with:
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    prompt: "Review this PR for correctness and missing tests"
    claude_args: "--max-turns 10 --model claude-sonnet-5"
```

v1.0 breaking changes from the beta: `mode` removed (auto-detected), `direct_prompt` renamed to `prompt`, and `custom_instructions` replaced by `claude_args: --append-system-prompt`. The action is secure by default (your code stays on GitHub's runners), supports skills in prompts (`/code-review:code-review …`), scheduled automations (e.g., a daily commit-summary cron), and Amazon Bedrock / Google Cloud Vertex via OIDC (`use_bedrock: "true"` / `use_vertex: "true"`). `/autofix-pr` can watch a pull request and automatically respond to CI failures and review comments.

### 11.12 Claude Code on the web and mobile (Research Preview)

Claude Code on the web (Research Preview) runs tasks on Anthropic-managed cloud infrastructure at **claude.ai/code** for Pro, Max, and Team users, and for Enterprise users with premium or Chat + Claude Code seats (Anthropic Docs, Aug 2026). Sessions persist even if you close your browser, and you can monitor them from the Claude mobile app.

- `claude --cloud "Fix the authentication bug in src/auth/login.ts"` creates a new cloud session; each `--cloud` command creates its own session, enabling parallel tasks.
- `claude --teleport` pulls a cloud session into your terminal to continue locally.
- Security: isolated virtual machines, network access controls, and credential protection — sensitive credentials such as git credentials or signing keys are never inside the sandbox.
- Limitations: shares account rate limits; GitHub required for clone/PR workflows (GitLab/Bitbucket via bundle upload, no push-back); unavailable on Bedrock/Vertex/Foundry; org IP allowlists break cloud sessions.
- Remote Control (`--remote-control`) and `/web-setup` connect local and cloud workflows. A documented hybrid pattern: plan locally with `--permission-mode plan`, commit the plan, then `claude --cloud "Execute the migration plan in docs/migration-plan.md"`.

### 11.13 Costs and usage limits

Claude Code is metered in one of two ways: subscription seat allowances or API token billing (Anthropic Docs, Aug 2026).

- **Subscription seats**: each member's usage draws from a per-seat allowance that resets on a **rolling five-hour window** plus a **weekly window**. The allowance is **shared with Claude chat and Cowork**, and its size depends on seat tier (Standard or Premium). The free Claude.ai plan excludes Claude Code entirely.
- **API billing**: per-token consumption at API rates; prompt-cache lifetime is an hour on subscriptions versus five minutes on API keys/cloud providers.
- **Official averages**: across enterprise deployments, average cost is about **$13 per developer per active day** and $150–250 per developer per month, with 90% of users below $30 per active day.
- Use `/usage` for detailed session token statistics; rate-limit sizing guidance exists per org size (e.g., 1–5 users → 200k–300k TPM/user).

> **As of August 2026 — verify against current Anthropic documentation.** Plan price points (Pro/Max/Team tiers) circulate mainly through secondary sources; a reported late-July 2026 doubling of 5-hour Claude Code rate limits with removal of peak-hour throttling for Pro/Max (weekly caps unchanged) is a third-party report we could not confirm against an official announcement. Do not quote exact seat prices from this chapter in customer-facing material.

### 11.14 Claude Code Enterprise

Enterprise deployment layers administrative control on top of everything above (Anthropic Docs, Aug 2026):

- **Managed settings**: administrators deploy settings that cannot be overridden by user or project settings — delivered via MDM/OS-level policies, managed settings files, server-managed settings, or a self-hosted Claude apps gateway. Managed-only keys include `allowManagedHooksOnly`, `allowManagedMcpServersOnly`, `allowManagedPermissionRulesOnly`, `disableSideloadFlags`, `strictKnownMarketplaces`, `blockedMarketplaces`, `strictPluginOnlyCustomization`, `forceRemoteSettingsRefresh`, and sandbox lockdowns (`allowManagedReadPathsOnly`, `allowManagedDomainsOnly`).
- **Managed CLAUDE.md and managed MCP**: org-wide instructions via the managed policy scope or the `claudeMd` key; org-approved MCP servers via `managed-mcp.json`.
- **Seat tiers**: Standard and Premium seats determine allowance sizes; controls live in the claude.ai admin console. (*Caveat: granular seat-assignment workflow details were not captured in our research — verify in the admin console docs.*)
- **Analytics**: org analytics include a spend report (estimated spend per user and per model, CSV export); on the Enterprise plan, the **Enterprise Analytics API** returns per-user usage and cost reports.
- **Authentication**: Anthropic first-party login, or enterprise cloud providers — Amazon Bedrock, Google Cloud's Agent Platform (Vertex), or Microsoft Foundry — or a self-hosted gateway (`/login` opens on the Cloud gateway screen).

**Secure development best practices for enterprises**: keep developers out of `bypassPermissions` outside containers; prefer sandbox auto-allow plus `dontAsk`-style managed deny rules for secrets paths (`.env`, signing keys); enforce managed hooks for lint/test gates; and use `failIfUnavailable` so sessions stop rather than fall back unsandboxed.

**Large-codebase navigation best practices**: (1) maintain a concise root CLAUDE.md (<200 lines) plus path-scoped `.claude/rules/` per subsystem; (2) use `claudeMdExcludes` to keep monorepo noise out of context; (3) scope exploration prompts to subtrees and use the Explore subagent at "medium" thoroughness before escalating to "very thorough"; (4) let auto memory accumulate per-project discoveries; (5) consider LSP code-intelligence plugins for precise symbol navigation in typed languages; (6) add `--add-dir` for cross-repo work rather than running from the filesystem root.

### 11.15 End-to-end workflow 1: Issue → implementation → tests → PR

This walkthrough adapts Anthropic's documented OAuth feature example (Anthropic Docs, Jul 2026) into a repeatable issue-to-PR procedure.

1. **Explore (plan mode).** Start with `Shift+Tab` into plan mode: `read /src/auth and understand how we handle sessions and login`. Claude explores read-only and cannot change anything.
2. **Plan.** `I want to add Google OAuth (issue #412). What files need to change? … Create a plan.` Review the plan in your editor with `Ctrl+G`; request changes until it is right.
3. **Approve and implement.** Accept the plan (switching to a mode that permits edits): `implement the OAuth flow from your plan. write tests for the callback handler, run the test suite and fix any failures.`
4. **Verify.** Run `/verify` to confirm behavior against the running app, not just the test suite; fix anything it surfaces.
5. **Review.** `/code-review` (or a `code-improver` subagent: `Use the code-improver agent to suggest improvements in this project`).
6. **Commit and open the PR.** `commit with a descriptive message and open a PR`. If CI fails or reviewers comment, `/autofix-pr` (with the GitHub App installed) or an `@claude` mention in the PR triggers the GitHub Action to respond.

### 11.16 End-to-end workflow 2: Legacy refactor with plan mode and cloud handoff

Goal: migrate a legacy callback-based module to async/await across many files without destabilizing main.

1. **Isolate.** Run in a worktree so the refactor cannot disturb your working branch: `claude -w`.
2. **Deep exploration.** `Use subagents to investigate how our authentication system handles token refresh` — the Explore subagent maps dependencies while keeping your main context clean; escalate thoroughness only if needed.
3. **Plan mode.** `refactor the authentication module to use async/await instead of callbacks — first produce a migration plan with per-file steps and a rollback strategy.` Save the approved plan to the repo: `write the plan to docs/migration-plan.md and commit it`.
4. **Bounded execution.** Execute in batches with verification gates: `implement steps 1–3 of docs/migration-plan.md, run the test suite, fix failures, then stop`. Repeat per batch; `/rewind` any batch that goes sideways — checkpoints restore code and conversation.
5. **Delegate the long tail.** For dozens of mechanical file conversions, either fan out headlessly (`for file in $(cat files.txt); do claude -p "Migrate $file per docs/migration-plan.md" --allowedTools "Edit,Bash(git commit *)"; done`) or hand off to the cloud: `claude --cloud "Execute the migration plan in docs/migration-plan.md"`, then `--teleport` the session back to review locally.
6. **Guardrails for the legacy repo.** Add a PreToolUse hook requiring tests to pass after every Edit/Write, and a path-scoped rule in `.claude/rules/legacy.md` (`paths: ["src/legacy/**"]`) codifying the migration conventions so every future session applies them automatically.

> **Try it — Cloud-to-terminal handoff.** With claude.ai/code access: create a plan locally in plan mode, commit it to a branch, launch `claude --cloud "Execute the plan in docs/<your-plan>.md"`, monitor the session from the mobile app, then run `claude --teleport` to pull it into your terminal and finish the review locally. Note exactly which state (commits, conversation, checkpoints) survived the handoff.

### Chapter summary

You have covered Claude Code end to end: installation on every platform; the CLI surface including headless `-p` mode, `--agents`, `--worktree`, `--permission-mode auto/dontAsk`, and `--cloud`/`--teleport`; skills-based slash commands; VS Code and JetBrains integrations; the four-scope CLAUDE.md memory system with imports, path-scoped rules, and 200-line/25KB auto memory; on-demand agentic repository exploration (with no persistent index); generation, refactoring, debugging, testing, review, and multi-file workflows; subagents (200/session, 20 concurrent, depth 3, background by default) and hooks (~30 events, 5 handler types); MCP with three scopes, OAuth, and `claude mcp serve`; permission modes and OS-level sandboxing; the Agent SDK and GitHub Actions; web/mobile cloud sessions; the ~$13/developer/active-day cost profile with shared 5-hour and weekly windows; and enterprise managed settings, seat tiers, and analytics — anchored by two full workflows you can adapt to your own repositories today.


---
