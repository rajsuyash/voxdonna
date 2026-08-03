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
