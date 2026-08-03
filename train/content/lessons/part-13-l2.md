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
