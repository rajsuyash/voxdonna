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
