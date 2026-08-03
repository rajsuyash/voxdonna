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
