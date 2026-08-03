### 15. Claude Agent SDK

The **Claude Agent SDK** (formerly the Claude Code SDK, renamed in late 2025/early 2026) packages the full Claude Code agent loop for embedding in your own applications: `claude-agent-sdk` (Python 3.10+) and `@anthropic-ai/claude-agent-sdk` (TypeScript, which bundles the native Claude Code binary). A single async **`query()`** replaces the manual tool loop from Section 6 — it returns an async iterable of streamed messages while the SDK runs the loop and built-in tools (Read, Write, Edit, Bash, Glob, Grep, WebSearch, WebFetch, AskUserQuestion).

```python
import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions

async def main():
    options = ClaudeAgentOptions(
        allowed_tools=["Read", "Grep", "Bash"],
        permission_mode="acceptEdits",
    )
    async for message in query(
        prompt="Find every TODO comment in src/ and open a summary issue list.",
        options=options,
    ):
        print(message)

asyncio.run(main())
```

Key options: `allowedTools` and `permissionMode` (`default` / `acceptEdits` / `plan` / `dontAsk` / `bypassPermissions`); **hooks** (`PreToolUse`, `PostToolUse`, `Stop`, `SessionStart`, `SessionEnd`, `UserPromptSubmit`) — in-process callbacks with matchers, your enforcement point for policy; **subagents** (`agents`) with their own context window and tool set, attributed via `parent_tool_use_id`; **sessions** via `session_id` plus `resume` for continuity; MCP servers via `mcpServers`; and `settingSources` to control `.claude/` directory loading. It also runs against Bedrock and Vertex via environment variables. Do not confuse it with **Claude Managed Agents**, the hosted REST service (priced per session-hour) — the Agent SDK runs in *your* process.

### 16. Chapter Summary and Production Checklist

You now have the full developer surface: one endpoint, eight SDKs, a streaming contract, a tool loop you own, structural guarantees via structured outputs, and an economics stack — caching at 0.1× reads, batching at 50% off, adaptive effort, and context editing — that determines whether your integration is affordable at scale. Before shipping, confirm you: store keys in the environment; pin `anthropic-version`; handle in-stream errors; differentiate 429 vs 529 with distinct retry policies; verify cache hits in `usage`; route latency-insensitive work to batches; and gate irreversible actions behind Agent SDK hooks or human approval.


---
