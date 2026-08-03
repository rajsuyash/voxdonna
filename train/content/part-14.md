# Part 14: API & Developer Guide

In this chapter you will move from being a user of Claude to being a builder with Claude. You will learn how the Claude Developer Platform is organized, how to authenticate, how the Messages API is structured, and how to use the capabilities that distinguish production integrations from toy scripts: streaming, tool use, structured outputs, vision and PDF inputs, prompt caching, batching, server tools, thinking controls, context management, and the Claude Agent SDK. Every concept comes with a working example.

> **Volatile facts:** Pricing, rate limits, tool versions, and model availability change frequently. All figures in this chapter are **as of August 2026 — verify against current Anthropic documentation** (platform.claude.com/docs) before committing to architecture or budget decisions.

---

### 1. The Claude Developer Platform

The **Claude Developer Platform** is Anthropic's programmatic surface for Claude. It consists of three pieces you will touch constantly:

- **The API itself**, reached over HTTPS at `https://api.anthropic.com`, with `POST /v1/messages` as the central endpoint.
- **The Anthropic Console**, the web UI where you create API keys, purchase prepaid credits, view usage, and inspect rate limits (Settings → Limits).
- **Official SDKs** for eight languages, plus dedicated clients for the cloud-hosted variants: `AnthropicBedrock` (AWS Bedrock), `AnthropicVertex` (Google Vertex AI), and `AnthropicFoundry` (Microsoft Foundry). (Anthropic Docs, 2026)

Two commercial facts shape everything else. First, API billing is **prepaid credits**, completely separate from Claude Pro/Max/Team/Enterprise subscriptions — a seat license buys you nothing at the API layer. Second, API keys (`sk-ant-…`) are created in the Console, shown **only once**, and are conventionally stored in the `ANTHROPIC_API_KEY` environment variable, which every official SDK reads automatically. Never hard-code a key; never commit one to version control.

### 2. Authentication

Every request requires three headers:

| Header | Purpose |
|---|---|
| `x-api-key` | Your API key. Note: API keys use `x-api-key`, **not** `Authorization: Bearer` (bearer tokens are reserved for short-lived OAuth / Workload Identity Federation credentials). |
| `anthropic-version` | Pins the API contract, e.g. `2023-06-01`. Always send it explicitly rather than relying on the default. |
| `Content-Type` | `application/json` |

Beta features are enabled with an additional `anthropic-beta` header carrying a dated feature flag (you will see `files-api-2025-04-14` later). (Anthropic authentication docs, Jun 2026)

### 3. The Messages API: Anatomy of a Request

The Messages API is a single-turn completion over a **conversation you supply**. A minimal request body contains:

- `model` — the model ID.
- `max_tokens` — **required**; the hard ceiling on output tokens for this turn.
- `messages` — an array of message objects alternating `user` and `assistant` roles. Each message's `content` is either a plain string or an array of **content blocks**.

A **content block** is a typed JSON object. The block types you will use most: `text`, `image`, `document`, `tool_use`, `tool_result`, and `thinking`; server-side tools add `server_tool_use` and result types such as `web_search_tool_result`.

Optional request fields include:

| Field | Purpose |
|---|---|
| `system` | The **system prompt**: top-level instructions that frame the whole conversation (persona, rules, output contract). |
| `tools`, `tool_choice` | Tool definitions and selection policy (`auto` / `any` / `tool` / `none`). |
| `stream` | `true` for server-sent-event streaming (Section 5). |
| `temperature`, `top_p`, `stop_sequences` | Sampling controls. |
| `thinking` / `output_config` | Thinking controls and structured output (Sections 11–12). |
| `metadata` | Request tagging (e.g. `user_id`) for your own analytics. |
| `context_management` | (Beta) Context editing strategies (Section 13). |
| `cache_control` | Prompt-caching breakpoints (Section 8). |

Two identifiers are worth memorizing. Client-executed tool calls produce IDs prefixed `toolu_`; server-side tool calls use `srvtoolu_`. You must return a `tool_result` for a `toolu_` call, but **never** for a `srvtoolu_` call — Anthropic's infrastructure already handled it. Also note the stop reasons: besides `end_turn`, `max_tokens`, and `stop_sequence`, long agentic runs can return `pause_turn` (the model paused mid-task, e.g. during a long multi-search; send the conversation back to continue) and `model_context_window_exceeded`.

#### A first call with cURL

```bash
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-5",
    "max_tokens": 1024,
    "system": "You are a terse SQL tutor. Answer in two sentences max.",
    "messages": [
      {"role": "user", "content": "What does a LEFT JOIN return that an INNER JOIN does not?"}
    ]
  }'
```

The response's `content` is itself an array of blocks (typically one `text` block), plus `stop_reason` and a `usage` object with input/output token counts — the object you will monitor for cost control.

### 4. Official SDKs

Anthropic publishes open-source, Stainless-generated SDKs for **Python, TypeScript/JavaScript, Java, Go, Ruby, PHP, and C# (eight languages)**, each with a `beta` namespace for early features. (Anthropic SDKs, Jun 2026)

```bash
pip install anthropic          # Python
npm install @anthropic-ai/sdk  # TypeScript / JavaScript
```

Both read `ANTHROPIC_API_KEY` automatically:

```python
from anthropic import Anthropic
client = Anthropic()
```

> **Note:** Anthropic was reported in May 2026 to be acquiring Stainless, the vendor that generates these SDKs. The acquisition status was unconfirmed as of August 2026; it does not affect how you use the SDKs.

### 5. Streaming (SSE)

Set `stream: true` and the API responds with **Server-Sent Events (SSE)** — a long-lived HTTP response delivering typed events as tokens are generated. The event lifecycle is:

1. `message_start` — exactly once per stream; carries the skeleton message.
2. `content_block_start` → one or more `content_block_delta` events → `content_block_stop`, repeated per block. Delta subtypes: `text_delta`, `input_json_delta` (tool arguments), `thinking_delta`, and a closing `signature_delta` for thinking blocks.
3. `message_delta` — final `stop_reason` and cumulative `usage`.
4. `message_stop`.

Two production rules. First, handle deltas incrementally and never assume one delta per word. Second — and this is the classic bug — **errors can arrive mid-stream**: the connection opens with HTTP 200 and later delivers an `error` event (e.g. `overloaded_error`). Status-code-only error handling will miss it; always handle the in-stream `error` event. The SDKs wrap this in helpers:

```python
with client.messages.stream(
    model="claude-sonnet-5",
    max_tokens=2048,
    messages=[{"role": "user", "content": "Draft a haiku about rate limits."}],
) as stream:
    for text in stream.text_stream:
        print(text, end="", flush=True)
    final = stream.get_final_message()  # stop_reason + usage
```

### 6. Tool Use / Function Calling

**Tool use** lets Claude request that *your* code execute a function. You declare tools with:

- `name` — must match `^[a-zA-Z0-9_-]{1,64}$`.
- `description` — Claude reads this to decide when to call; write it like documentation.
- `input_schema` — a JSON Schema `object` describing arguments (omit `$schema` / `additionalProperties`).

The **tool loop** is the core agent pattern:

1. Send a request with `tools`. Claude may answer with a `tool_use` content block (`id`, `name`, `input`) and `stop_reason: "tool_use"`.
2. **Your application** — not Claude — executes the function.
3. Append the assistant message (with the `tool_use` block) and a new `user` message containing a `tool_result` block referencing `tool_use_id`.
4. Repeat until Claude replies with `end_turn`.

```python
import json
from anthropic import Anthropic

client = Anthropic()

tools = [{
    "name": "get_invoice_total",
    "description": "Return the outstanding total (in USD) for a customer invoice.",
    "input_schema": {
        "type": "object",
        "properties": {"invoice_id": {"type": "string", "description": "e.g. INV-1042"}},
        "required": ["invoice_id"],
    },
}]

def get_invoice_total(invoice_id: str) -> float:
    ...  # your database call

messages = [{"role": "user", "content": "How much is still owed on INV-1042?"}]

while True:
    resp = client.messages.create(
        model="claude-sonnet-5", max_tokens=1024,
        tools=tools, messages=messages,
    )
    if resp.stop_reason != "tool_use":
        print(next(b.text for b in resp.content if b.type == "text"))
        break
    messages.append({"role": "assistant", "content": resp.content})
    results = []
    for block in resp.content:
        if block.type == "tool_use":
            total = get_invoice_total(**block.input)
            results.append({
                "type": "tool_result", "tool_use_id": block.id,
                "content": json.dumps({"total_usd": total}),
            })
    messages.append({"role": "user", "content": results})
```

Use `tool_choice` to control selection: `auto` (default), `any` (must call *some* tool), `tool` (must call a *named* tool), or `none`. For parallel tool calls, say so in the system prompt — Claude 4.x follows instructions literally, so desired "above and beyond" behaviors must be requested explicitly. Distinguish tool use from retrieval-augmented generation (RAG): tool use is an *action* contract; RAG is *context injection* — many systems combine both.

### 7. Structured Outputs

**Structured outputs (GA)** — generally available since approximately February 2026, no beta header required — come in two flavors. (Structured outputs guide, Jul 2026; verify current syntax on platform.claude.com, as this capability changed recently)

1. **JSON-schema output**: attach an `output_config.format` object carrying your schema; the response text is guaranteed to validate. In the Python SDK this is exposed as `client.messages.parse(...)`, which accepts a Pydantic model and returns `resp.parsed_output`.
2. **Constrained tool use**: force a tool call with `tool_choice: {"type": "tool", "name": ...}`; the tool's arguments are constrained to its `input_schema` — the classic pre-GA technique, still useful.

```typescript
import Anthropic from "@anthropic-ai/sdk";
import { z } from "zod";

const client = new Anthropic();

const Ticket = z.object({
  priority: z.enum(["low", "medium", "high", "critical"]),
  component: z.string(),
  summary: z.string(),
  repro_steps: z.array(z.string()),
});

const resp = await client.messages.parse({
  model: "claude-sonnet-5",
  max_tokens: 1024,
  output_format: Ticket,
  messages: [{
    role: "user",
    content: "Triage this bug report: 'Checkout page 500s when cart has a gift card and a coupon. Started Tuesday.'",
  }],
});

console.log(resp.parsed_output.priority); // typed: "low" | "medium" | "high" | "critical"
```

Prefer this over "please reply in JSON" prompting: the guarantee is structural, not behavioral.

#### Try it — Exercise 1: Build a structured extractor

Write a script that (a) defines a schema for a meeting summary (`attendees`, `decisions[]`, `action_items[]` with owner and due date), (b) pipes a raw meeting transcript through `messages.parse` (Python) or `client.messages.parse` (TS), and (c) prints the parsed object as a table. Then break it: feed a transcript with no decisions and confirm the output still validates with empty arrays rather than hallucinated entries. Bonus: re-implement the same extraction using constrained tool use and compare.

### 8. Prompt Caching

**Prompt caching (GA)** stores a reusable prefix of your request so repeated calls skip re-processing it. Mark a content block with `cache_control: {"type": "ephemeral"}` — up to **4 explicit breakpoints** per request — or use the newer **top-level automatic caching**, which caches the last cacheable block and is recommended for multi-turn conversations. TTL is **5 minutes** by default or **1 hour** (`ttl: "1h"`). Pricing (input-token multipliers): 5-minute write **1.25×**, 1-hour write **2×**, cache read **0.1×** — a 90% discount on repeated context. Minimum cacheable prefixes vary by model (e.g. ~1,024 tokens on Sonnet-class models, ~4,096 on Haiku 4.5). (Anthropic prompt caching docs, Apr 2026 — verify current pricing)

```bash
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-5",
    "max_tokens": 1024,
    "system": [
      {
        "type": "text",
        "text": "You are a legal assistant. Here is the full 40-page master services agreement: ...",
        "cache_control": {"type": "ephemeral"}
      }
    ],
    "messages": [{"role": "user", "content": "Summarize the indemnification clause."}]
  }'
```

Cache behavior rules to internalize: invalidation cascades in the order **tools → system → messages**; any byte change in a prefix invalidates everything after it; caches are scoped per workspace (since Feb 2026). Check `usage` for `cache_creation_input_tokens` and `cache_read_input_tokens` to confirm hits. A beta diagnostic (`diagnostics.previous_message_id`) compares consecutive requests to tell you why a cache missed.

### 9. Vision and PDF Inputs

**Vision.** Send an `image` content block with a base64 source (`source: {"type": "base64", "media_type": ..., "data": ...}`), a URL source, or a Files API `file_id`. Supported formats: JPEG, PNG, GIF (non-animated; first frame only), and WebP. Limits: **10 MB per image** on the API (5 MB on Bedrock/Google Vertex), at most **8000×8000 px** (larger images are resized down to roughly 1568×1568, ~1,600 input tokens each), and up to **100 images per request on 200k-context models, 600 on other models** (claude.ai chat is capped at 20 images per message). All Claude 4-series and later models support vision.

**PDF.** A `document` content block accepts a base64 PDF (`media_type: "application/pdf"`) or a `file_id`. Claude reads **both the text layer and page images**, so scanned documents, charts, and layout all come through. Limits: **100 pages and 32 MB per request**; PDFs must be standard (not password-protected). For anything larger, upload through the Files API (500 MB per file) and reference it by ID.

### 10. Batch API and Files API

**Message Batches API (GA).** Submit up to 100,000 requests (or 256 MB) as a batch via `POST /v1/messages/batches`; results arrive within 24 hours (most in under an hour) as JSONL from the `/results` endpoint, retained for 29 days. The trade: **50% off input and output tokens** in exchange for giving up latency and streaming. Expired requests are not billed. Ideal for eval sweeps, backfills, classification pipelines, and nightly enrichment jobs. Note: batches are available on the Anthropic API, Bedrock, and Vertex, but not on Claude Platform on AWS. (Older docs cite a 10,000-request cap; the 100k/256 MB figure is from 2026 sources — verify.)

**Files API (Beta; header `anthropic-beta: files-api-2025-04-14`, SDK `client.beta.files.*`).** Upload once (up to **500 MB per file**, 500 GB per organization) and reference the returned `file_id` in `document`/`image` blocks, the code execution tool, and Skills. Storage is free; you pay input tokens only when a file is used. Files persist until you DELETE them (an exception to the platform's 30-day auto-deletion default). One asymmetry to remember: only files **created by** Claude (code execution outputs, Skills artifacts) can be downloaded back; files you uploaded cannot be re-downloaded.

### 11. Thinking: Adaptive Effort vs. Legacy Budgets

Claude's reasoning controls have two generations:

- **Extended thinking (legacy)**: `thinking: {"type": "enabled", "budget_tokens": N}` — the model thinks on every request up to a fixed budget. Supported on Claude 4.5 and earlier; deprecated on 4.6; **unsupported (requests error) on Opus 4.7 and later**.
- **Adaptive thinking (current)**: `thinking: {"type": "adaptive"}` plus `output_config: {"effort": "low" | "medium" | "high" | "xhigh" | "max"}` — the model decides *whether* and *how deeply* to think per request, and interleaves thinking between tool calls automatically. (Adaptive-thinking overview, Aug 2026 — the exact per-model support matrix should be confirmed in the extended-thinking docs.)

Thinking tokens are billed as **output tokens** — you pay for the full reasoning, not just the summary shown to you. When streaming, thinking arrives as `thinking` blocks whose `signature_delta` lets you cryptographically verify they were generated by Claude. Tune `effort` as a cost/latency dial: `low` for routing and classification, `high` (the default) or above for hard reasoning.

### 12. Server Tools: Web Search and Code Execution

**Server tools** run on Anthropic's infrastructure and are declared by a versioned `type`.

**Web search tool (GA)** — declared as `web_search_20250305` (original), `web_search_20260209` (dynamic filtering: Claude runs code to filter results, cutting tokens roughly 24%, and is not zero-data-retention eligible by default), or `web_search_20260318` (response-inclusion control). Priced at **$10 per 1,000 searches** plus standard token costs; failed searches are not billed, and usage is reported in `usage.server_tool_use.web_search_requests`. Options include `max_uses`, `allowed_domains`/`blocked_domains`, and `user_location`; Console admins can disable or domain-restrict the tool org-wide. Citations arrive as `text.citations[]` with `cited_text` excerpts (≤150 characters). The companion web *fetch* tool is free (token costs only) with a `max_content_tokens` cap.

**Code execution tool** — `{"type": "code_execution_20250522"}` runs Claude-generated Python in an Anthropic-managed, **sandboxed container** that persists across turns within a conversation (up to ~1 hour, ~1 GB of state). The scientific stack (numpy, pandas, matplotlib) is preinstalled; additional packages can be pip-installed from a PyPI allowlist; there is no inbound network access. Generated files come back as `file_id` references via the Files API. Pricing: free when combined with the 20260209 web search/fetch tools; standalone, organizations get **1,550 free container-hours per month, then $0.05/hour** (5-minute minimum). (Some sources express the free allowance as ~50 hours/day — the same number, differently framed.)

Related but different: the Bash, text editor (`text_editor_20250429`), and computer-use tools are **client-side Anthropic-defined tools** — Claude emits the action, your harness executes it.

#### Try it — Exercise 2: Research-to-report pipeline

Build a script that (1) declares both `web_search_20260209` and `code_execution_20250522`, (2) asks Claude to research three competitors' pricing and chart the comparison, and (3) saves the returned chart file via the Files API. Handle the `srvtoolu_` blocks correctly (no `tool_result` from you), print `usage.server_tool_use.web_search_requests` to track search spend, and note whether you hit `pause_turn` — if so, send the conversation back to resume.

### 13. Context Editing and the Memory Tool

Long agent runs rot: stale tool results and obsolete thinking crowd the window. **Context editing (beta `context-management-2025-06-27`)** applies declarative strategies via `context_management.edits`:

- `clear_tool_uses_20250919` — clears old tool results, with options for `trigger` (on input-token count or tool-use count), `keep` (how many recent uses to retain), `clear_at_least`, `clear_tool_inputs`, and `exclude_tools`.
- `clear_thinking_20251015` — clears older thinking blocks.
- `compact_20260112` (beta `compact-2026-01-12`) — a separate **compaction** feature that summarizes prior context rather than deleting it.

Applied edits are reported back in the response so you can audit what was removed. Complementing this is the **memory tool** `memory_20250818`, a *client-side* tool: Claude issues file commands (`view`, `create`, `insert`, `delete`, `rename`, `str_replace`) against a memory directory that *your* code hosts — validation and tenant scoping are your handler's job, which is exactly what makes it enterprise-safe. Anthropic reports an 84% token reduction and a 39-point task-quality improvement when combining memory with context editing in a 100-turn evaluation (Anthropic-reported figures; validate on your own workloads). When everything still overflows, watch for the `model_context_window_exceeded` stop reason.

### 14. Errors, Rate Limits, and Retries

Error bodies follow `{"type": "error", "error": {"type": ..., "message": ...}}` plus a `request_id` (also in the `request-id` header — capture it for support escalations).

| Status | Type | Retry? |
|---|---|---|
| 400 | `invalid_request_error` | No — fix the request |
| 401 | `authentication_error` | No — check the key |
| 403 | `permission_error` | No — check access |
| 429 | `rate_limit_error` | Yes — honor `retry-after` / rate-limit headers |
| 500 | `api_error` | Yes, with backoff |
| 529 | `overloaded_error` | Yes — capped exponential backoff with jitter |

The mental model: **429 is your problem** (you are sending too fast — slow down, use the headers); **529 is the service's problem** (Anthropic-wide capacity — back off and retry). Remember that 529 can surface *inside* a 200-OK stream as an error event. The Python SDK raises `APIStatusError` subclasses so you can catch precisely.

Rate limits are **organization-level, per model class**, measured in requests per minute (RPM), input tokens per minute (ITPM — uncached; cache reads are excluded for most models), and output tokens per minute (OTPM), with token-bucket replenishment. Check yours in Console → Settings → Limits or via the Rate Limits API. In June 2026 Anthropic renamed the numeric usage tiers to **Start / Build / Scale / Custom**, with monthly spend caps ascending from hundreds of dollars (Start) to none (Custom); advancement is automatic as cumulative credit purchases grow. Deliberately, this chapter quotes no exact RPM/ITPM figures — they vary by tracker, model, and org, and the Console is authoritative. Design for 429s regardless: queue, backoff, and consider the Batch API for anything non-interactive.

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
