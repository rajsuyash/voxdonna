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
