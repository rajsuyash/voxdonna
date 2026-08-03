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

:::exercise Try it — Exercise 1: Build a structured extractor
Write a script that (a) defines a schema for a meeting summary (`attendees`, `decisions[]`, `action_items[]` with owner and due date), (b) pipes a raw meeting transcript through `messages.parse` (Python) or `client.messages.parse` (TS), and (c) prints the parsed object as a table. Then break it: feed a transcript with no decisions and confirm the output still validates with empty arrays rather than hallucinated entries. Bonus: re-implement the same extraction using constrained tool use and compare.
:::

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
