# Part 19: Visual Architecture Guide

This chapter translates the major Claude Enterprise architectures into text-based diagrams you can read, copy into runbooks, and use to orient new team members. Each diagram is followed by a walkthrough of every element. All diagrams are based on documented Anthropic architecture as of August 2026 — verify volatile details against current Anthropic documentation before relying on them operationally.

### 15.1 The Claude Platform Map

```
+------------------------------------------------------------------+
|                        CLAUDE PLATFORM                           |
|                                                                  |
|  +------------------+  +------------------+  +----------------+  |
|  | Consumer & Work  |  |  Claude Code     |  |    Cowork      |  |
|  | apps (GA)        |  |  (GA)            |  |    (GA)        |  |
|  | web / desktop /  |  |  CLI, VS Code,   |  |  desktop + web/|  |
|  | mobile: Chat,    |  |  JetBrains, web, |  |  mobile (beta) |  |
|  | Projects,        |  |  mobile          |  |  local files,  |  |
|  | Artifacts,       |  |  CLAUDE.md,      |  |  connectors,   |  |
|  | Research, Memory |  |  hooks, subagents|  |  sub-agents    |  |
|  +------------------+  +------------------+  +----------------+  |
|                                                                  |
|  +-------------------------------------------------------------+ |
|  |            Connectors (remote MCP servers) + Directory      | |
|  +-------------------------------------------------------------+ |
|                                                                  |
|  +-------------------------------------------------------------+ |
|  |   API / Developer Platform (Messages API, SDKs, Batch,      | |
|  |   Files, Agent SDK)  — also via Bedrock / Vertex / Azure    | |
|  +-------------------------------------------------------------+ |
|                                                                  |
|  +-------------------------------------------------------------+ |
|  |   Models: Fable 5 | Opus 5 | Sonnet 5 | Haiku 4.5           | |
|  +-------------------------------------------------------------+ |
+------------------------------------------------------------------+
```

The platform has three user-facing surfaces and one developer surface, all sitting on the same model layer. The consumer and work apps (web, desktop, mobile) deliver Chat, Projects, Artifacts, Research, and Memory (all GA). Claude Code (GA since May 2025) is the developer agent surface across CLI, IDE integrations, web, and mobile, configured via CLAUDE.md, hooks, and subagents (Anthropic Docs, 2026). Cowork (research preview January 2026, GA spring 2026) is the no-code desktop agent for local files, connectors, and browser control, with web/mobile access in beta since July 2026. Connectors — remote MCP servers — bridge all surfaces to external systems. Underneath, the API/Developer Platform exposes the same models programmatically, including through Amazon Bedrock, Google Vertex AI, and Microsoft Azure (Anthropic, Aug 2026). The model lineup as of August 2026 is Fable 5, Opus 5 (GA 2026-07-24), Sonnet 5, and Haiku 4.5.

### 15.2 Enterprise Authentication & Provisioning Flow

```
  Corporate email domain           Identity Provider (IdP)
        |                     (Okta / Entra ID / Google Workspace)
        v                                        |
  [1] Domain capture                    [2] SAML 2.0 / OIDC SSO
   DNS TXT verification                 (Enterprise: any IdP;
        |                                Team: Google/Microsoft only)
        v                                        |
  +-----+---------------------------+            v
  |   CLAUDE ENTERPRISE ORG         |   User login routed through SSO
  |                                 |            |
  |   [3] SCIM provisioning <-------+----- IdP group membership
  |   (Enterprise only; requires    |      drives seat + role mapping
  |    SSO; create/update/deactivate|            |
  |    accounts automatically)      |            v
  |                                 |   [4] Roles & workspaces
  |   Primary Owner -> Owner ->     |   RBAC: standard roles or
  |   Admin -> User; custom roles   |   custom roles (Enterprise only,
  |   (Ent. only, assigned to       |   assigned to groups)
  |   groups) + IP allowlisting*    |
  +---------------------------------+
  * reported; not on official feature list — verify with Anthropic
```

Onboarding an enterprise org has four stages. First, **domain capture** claims your corporate email domain via DNS TXT verification, so every login with that domain routes through your SSO and existing individual accounts are pulled into the managed workspace (docs.anthropic.com, Jul 2026). Second, **SSO**: Enterprise supports SAML 2.0 and OIDC with Okta, Microsoft Entra ID, and Google Workspace — any IdP, whereas Team plan SSO is limited to Google/Microsoft. Third, **SCIM provisioning** (Enterprise only, and it requires SSO) automates account creation, role updates, and deactivation from the IdP; IdP group membership can drive seat assignment and role mapping, and SCIM-provisioned members activate automatically. Fourth, **roles and workspaces**: the standard hierarchy runs Primary Owner (one per org) → Owner → Admin → User, and custom roles — an Enterprise-only feature — are assigned to groups, not individuals. Caveat: IP allowlisting appears in several secondary sources but not on the official feature list as of August 2026 — confirm with your Anthropic account team.

### 15.3 Enterprise Data Governance Flow

```
 [User prompt]
      |
      v
 +-----------+     +------------------------+     +----------------+
 | Workspace | --> | Retention controls     | --> | Audit logs     |
 | (chat,    |     | (Enterprise only:      |     | (Enterprise;   |
 | projects, |     |  configurable; API     |     |  180 days;     |
 | files)    |     |  default 7-day; ZDR    |     |  metadata only:|
 |           |     |  by agreement)         |     |  UUIDs, actor, |
 | No model  |     +------------------------+     |  event, IP)    |
 | training  |                                          |
 | by default|                                          v
 +-----------+                              +----------------------+
      |                                     | Compliance API       |
      |                                     | (Enterprise; Admin   |
      |                                     |  keys sk-ant-admin01-|
      |                                     |  read:compliance_    |
      |                                     |  activities; full    |
      |                                     |  chat/file content)  |
      |                                     +----------------------+
      |                                                |
      v                                                v
 Encryption: TLS 1.2+ in transit,           SIEM / Datadog
 AES-256 at rest                              (official Datadog integration)
```

Every prompt you send lives inside a **workspace** governed by three concentric controls. By contract, prompts, data, and results are not used to train models by default on commercial products — there is no opt-in/opt-out toggle (Anthropic, Aug 2026). **Retention controls** (Enterprise only) let admins configure retention; the API default is 7-day deletion of inputs/outputs with a 30-day opt-in via DPA, and Zero Data Retention (ZDR) — nothing stored at rest after the response — is available for qualified accounts by commercial agreement, scoped to the Messages API and excluding Batch, Files, and several other surfaces. **Audit logs** (Enterprise only, 180 days, exported by Owners) are metadata-only: chat titles and content are excluded, only UUIDs, actor, event, IP address, and device fields appear. The **Compliance API** (enabled by the Primary Owner under Organization settings → Data and privacy) provides programmatic access to full activity, chat, and file content using Admin API keys with the `read:compliance_activities` scope, and integrates with SIEM tooling — Datadog has an official integration. Caveat: Cowork sessions were reported (May 2026) as not captured in audit/compliance data — verify current coverage.

### 15.4 MCP Architecture

```
 +--------------------- MCP HOST (Claude Desktop, Claude Code) ----+
 |                                                                 |
 |   +-- MCP Client 1 (one dedicated connection per server)        |
 |   +-- MCP Client 2                                              |
 +--------+--------------------------------------------------------+
          |                            |
   [stdio transport]          [Streamable HTTP transport]
   JSON-RPC 2.0 over          single endpoint (e.g. /mcp),
   stdin/stdout; server       POST + optional SSE; TLS;
   launched as subprocess;    many clients; horizontally
   local creds; 1 client      scalable
          |                            |
          v                            v
   +-------------+             +---------------------------+
   | LOCAL MCP   |             | REMOTE MCP SERVER         |
   | SERVER      |             | (= Claude "connector")    |
   | tools /     |             | tools / resources/prompts |
   | resources / |             | OAuth 2.1: auth code +    |
   | prompts     |             | PKCE-S256, Protected      |
   +-------------+             | Resource Metadata (RFC    |
                               | 9728), Resource Indicators|
                               | (RFC 8707), Dynamic Client|
                               | Registration (RFC 7591)   |
                               +---------------------------+
          Data layer: JSON-RPC 2.0 (lifecycle, capability
          negotiation, primitives) — identical across transports
```

The Model Context Protocol (MCP) is the open standard Anthropic introduced in November 2024 for connecting AI applications to external tools and data. It has three participants: the **host** (the AI app — Claude Desktop, Claude Code — which orchestrates everything), the **client** (one lives inside the host per server, maintaining a dedicated connection), and the **server** (which exposes tools, resources, and prompts). The protocol splits into a data layer (JSON-RPC 2.0) and a swappable transport layer. Two transports are current: **stdio**, where the client launches the server as a local subprocess — ideal for filesystem, git, and shell tools with local credentials, exactly one client; and **Streamable HTTP**, a single endpoint (for example `/mcp`) with optional server-sent events, used for shared remote servers behind TLS. Remote servers authenticate with OAuth 2.1: authorization code flow with mandatory PKCE, resource metadata discovery, audience-bound tokens, and dynamic client registration (modelcontextprotocol.io, 2026). Caveat: the 2026-07-28 spec release candidate makes MCP stateless (removing the initialize handshake and session IDs) — adoption timing varies by SDK, so pin your spec version.

### 15.5 Connector Permission Stack

```
 Effective permission = INTERSECTION of all four layers
 (Claude never gets broader access than the connecting user)

 +-------------------------------------------------------------+
 | Layer 1: Source-system permissions                          |
 |   What the authenticated user can do in Google / M365 /     |
 |   Slack / Jira itself (sharing rules, Graph permissions)    |
 +-------------------------------------------------------------+
                          ∩
 +-------------------------------------------------------------+
 | Layer 2: OAuth scopes granted at consent                    |
 |   User-scoped tokens, per-user permissions; admin consent   |
 |   for M365 (Entra Global Admin, tenant-wide)                |
 +-------------------------------------------------------------+
                          ∩
 +-------------------------------------------------------------+
 | Layer 3: MCP tool design                                    |
 |   Which tools the server exposes (read vs write tools;      |
 |   e.g. Gmail = drafts only, never send)                     |
 +-------------------------------------------------------------+
                          ∩
 +-------------------------------------------------------------+
 | Layer 4: Claude-side admin & user controls                  |
 |   Org Owner per-connector policy: Always allow / Needs      |
 |   approval / Blocked; org-wide custom connectors;           |
 |   managed-mcp.json allowlist via MDM (Jamf/Intune)          |
 +-------------------------------------------------------------+
                          =
              What Claude can actually do in a session
```

Connectors are remote MCP servers reached from Anthropic's cloud, but their effective power is gated by four stacked layers that intersect — never union (technovids connector guide, Jun 2026). Layer 1 is the source system: Claude acts as the signed-in user, so Slack private channels, Drive files, and Jira projects are only visible if that user can see them. Layer 2 is OAuth: the scopes granted at consent time bound the token; for Microsoft 365 an Entra Global Administrator must grant one-time tenant-wide admin consent before users connect. Layer 3 is tool design: the server decides what to expose — Gmail, for example, creates drafts but cannot send mail on your behalf (Anthropic support docs, 2026). Layer 4 is Claude-side policy: organization owners set per-connector policies of Always allow, Needs approval, or Blocked, and Enterprise admins can enforce an MCP allowlist via `managed-mcp.json` deployed through MDM. As an instructor, drill the intuition: removing access at any one layer removes it entirely.

### 15.6 The Agentic Loop (Claude Code / Cowork)

```
        +---------------------------------------------------+
        |                AGENTIC LOOP                       |
        |                                                   |
        |   [Plan] --> [Tool call] --> [Observe] --+        |
        |      ^                                   |        |
        |      +------------ [Iterate] <-----------+        |
        +---------------------------------------------------+
              |                |                 |
              v                v                 v
   +----------------+ +-----------------+ +----------------+
   | CLAUDE.md +    | | Built-in tools: | | Hooks (in-     |
   | permissions:   | | Read/Write/Edit/| | process,       |
   | permissionMode | | Bash/Glob/Grep/ | | matched):      |
   | default /      | | WebSearch/      | | PreToolUse,    |
   | acceptEdits /  | | WebFetch; MCP   | | PostToolUse,   |
   | plan / bypass  | | servers via     | | Stop,          |
   |                | | mcpServers      | | UserPromptSubmit|
   +----------------+ +-----------------+ +----------------+
              |
              v
   +--------------------------------------------------+
   | Subagents: own context window + own tool set;    |
   | attributed via parent_tool_use_id                |
   +--------------------------------------------------+
```

Both Claude Code and Cowork run the same fundamental agentic loop: Claude plans the next step, issues a tool call, observes the result, and iterates until the task is complete. You shape the loop from three directions. First, configuration: CLAUDE.md files carry standing instructions, and `permissionMode` (default, acceptEdits, plan, dontAsk, bypassPermissions) controls how much autonomy the agent has. Second, the tool surface: built-in tools (Read, Write, Edit, Bash, Glob, Grep, WebSearch, WebFetch) plus any MCP servers you configure. Third, **hooks**: in-process callbacks with matchers — PreToolUse, PostToolUse, Stop, SessionStart, SessionEnd, UserPromptSubmit — that let your code intercept, approve, or modify actions at each loop boundary (Claude Agent SDK docs, 2026). **Subagents** handle delegated subtasks in their own context window with their own tool set, attributed back to the parent via `parent_tool_use_id`. In Cowork, the same loop drives multi-step work over granted local folders, connectors, and the browser, with permission prompts at sensitive steps.

#### Try it
In Claude Code, define a `PreToolUse` hook that logs every Bash call to a file, then ask Claude to refactor a small script. Watch the log to see each loop iteration: plan, tool call, observation.

### 15.7 API Request Anatomy

```
 [Your client code]
   SDK: Python / TS / Java / Go / Ruby / PHP / C# (8 SDKs)
      |
      |  Headers: x-api-key: sk-ant-...  |  anthropic-version
      |           Content-Type: application/json
      v
 +----------------------------------------------------------+
 | POST /v1/messages                                        |
 | body: model, max_tokens, messages[] (user/assistant),    |
 |       system, tools[], tool_choice, stream, thinking,    |
 |       cache_control breakpoints (up to 4)                |
 +----------------------------------------------------------+
      |
      +--> [Tools path]  model returns tool_use blocks (id
      |     toolu_...) -> YOUR code executes -> tool_result
      |     blocks back; server tools (web search, code
      |     execution) run on Anthropic infra (srvtoolu_)
      |
      +--> [Prompt caching path]  cache_control ephemeral
      |     breakpoints; TTL 5 min (1h option); read 0.1x,
      |     write 1.25x/2x; invalidation: tools->system->
      |     messages; scoped per workspace
      |
      +--> [Batch path]  POST /v1/messages/batches: up to
            100k requests/256MB; 50% discount; results in
            24h, kept 29 days; no streaming
      |
      v
 Response (or SSE stream: message_start -> content_block_*
 -> message_delta -> message_stop; errors may arrive
 mid-stream after HTTP 200)
```

A production API call has more moving parts than the quickstart suggests. Authentication uses the `x-api-key` header (not `Authorization: Bearer`) plus an `anthropic-version` header pinning the API contract (Anthropic Docs, 2026). The request body requires `model` and `max_tokens`, with alternating user/assistant messages and optional system prompt, tools, and thinking configuration. Three specialized paths branch off. The **tools path**: Claude returns `tool_use` blocks; your application — never Claude — executes client tools and returns `tool_result` blocks; server-side tools like web search execute on Anthropic infrastructure and use the `srvtoolu_` ID prefix. The **prompt caching path**: up to four explicit `cache_control: ephemeral` breakpoints (or top-level automatic caching) with a 5-minute default TTL, 1-hour option, cache reads at 0.1× base input price, and an invalidation hierarchy of tools → system → messages. The **batch path**: asynchronous processing at a 50% discount with 24-hour completion. Streaming uses server-sent events, and remember: errors like `overloaded_error` can arrive mid-stream after an HTTP 200, so handle in-stream error events.

### 15.8 Projects RAG Flow

```
 [Knowledge base uploads]            (Projects: Pro/Max/Team/
  PDF, DOCX, TXT, MD, CSV,           Enterprise; not Free)
  XLSX, images; 200K context         Custom instructions
  (500K on Enterprise)               attached to project
         |                                   |
         v                                   |
 +----------------------+                    |
 | Knowledge base index |                    |
 | (project knowledge   |                    |
 |  files; RAG mode     |                    |
 |  auto-expands        |                    |
 |  capacity up to 10x  |                    |
 |  when knowledge >    |                    |
 |  context window)     |                    |
 +----------------------+                    |
         |  retrieval: relevant              |
         |  passages selected per query       v
         v                            +---------------+
 +-------------------------------+   | Your prompt   |
 | Context injection: retrieved  |<--+---------------+
 | chunks + custom instructions  |
 | assembled into the request    |
 +-------------------------------+
         |
         v
 +-------------------------------+
 | Claude response grounded in   |
 | project knowledge; respects   |
 | project boundaries (search &  |
 | memory do not leak across)    |
 +-------------------------------+
```

Projects (GA; all paid plans, not Free) are persistent workspaces combining a knowledge base of uploaded files with custom instructions, backed by a 200K context window — 500K on Enterprise (anthropic.com/news/projects). When your knowledge base exceeds the context window, retrieval-augmented generation (RAG) mode kicks in: rather than stuffing every file into the prompt, the system indexes the knowledge base and, per query, retrieves only the relevant passages, expanding effective capacity up to roughly 10× (fwdslash.ai, May 2026 — a Medium-confidence figure; treat the multiplier as approximate). Those retrieved chunks are injected into the request alongside your custom instructions and your prompt, and Claude answers grounded in that assembled context. Two governance properties matter for enterprises: chats inside a project respect project boundaries — Claude's cross-chat search and memory features do not leak content across them — and project sharing is role-based (Private, View, Edit) with artifacts shared only among project members.

#### Try it
Create a project, upload three policy documents and a style guide as custom instructions, then ask a question answerable only from one document. Repeat with a question spanning two documents and compare how retrieval composes the answer versus a raw paste of all files.


---
