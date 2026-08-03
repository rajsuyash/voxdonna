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
