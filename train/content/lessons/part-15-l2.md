### 11.3.5 Primitives: Tools, Resources, Prompts — and the Client Side

**Primitives** are the capability types a server exposes. The clearest way to distinguish them is by *who controls their use*:

| Primitive | Controlled by | What it is | Key methods |
|---|---|---|---|
| **Tools** | The model | Executable functions; can change state (create tickets, send messages) | `tools/list`, `tools/call` |
| **Resources** | The host application | Read-only context addressed by URI — snapshots, not live feeds | `resources/list`, `resources/read` |
| **Prompts** | The user | Reusable prompt templates/workflows offered by the server | `prompts/list`, `prompts/get` |

Think: tools are the action layer, resources the knowledge layer, prompts the workflow layer (modelcontextprotocol.io architecture docs). Since the 2025-06-18 revision, tools can also return structured output and resource links.

Servers can also call back into the client via **client primitives**:

- **Sampling** — the server asks the client's model to generate a completion (`sampling/complete`). Deprecated in the 2026-07-28 RC.
- **Elicitation** — the server asks the user for structured input mid-task (added 2025-06-18).
- **Roots** — the client tells the server which filesystem locations it may consider. Deprecated in the RC.
- **Logging** — server log messages routed to the client. Deprecated in the RC (use stderr/OpenTelemetry).

> **Reality check:** many real-world clients implement only tools. When designing a server, treat tools as the guaranteed surface and the rest as progressive enhancement — and note that sampling, roots, and logging are on the deprecation path in the RC, so avoid building new dependencies on them.

:::exercise Try it #1: Inspect a server's primitives
1. Install the MCP Inspector: `npx @modelcontextprotocol/inspector` (requires Node.js).
2. Point it at any local server command (for example a filesystem server) and open the web UI it launches.
3. Run `tools/list`, `resources/list`, and `prompts/list` from the Inspector. Note which lists are non-empty.
4. Call one tool with sample arguments and examine the raw JSON-RPC request/response pair. Identify the `jsonrpc: "2.0"`, `method`, `params`, and `id` fields.

**What you should take away:** the "magic" of connectors is a small, readable JSON-RPC conversation you can inspect end to end.
:::

### 11.3.6 Authentication: OAuth 2.1 for Remote Servers

Local stdio servers need no protocol-level auth — they inherit the user's session. Remote servers are different: the MCP Authorization specification builds on **OAuth 2.1** (itself an IETF draft, not yet a finalized RFC — a caveat worth knowing). The model, per the 2025-11-25 authorization spec (MCP spec via AuthPlane/latenode, Jun 2026):

- The remote MCP server acts as an OAuth **resource server**.
- Clients use the **authorization code flow with mandatory PKCE-S256** — Proof Key for Code Exchange, which binds the authorization request to the token request so intercepted codes are useless. The implicit grant is prohibited.
- **Protected Resource Metadata (RFC 9728)** lets a client discover which authorization server governs a given MCP server.
- **Resource Indicators (RFC 8707)** bind tokens to a specific server's audience, so a token minted for one service cannot be replayed against another.
- **Dynamic Client Registration (RFC 7591)** lets clients register themselves with the authorization server without manual setup; **Client ID Metadata Documents (CIMD)** provide an alternative.
- Tokens are presented in the HTTP `Authorization` header.

Claude's hosted OAuth callback for custom connectors is `https://claude.ai/api/mcp/auth_callback`; Claude Code uses loopback redirects. Remember the boundary of what OAuth gives you: it governs **token issuance and presentation**. Per-call authorization — which tool may run, on whose behalf, with what arguments — remains your job as the deployer, because OAuth scopes are coarse.

### 11.3.7 Security: The Canonical Risks and Their Mitigations

MCP expands your attack surface: you are loading executable capabilities and untrusted descriptions into a model's context. The MCP security best-practices specification and the OWASP MCP Top 10 name the canonical risks (thesaaslibrary/aptible, Jul–Aug 2026):

| Risk | What it is | Core mitigation |
|---|---|---|
| **Tool poisoning** (MCP03) | Malicious instructions hidden inside a tool's description, which the model reads and may follow | Treat third-party tool descriptions as untrusted input; review on install and on every update |
| **Confused deputy** | A proxy server with elevated privileges acts on requests without verifying the end user's authorization | Enforce per-user authorization at the server; never let a shared credential act beyond the caller's rights |
| **Token passthrough** | Forwarding a token that was not issued for that server — an anti-pattern the spec **explicitly forbids** | Validate token audience (RFC 8707); issue server-specific tokens |
| **Prompt injection** (MCP06) | Content returned by a tool manipulates the model into unsafe actions | Human-in-the-loop approval for irreversible actions; scoped tool permissions |
| **Rug pulls** | A server silently mutates its tool definitions after you installed it | Pin server versions; re-review on update; behavioral monitoring |

The standing mitigation checklist:

1. Grant the **minimum necessary** scopes; prefer read-only tools over write tools, and separate read and write tools by design.
2. Apply **human-in-the-loop approval** for irreversible or destructive actions.
3. **Audit-log every tool call**, with per-decision authorization records.
4. Establish **behavioral baselines** and monitor for drift (a read-only server suddenly invoking writes is a signal).
5. Review tool descriptions and schemas on install **and on every update** — descriptions are executable-adjacent content.

In Claude itself, the permission model is layered defense: the effective permission is the *intersection* of the source-system permissions of the authenticated user, the OAuth scopes granted, the tool's own design, and the Claude-side admin/user controls ("Always allow / Needs approval / Blocked" per action). Claude never gains broader access than the connecting user (technovids, Jun 2026). Team/Enterprise owners can additionally enforce MCP allowlists (e.g., via MDM-deployed `managed-mcp.json`) — note the default posture is open unless an admin restricts it.
