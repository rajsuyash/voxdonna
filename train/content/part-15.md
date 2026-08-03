# Part 15: Model Context Protocol (MCP) In Depth

Earlier in this chapter you learned to use connectors from the directory. This part goes underneath them: the Model Context Protocol (MCP) itself — what it is, how it is structured, how to secure it, and how to build and connect your own servers. If you are an enterprise admin, developer, or power user, MCP literacy is the single highest-leverage advanced skill in the Claude ecosystem: the same protocol powers Claude chat connectors, Claude Code tool servers, the Anthropic API, and — increasingly — the wider industry, which has also adopted MCP as a standard.

### 11.3.1 What MCP Is and Why It Matters

The **Model Context Protocol (MCP)** is an open standard, introduced by Anthropic in November 2024, for connecting AI applications to external tools and data sources. It is frequently described as "USB-C for AI": one standardized interface that lets any compliant AI application talk to any compliant tool server, replacing a world of one-off integrations (modelcontextprotocol.io, 2026).

The reason MCP matters to you is that it is the **connective tissue across the entire Claude surface area**:

| Surface | How MCP shows up |
|---|---|
| Claude chat (web/desktop/mobile) | Connectors — every connector in the directory is a remote MCP server |
| Claude Code | `claude mcp add` attaches local or remote MCP servers to the agent |
| Anthropic API | Remote MCP servers can be passed programmatically via `mcp_servers` in the Messages API |
| Wider ecosystem | A public registry, hundreds of third-party servers, and adoption by other AI vendors |

Learn MCP once, and you can reason about every tool integration you will encounter in this guide.

> **Governance note:** MCP is an open, community-governed project. The protocol and its official registry have been maintained under Linux Foundation (Agentic AI Foundation) governance since December 2025, and the specification evolves through Specification Enhancement Proposals (SEPs) (secondary reporting, May 2026 — confirm current governance at modelcontextprotocol.io/community/governance).

### 11.3.2 Architecture: Hosts, Clients, and Servers

MCP has three participants. You must keep the terms precise, because "client" does not mean what most people expect:

- **MCP Host** — the AI application you are using: Claude Desktop, Claude Code, VS Code, Cursor. The host orchestrates everything and may run several clients at once.
- **MCP Client** — a component *inside the host* that maintains one dedicated connection to one server. If Claude is connected to three servers, it is running three clients.
- **MCP Server** — a program that exposes tools, resources, and prompts to a client. A local server typically serves exactly one client; a remote server can serve many.

The protocol itself has two layers. The **data layer** defines the message format — JSON-RPC 2.0 — covering lifecycle, capability negotiation, the primitives, and notifications. The **transport layer** defines how those bytes move, and it is swappable: the messages are identical regardless of transport.

A text rendering of the topology:

```
┌───────────────────────── MCP Host (e.g., Claude Desktop) ─────────────────────────┐
│                                                                                   │
│   Claude model  ◄──►  MCP Client #1  ══►  MCP Server A  (local, stdio: filesystem)│
│                    ◄──►  MCP Client #2  ══►  MCP Server B  (remote, HTTP: Jira)   │
│                    ◄──►  MCP Client #3  ══►  MCP Server C  (remote, HTTP: Slack)  │
│                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────┘
        Each client holds ONE dedicated connection to ONE server.
        All connections speak JSON-RPC 2.0; only the transport differs.
```

### 11.3.3 Transports: stdio vs Streamable HTTP

A **transport** is the mechanism that carries JSON-RPC messages between client and server. The specification currently defines two standard transports (modelcontextprotocol.io spec, fetched Aug 2026):

| Property | stdio | Streamable HTTP |
|---|---|---|
| How it runs | Client launches the server as a local subprocess | Server runs as a hosted network service |
| Wire format | Newline-delimited JSON-RPC over stdin/stdout | Single endpoint (e.g. `/mcp`); POST plus optional Server-Sent Events for streaming |
| Clients per server | Exactly one | Many |
| Auth model | Inherits local environment/credentials | OAuth 2.1 / API keys, TLS |
| Best for | Personal, local tools: filesystem, git, shell | Shared, team, or SaaS integrations |

Two operational details are worth memorizing. First, a stdio server **must never write non-MCP bytes to stdout** — use stderr for logging, or you corrupt the protocol stream. Second, the older **HTTP+SSE transport** (two endpoints: GET `/sse` plus POST `/messages`) has been **deprecated since the 2025-03-26 spec revision**. If you inherit a server using it, plan a migration; new servers should use Streamable HTTP.

#### The 2026-07-28 stateless specification (Release Candidate)

> **Caveat — Release Candidate:** On 2026-07-28 the MCP project published a release candidate for a major spec revision. As of August 2026 it is an RC, not the stable release (the stable revision at time of writing is 2025-11-25), and SDK adoption varies — verify against the current specification before building against it.

The headline change: **MCP becomes stateless at the protocol layer** (Official MCP blog, Jul 2026):

- The `initialize`/`initialized` handshake is **removed** (SEP-2575).
- The `Mcp-Session-Id` header and protocol-level sessions are **removed** (SEP-2567).
- Protocol version, client info, and capabilities travel in `_meta` on every request, with a new `server/discover` method.
- The legacy HTTP+SSE transport is reclassified as Deprecated.
- **Roots, Sampling, and Logging are deprecated** — the recommended replacements are explicit tool parameters, direct calls to model provider APIs, and stderr/OpenTelemetry respectively.

For you, the practical consequence is simpler server code (no session lifecycle to manage) and cleaner horizontal scaling — but treat every RC detail as subject to change until the stable release lands.

### 11.3.4 Local vs Remote Servers

Choosing between a local and remote server is an architectural decision, not a code change — the same server logic can run over either transport unchanged (e.g., `mcp.run(transport=...)`).

**Local servers (stdio)** run on the user's machine, inherit that machine's environment and credentials, serve exactly one client, and need no network hardening. Use them for anything that must touch the user's filesystem, local git repos, or shell. **Remote servers (Streamable HTTP)** are hosted services serving many clients, fronted by TLS and OAuth or API keys, and can scale horizontally behind load balancers — especially once the stateless RC lands.

One connectivity fact trips up every new connector author: **remote connectors are reached from Anthropic's cloud, not from your machine** (Sunpeak, Jul 2026). A server that works in your browser will still fail in Claude if it sits behind a VPN, firewall, private DNS zone, or IP allowlist. During development, use a tunnel to expose a local server publicly.

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

#### Try it #1: Inspect a server's primitives

1. Install the MCP Inspector: `npx @modelcontextprotocol/inspector` (requires Node.js).
2. Point it at any local server command (for example a filesystem server) and open the web UI it launches.
3. Run `tools/list`, `resources/list`, and `prompts/list` from the Inspector. Note which lists are non-empty.
4. Call one tool with sample arguments and examine the raw JSON-RPC request/response pair. Identify the `jsonrpc: "2.0"`, `method`, `params`, and `id` fields.

**What you should take away:** the "magic" of connectors is a small, readable JSON-RPC conversation you can inspect end to end.

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

### 11.3.8 The Official MCP Registry (Preview)

The official MCP Registry at `registry.modelcontextprotocol.io` is the canonical directory of MCP servers, under Linux Foundation governance since December 2025; community directories (Smithery, Glama, MCP.so) ingest from it (qveris, May–Jul 2026). Key facts:

- It is **still in Preview as of July 2026** — treat it as a beta service.
- It exposes a REST API and standardized `server.json` metadata; publishing requires CLI push with GitHub or DNS namespace proof.
- **A listing is not a security, uptime, licensing, or quality guarantee.** Verify publisher identity, transport, permissions, and protocol version yourself; pin versions.
- Enterprise registries and gateways exist to fill the RBAC/audit gap that the public registry deliberately does not.

> As of August 2026 — registry status, discovery conventions (such as server cards at `/.well-known/mcp/server-card.json`), and governance details are evolving; verify against modelcontextprotocol.io before relying on them.

### 11.3.9 Building a Custom MCP Server with FastMCP

The official Python SDK ships a high-level **FastMCP** API that infers tool schemas from type hints and docstrings. Install it with `pip install mcp`. Here is a complete minimal server:

```python
# server.py
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo-server")

@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return the sum."""
    return a + b

@mcp.resource("config://version")
def version() -> str:
    """Return the server version."""
    return "1.0.0"

@mcp.prompt()
def summarize(topic: str) -> str:
    """Reusable summary prompt template."""
    return f"Summarize the key facts about {topic} in three bullets."

if __name__ == "__main__":
    mcp.run(transport="stdio")   # use "streamable-http" for a remote server
```

Notes for when you grow beyond the example: tool names must be ≤64 characters and match `^[a-zA-Z0-9_-]{1,64}$`; write descriptive docstrings, because the model reads them to decide when to call the tool (and reviewers read them for poisoning); annotate tools with hints such as `readOnlyHint`/`destructiveHint` if you plan to submit to a directory.

**Test with the MCP Inspector** before connecting anything to Claude:

```bash
npx @modelcontextprotocol/inspector python server.py
```

The Inspector opens a web UI where you can list and call your tools, read resources, and inspect the raw JSON-RPC traffic. A TypeScript path exists too (`@modelcontextprotocol/sdk`, plus community FastMCP variants with CLI `fastmcp run/inspect/call`), but the walkthrough above is sufficient for this course.

#### Connecting your server to Claude

**As a custom remote connector (all Claude plans):**

1. Serve your server over Streamable HTTP at a publicly reachable HTTPS URL (remember: Anthropic's cloud must reach it — tunnel during development).
2. In Claude, go to **Settings → Customize → Connectors → "+ Add custom connector"**.
3. Enter a name and the server URL; if your server uses OAuth, add the Client ID/Secret under advanced settings.
4. Complete the OAuth consent flow; Claude discovers the server's tools automatically.
5. Test in a new conversation: ask something that requires your tool and confirm the tool call appears.

Plan availability: custom remote connectors work on **all plans, with Free limited to 1 custom connector**; on Team/Enterprise, an Owner can add connectors at the org level and members connect individually (Sunpeak/customconnectors, Jul 2026).

> **Known gap (open issue):** custom MCP connectors cannot be attached to scheduled routines — there is no UUID discovery path to reference them (anthropics/claude-code issue #63233, open as of May 2026). If your workflow depends on routines, plan around this.

**Programmatically and in Claude Code:** remote MCP servers can also be consumed via the Anthropic API (`mcp_servers` in the Messages API) and in Claude Code:

```bash
claude mcp add --transport http notion https://mcp.notion.com/mcp
```

#### Try it #2: Build, test, and connect your own server

1. Save the FastMCP example above as `server.py` and run `pip install mcp`.
2. Test locally with the MCP Inspector; call `add(2, 3)` and read the `config://version` resource.
3. Extend the server with one more tool of your own design (e.g., a `word_count(text)` tool) and re-test.
4. (Stretch) Switch the transport to `streamable-http`, expose it through a tunnel, and add it to Claude as a custom connector following the five steps above.
5. In Claude, verify the layered permission model: confirm you are prompted for approval before the tool executes.

### 11.3.10 Best-Practices Checklist

**Design**

- Prefer tools as your primary primitive; treat resources and prompts as enhancements, and avoid new dependencies on sampling/roots/logging (deprecated in the 2026-07-28 RC).
- Separate read and write tools; annotate with `readOnlyHint`/`destructiveHint`; keep tool names ≤64 characters and descriptions accurate — descriptions are both UX and attack surface.
- Return structured output where clients support it (since 2025-06-18).

**Deployment**

- Use stdio for local, single-user servers; Streamable HTTP for anything shared. Never deploy the deprecated HTTP+SSE transport for new work.
- Remote servers must be publicly reachable from Anthropic's cloud, behind TLS, with OAuth 2.1 (PKCE-S256, RFC 9728/8707/7591) rather than static shared secrets.
- Validate token audience on every request; never pass through tokens issued for another service.

**Security & governance**

- Minimum scopes, read-only by default, human approval for irreversible actions, full audit logging.
- Pin server versions and re-review tool descriptions on every update (rug-pull and tool-poisoning defense).
- Enterprise: enforce MCP allowlists and per-action policies ("Always allow / Needs approval / Blocked"); treat public registry listings as unvetted.

**Operations**

- Track the spec: the 2026-07-28 stateless RC will simplify scaling but changes lifecycle assumptions — as of August 2026, verify against the current specification and your SDK's pinned version before upgrading.
- Test every change with the MCP Inspector before touching production connectors.

---

*Volatility note: spec revision dates, registry status, plan gating for custom connectors, and the routines gap are all as of August 2026 — verify against current Anthropic and modelcontextprotocol.io documentation.*


---
