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
