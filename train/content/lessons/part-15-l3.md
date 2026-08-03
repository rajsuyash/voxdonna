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

:::exercise Try it #2: Build, test, and connect your own server
1. Save the FastMCP example above as `server.py` and run `pip install mcp`.
2. Test locally with the MCP Inspector; call `add(2, 3)` and read the `config://version` resource.
3. Extend the server with one more tool of your own design (e.g., a `word_count(text)` tool) and re-test.
4. (Stretch) Switch the transport to `streamable-http`, expose it through a tunnel, and add it to Claude as a custom connector following the five steps above.
5. In Claude, verify the layered permission model: confirm you are prompted for approval before the tool executes.
:::

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
