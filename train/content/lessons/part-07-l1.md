Connectors are how Claude stops being a clever text box and becomes a colleague who can actually see your files, tickets, calendars, and CRM records. In this chapter you will learn what a connector technically is, how the four-layer permission model keeps you safe, what is in the catalog as of August 2026, how to set up and govern connectors at enterprise scale, and how to decide between a native connector, a third-party bridge, the API, and building your own MCP server.

> **Volatility note:** Connector availability, plan gating, and capability surfaces (read vs. write) changed repeatedly through 2025–2026. Everything in this chapter is accurate as of August 2026 — verify against current Anthropic documentation before making procurement or rollout decisions.

---

### 5.3.1 How connectors work

A **connector** is an integration built on the **Model Context Protocol (MCP)** — an open protocol that lets an AI application discover and call tools exposed by an external server. Each connector is a (usually remote) **MCP server**: a service that describes its own tools (for example, `search_drive`, `create_draft`, `list_events`) and executes them when Claude calls them.

Three facts about the architecture matter in practice:

1. **Claude connects from Anthropic's cloud, not your machine.** When you use a remote connector, the network call to the MCP server originates from Anthropic's infrastructure (Sunpeak.ai, Jul 2026). A server that works fine in your browser will still fail in Claude if it sits behind a VPN, firewall, private DNS zone, or IP allowlist. This is the single most common cause of "my custom connector won't connect."
2. **Capabilities are discovered dynamically.** You do not configure which tools exist. Claude asks the server, and the server describes its own tools; those tools simply appear in the conversation (modelcontextprotocol.io docs, Jul 2026).
3. **Anthropic does not persistently store your connector data.** Authentication tokens are stored encrypted, and you can disconnect a connector at any time (modelcontextprotocol.io docs, Jul 2026).

#### The connection flow

Every connector — whether from the Directory or a custom URL — follows the same setup pattern:

1. Open **Settings > Customize > Connectors** (or click **+** in the composer and choose **Connectors**).
2. Either pick a connector from the **Directory** (one-click **Connect**) or choose **+ Add custom connector** and paste a remote MCP server URL.
3. Authenticate via **OAuth 2.0**. The consent screen is per-user: the token issued is scoped to *your* account in the source system, not to your organization as a whole.
4. Claude discovers the server's tools automatically. From that point on, you talk normally — Claude decides when a tool call is needed, and you see each call and its result inline.

> **Instructor tip:** "URL, sign in, done. The tools show up, and you talk to Claude normally." (modelcontextprotocol.io docs, Jul 2026) If a connector asks you to paste API keys into a chat, something is wrong — legitimate connectors use OAuth consent screens.

#### The four-layer permission model

The most important security concept in this chapter: **Claude never gets broader access than the connecting user**. The effective permission of any connector is the *intersection* of four layers (technovids.com Claude Connectors Guide, Jun 2026; Sunpeak, Jul 2026):

| Layer | What it is | Example |
|---|---|---|
| 1. Source-system permissions | What *you* can do in the external service | You cannot read a private Slack channel you are not a member of — neither can Claude |
| 2. OAuth scopes | The permissions you granted at consent time | You granted `Mail.Read` but not `Mail.Send` |
| 3. Tool design | What the MCP server's tools allow | Gmail connector exposes draft creation, not sending |
| 4. Admin/user controls | Claude-side policy per action | Admin sets "Needs approval" on all write tools |

A tool call succeeds only if **all four layers permit it**. This is why, for example, an admin can safely enable the Microsoft 365 connector org-wide: a junior analyst's Claude session still cannot read the CEO's mailbox, because layer 1 (their Entra-delegated permissions) forbids it.

---

### 5.3.2 Catalog timeline and scale

| Date | Milestone |
|---|---|
| **2025-05-01** | Anthropic launches **"Integrations"** — remote MCP across web/desktop — with 10 launch partners: Atlassian (Jira/Confluence), Zapier, Cloudflare, Intercom, Asana, Square, Sentry, PayPal, Linear, Plaid. Beta on Max/Team/Enterprise; Pro added 2025-06-03 (Anthropic, May 2025) |
| **2025-07-14** | **Connectors Directory** launches (claude.ai/directory, now claude.com/connectors) with new connectors built by Notion, Canva, Figma, Socket, Prisma; one-click Connect for remote, Install for desktop extensions (Analytics India Magazine, Jul 2025) |
| **2025-07-29** | HubSpot ships the first CRM connector (HubSpot developer changelog, Jul 2025) |
| **2026-01-26** | **MCP Apps** — interactive connectors rendering live UI inside Claude — launch with nine apps (VentureBeat, Jan 2026) |
| **2026-02-02** | Salesforce adds bi-directional MCP Apps support (salesforce.com, Feb 2026) |
| **2026-04** | Consumer/life connectors (Spotify, Uber, Instacart, and more) plus dynamic in-conversation connector suggestions (CNET, Apr 2026) |
| **2026-07** | Community mirror tracks **841 listed + 18 held** connectors across 30 categories |

**Scale — with a flag.** Exact counts diverge by surface and snapshot date: CNET reported "200+" in April 2026, a June 2026 snapshot counted 439, and a community-maintained mirror (github.com/rdmgator12/awesome-claude-connectors) counted 841 listed plus 18 held as of 2026-07-23. Treat "800+ connectors by mid-2026" as directionally correct but point-in-time — the count grows weekly, and the mirror is a community project, not an Anthropic-published figure.

Directory connectors are built and maintained by third-party developers using MCP; Anthropic reviews submissions against security, safety, and compatibility standards (the MCP Directory Policy) through a human, queue-based review (Anthropic support FAQ via mirror, Mar 2026).

**Not a connector:** web search and web fetch are built-in Anthropic-managed capabilities, not MCP connectors. Web search went global on all paid plans 2025-05-01 and reached all plans after 2025-06-03 (Anthropic, May 2025).

---
