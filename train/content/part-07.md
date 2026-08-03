# Part 7: Feature Deep Dive III — Connectors & Integrations

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

### 5.3.3 Per-connector mini-guides

Each guide below covers purpose, authentication, setup, permissions, use cases, limitations, plan availability, and example prompts. Plan availability reflects August 2026 — verify in product, since Free-plan gating for directory connectors has been inconsistent across sources and expanded over time.

#### Google Drive, Gmail, Google Calendar (first-party)

| | |
|---|---|
| **Purpose** | Drive: search/read Docs, Sheets, Slides, PDFs, Office files; create files/folders. Gmail: search, read, summarize threads; create drafts. Calendar: view/create/update events, recurring events, availability, RSVP, Meet links |
| **Auth** | Google OAuth 2.0; mirrors your Google permissions. Workspace admins must mark Claude a trusted app (Security > API controls) for work accounts |
| **Setup** | Settings > Customize > Connectors → toggle on → Google consent |
| **Plans** | Broadly available, including Free; Workspace connectors reached GA ~2026-02-24 (promptoptimizer.tools, Jul 2026) |
| **Limitations** | **Gmail is draft-only** — "Claude creates drafts in your Gmail account, but cannot send emails on your behalf" (Anthropic). Attachments are not readable via Gmail. Images inside Drive docs are invisible (text extraction only). **Conflict flag:** the write surface is ambiguous — an April 2026 report showed read+create only (no move/rename/delete), while June 2026 sources describe full Calendar read/write including delete. The surface appears to have expanded during H1 2026; verify in product |

**Example prompts:**

```
Find the Q2 board deck in my Drive and summarize the risks section in five bullets.
```

```
Draft a reply to Priya's thread about the vendor contract — keep it under 120 words
and ask for the redlines by Friday. (I'll review the draft before sending.)
```

#### Slack (directory connector + interactive MCP App)

| | |
|---|---|
| **Purpose** | Search channel and thread history, summarize discussions, draft messages (preview/format/review before posting). Interactive Slack app inside Claude since 2026-01-26 |
| **Auth** | OAuth to the workspace; user-scoped channel access; your Slack admin may need to approve the app |
| **Setup** | Settings > Connectors > Slack (one-click). Slack also publishes its own MCP server (`mcp.slack.com/mcp`) and a Claude Code plugin |
| **Permissions** | Private channels only if explicitly granted; messages are drafted for your review, never auto-posted |
| **Limitations** | No event triggers (Claude cannot "watch" a channel). Distinct from the "Claude app in Slack" bot and from Claude Tag (@Claude in Slack, beta on Team/Enterprise since Jun 2026) — separate features |
| **Plans** | Directory connector: paid plans (Pro+); interactive app: Pro/Max/Team/Enterprise (MacRumors, Jan 2026) |

**Example prompts:**

```
Summarize everything that happened in #incident-response in the last 24 hours
and list the open action items with owners.
```

```
Draft a message for #eng-updates announcing the API deprecation timeline.
Let me review it before anything is posted.
```

#### Notion

| | |
|---|---|
| **Purpose** | Read/search pages, databases, wikis; create/update pages via Notion's hosted MCP. Directory connector since July 2025 |
| **Auth** | One-click OAuth via Notion's hosted server `https://mcp.notion.com/mcp`; inherits your Notion permissions — no page-by-page sharing needed |
| **Setup** | Settings → Connectors → Notion → OAuth (Notion developer docs, Apr 2026). Claude Code: `claude mcp add --transport http notion https://mcp.notion.com/mcp` |
| **Limitations** | **Conflict flag:** April 2026 sources describe the directory connector as read-only; June–July 2026 sources describe create/update. Write support was likely added during 2026 — verify |
| **Plans** | Pro/Max/Team/Enterprise |

**Example prompt:**

```
Search our Notion wiki for the onboarding checklist, then draft an updated
version that adds the new security-training step.
```

#### Jira & Confluence (Atlassian)

| | |
|---|---|
| **Purpose** | Read boards in real time, track tasks, create Jira work items, summarize/create multiple Confluence pages at once. Launch partner, 2025-05-01 (Anthropic) |
| **Auth** | OAuth to your Atlassian Cloud account via Atlassian's remote MCP server (mcp.atlassian.com) |
| **Permissions** | Inherits Atlassian permissions; scopes approved by you at consent |
| **Limitations** | No event triggers |
| **Plans** | Paid plans (Max/Team/Enterprise at launch; Pro added Jun 2025) |

**Example prompt:**

```
Create Jira tickets for the five bugs in this triage list, assign them to the
mobile component, and link them to SPRINT-42.
```

#### GitHub — *flag: directory status uncertain*

> **Caveat:** GitHub is **not** confirmed as a one-click first-party directory toggle as of mid-2026 (usecarly.com, Jun 2026; open feature request anthropics/claude-ai-mcp#179, Apr 2026). The reliable path is GitHub's own official **remote MCP server** (`https://api.githubcopilot.com/mcp`) added as a **custom connector** (paid plan required). Historically, GitHub's server had OAuth/DCR compatibility issues with Claude Web requiring an auth-proxy workaround (dt.in.th, Dec 2025) — this may have improved in 2026; verify.

| | |
|---|---|
| **Purpose** | Read repos, issues, PRs, code; create issues/PRs; search |
| **Auth** | GitHub OAuth or PAT; you choose repo/org scoping |
| **Note** | Claude also has a separate built-in "Add from GitHub" repo sync (file contents only — no issues/PRs) and a system GitHub connector powering org plugins/Claude Code Cloud |

**Example prompt:**

```
Read the open PRs in our payments repo, flag any that touch the refund path,
and draft review comments for the two oldest.
```

#### Salesforce (MCP Apps, Feb 2026)

| | |
|---|---|
| **Purpose** | CRM context and actions inside Claude via bi-directional MCP Apps (announced 2026-02-02, salesforce.com); full connectivity via Salesforce **Hosted MCP Servers** (GA April 2026) — auth via External Client App + OAuth, executing as the authenticated user so profiles, permission sets, and sharing rules hold |
| **Status flag** | Connectivity as of mid-2026 is confirmed; the exact "Directory listing" status is unverified — Salesforce was "coming soon" for a long time (arrows.to, Apr 2026). Strategic backdrop: Anthropic–Salesforce partnership expanded Oct 2025 (Claude as a foundational model for Agentforce 360) |

**Example prompt:**

```
Show me all open opportunities over $50k closing this quarter and draft
a risk summary for my forecast call.
```

#### HubSpot (first CRM connector, 2025-07-29)

| | |
|---|---|
| **Purpose** | Read CRM data (contacts, companies, deals, tickets + associations), generate insights and charts; bidirectional write followed launch |
| **Auth** | OAuth; automatically respects HubSpot user permissions and EU data-center routing (HubSpot developer changelog, Jul 2025) |
| **Permissions** | Super Admins configure read/write permissions and approval gates; writes appear in the HubSpot Audit Log attributed to user + connector |
| **Limitations** | No access to Sensitive Data properties/PHI; read-only at launch for standard records; subject to HubSpot API limits |
| **Plans** | All HubSpot tiers + paid Claude (Pro/Max/Team/Enterprise) |

**Example prompt:**

```
Chart our deals by stage and close date for Q3, and list the ten deals with no
activity in the last 14 days.
```

#### Linear

| | |
|---|---|
| **Purpose** | Pull tickets/sprints, create/update issues. Launch partner, May 2025 (Anthropic) |
| **Auth** | OAuth; paid plans |

**Example prompt:**

```
Write release notes for our latest sprint from Linear, grouped by feature,
fix, and chore.
```

#### Asana

| | |
|---|---|
| **Purpose** | Task/project read+write; interactive MCP App since 2026-01-26 (timelines, tasks). Launch partner, May 2025 |
| **Auth** | OAuth via Asana MCP |
| **Limitations** | Known quirks: the V1 SSE endpoint lacked `create_task` — use V2 (`mcp.asana.com/v2/mcp`); Claude Code OAuth needs a pinned callback port |

**Example prompt:**

```
Show every Asana task due this week assigned to the design team and flag
any that have no status update.
```

#### Intercom

| | |
|---|---|
| **Purpose** | Analyze conversation history and user attributes, spot feedback patterns, manage the feedback→bug-resolution workflow (Intercom's Fin agent can act as an MCP client filing Linear bugs). Launch partner, May 2025 (Anthropic) |

**Example prompt:**

```
Analyze last month's Intercom conversations and rank the top five complaints
by frequency, with example quotes for each.
```

#### Microsoft 365 (Outlook / Teams / SharePoint / OneDrive) — first-party

| | |
|---|---|
| **Purpose** | Search/read across Outlook mail and calendar, OneDrive files, SharePoint sites, Teams chats/channels/transcripts. **Write tools** for email, calendar, mailbox settings, OneDrive, and SharePoint added 2026-07-07 (Teams remains read-only) |
| **Auth** | Microsoft Entra ID, OAuth with delegated permissions — Claude acts as the signed-in user. Personal @outlook.com accounts unsupported. **Two service principals** exist in your tenant: "M365 MCP Client for Claude" and "M365 MCP Server for Claude" |
| **Setup (three gates)** | 1. Team/Enterprise Owner enables the connector in Claude org settings. 2. An Entra **Global Administrator** grants one-time tenant-wide **admin consent** (in-Claude flow or manual via adminconsent URLs). 3. Each user connects individually under Customize > Connectors |
| **Admin controls** | Entra-side: "Assignment required" to scope users/groups; revoke individual Graph permissions (Mail.Read, Sites.Read.All, Chat.Read, Files.Read.All, etc.); Conditional Access/MFA inherited; every Graph call captured in Purview audit logs. Claude-side: per-tool allow/approval/block |
| **Plans** | Initially Team/Enterprise only; expanded to all plans ~early April 2026. Write tools still require org enablement + Entra consent (blog.admin365.ai, Jun 2026; linkloot.io, Jul 2026) |

**Example prompts:**

```
Find every email from the Contoso account team this month and build a
relationship-summary doc in my OneDrive.
```

```
What did I miss in the #product-launches Teams channel while I was on leave?
Summarize decisions only.
```

#### Box

| | |
|---|---|
| **Purpose** | Search files, read/preview documents inline, extract insights; interactive MCP App since 2026-01-26 |
| **Setup** | Settings → Connectors → Box → OAuth. Broad plan availability |
| **History** | Announced as upcoming May 2025; confirmed as an official directory connector in 2026 |

**Example prompt:**

```
Search Box for all executed NDAs signed in 2026 and list counterparties and
expiration dates in a table.
```

#### Dropbox — *flag: no first-party connector found*

> **Caveat (Medium confidence):** No first-party Claude directory connector for Dropbox is evidenced as of August 2026. Dropbox offers an official MCP server via **Dropbox Dash** (enterprise-search-centric, read-focused, no file writes), and third-party bridges (e.g., Merge Agent Handler) expose the full file API. Whether a native directory listing exists is ambiguous — check the Directory before promising it to users.

#### Zapier

| | |
|---|---|
| **Purpose** | A gateway to roughly 7,000+ apps through pre-built workflows and automations — the pragmatic answer when no native connector exists. Launch partner, May 2025 (Anthropic) |
| **Auth** | OAuth to Zapier; the underlying app connections live in your Zapier account |

**Example prompt:**

```
Pull this month's HubSpot sales data via Zapier and prepare a meeting brief
for tomorrow's pipeline review.
```

#### Canva

| | |
|---|---|
| **Purpose** | Directory connector since July 2025 (built by Canva); interactive MCP App since Jan 2026 — create presentation outlines, apply your branding, and produce decks in real time inside the conversation |

**Example prompt:**

```
Turn this project postmortem into a 10-slide Canva deck outline using our
brand template, then generate the deck.
```

#### Figma

| | |
|---|---|
| **Purpose** | Directory connector since July 2025; interactive app — turn text or images into flow charts, Gantt charts, and diagrams via FigJam |

**Example prompt:**

```
Convert this migration runbook into a FigJam flow chart with decision points
for the rollback criteria.
```

#### Stripe

| | |
|---|---|
| **Purpose** | Payment, subscription, and revenue data analysis; billing metrics. Announced as "coming" May 2025 (Anthropic); present in the Directory per multiple 2026 sources. **Flag:** exists with high confidence, but exact capability scope is Medium confidence |
| **Auth** | OAuth; paid plans |

**Example prompt:**

```
Summarize MRR movement last month: new, expansion, contraction, churn —
with the five largest churned accounts.
```

#### PayPal

| | |
|---|---|
| **Purpose** | Payments and business actions. Launch partner, 2025-05-01 (Anthropic). **Flag:** confirmed at launch; detailed capability documentation is thin — verify current tool surface in product |

---

### 5.3.4 MCP Apps: interactive connectors

On 2026-01-26 Anthropic launched **MCP Apps** (an open MCP extension that renders live, interactive UI inside the Claude conversation). Instead of a textual tool result, the connector returns a working interface — a Kanban board, a design canvas, a chart you can manipulate (VentureBeat, Jan 2026).

The nine launch apps: **Amplitude, Asana, Box, Canva, Clay, Figma, Hex, monday.com, Slack** (the Slack app comes from Salesforce). Salesforce followed with bi-directional MCP Apps support on 2026-02-02, expanding toward Agentforce 360.

Availability: web and desktop, on Pro, Max, Team, and Enterprise — with **no additional charge** beyond the paid plan. "Connectors require a paid Claude plan — Pro, Max, Team, or Enterprise — but there is no additional charge associated with using connectors." — Sean Strong, Anthropic PM for MCP Apps (VentureBeat, Jan 2026). MCP Apps are not available on Free.

#### Try it — Exercise 1: Connect and interrogate

1. Open **Settings > Customize > Connectors** and connect **Google Drive** (or Box/OneDrive if you are on those stacks). Complete the OAuth consent and note exactly which scopes you granted — that is layer 2 of the permission model.
2. In a new chat, ask: `List the ten most recently modified documents you can see, and for each say whether you can edit or only read it.`
3. Now ask Claude to do something you know *you* cannot do (for example, read a colleague's private folder). Observe the refusal or empty result — that is layer 1 enforcing itself.
4. Disconnect the connector in Settings and confirm the tools disappear from a fresh conversation.

**What you learned:** dynamic tool discovery, per-user OAuth scoping, and why Claude's access is capped by your own permissions.

---

### 5.3.5 Enterprise controls for connectors

On Team and Enterprise plans, connectors are governed, not just enabled (Sunpeak, Jul 2026; technovids guide, Jun 2026; Harmonic Security, Mar 2026):

| Control | What it does | Plan |
|---|---|---|
| **Org enable/disable** | Owners enable or disable individual connectors for the whole workspace (Organization Settings > Connectors); org-wide custom connectors can be added centrally, with members self-authenticating per-user | Team/Enterprise |
| **Per-action policies** | **Always allow / Needs approval / Blocked** set per connector action | Team/Enterprise |
| **Enterprise-managed authentication (Beta)** | Provision connector access centrally via your IdP (e.g., **Okta**) instead of per-employee OAuth | Enterprise (Beta) |
| **MDM allowlists** | Deploy `managed-mcp.json` via Jamf/Intune to enforce an MCP allowlist on managed devices. **Note:** default posture is open — users can enable catalog connectors without approval unless you restrict them | Enterprise |
| **RBAC** | Role-based access gates agent surfaces (e.g., Cowork) whose connectors are org-managed; Cowork users cannot self-add connectors | Enterprise |
| **Audit** | Enterprise usage analytics and audit logs; source-system logs add depth (Purview for M365 Graph calls, HubSpot Audit Log for CRM writes) | Enterprise |

Certification posture for connector traffic: SOC 2 Type II, ISO 27001, GDPR DPA, Microsoft publisher verification (Anthropic security guide via mirror, Mar 2026). Enterprise is also self-serve purchasable since Feb 2026, including SSO/SCIM and admin controls for plugins/connectors (secondary source — Medium confidence).

**Deployment checklist for admins:**

1. Inventory which catalog connectors your data-classification policy permits.
2. Disable everything else at org level; set write-capable tools to "Needs approval."
3. Push a `managed-mcp.json` allowlist through MDM before announcing availability.
4. For Microsoft 365, complete Entra admin consent and scope "Assignment required" to a pilot group first.
5. Verify audit visibility end-to-end (Claude-side logs plus Purview/HubSpot) before broad rollout.

---

### 5.3.6 Custom connectors via MCP

When the catalog does not cover your system, build your own. Any **remote MCP server reachable over HTTPS** can be added: Settings > Customize > Connectors > **+ Add custom connector** → name + URL (optional OAuth Client ID/Secret in advanced settings).

Key facts:

- **Plans:** all plans, with **Free limited to 1 custom connector**. Team/Enterprise: an Owner adds it at org level; members connect individually.
- **Network:** Anthropic's cloud must reach the endpoint — no localhost, VPN, or firewalled servers. Use a tunnel (e.g., during development) to expose a local server.
- **Transport/auth:** Streamable HTTP preferred (SSE is legacy); OAuth 2.0 consent flow with hosted callback `https://claude.ai/api/mcp/auth_callback`; Claude Code uses loopback redirects.
- **Programmatic use:** remote MCP servers also work via the Anthropic API (`mcp_servers` parameter in the Messages API) and Claude Code (`claude mcp add --transport http`).
- **Known gap (flagged):** custom MCP connectors **cannot be attached to scheduled routines** — there is no UUID discovery path (anthropics/claude-code#63233, May 2026). If your automation depends on routines, plan around this.

**Directory submission:** to publish your connector, submit via the review form at claude.com/connectors. Requirements include a privacy policy, tool titles with `readOnlyHint`/`destructiveHint` annotations, separate read and write tools, tool names ≤64 characters, test credentials, documentation and a support contact; MCP Apps additionally need 3–5 screenshots. Review is human and queue-based — expect a weeks-long wait (tallyfy.com, Jun 2026; official FAQ via mirror).

#### Try it — Exercise 2: Connect a public MCP server as a custom connector

1. Pick a public, HTTPS-reachable MCP server you have authorization to use (for example, GitHub's remote server at `https://api.githubcopilot.com/mcp`, or Notion's hosted server).
2. Go to **Settings > Customize > Connectors > + Add custom connector**, give it a name, paste the URL, and complete OAuth.
3. Ask Claude: `What tools do you have from the connector we just added? Describe each one's read vs. write behavior.`
4. Trigger one read-only call and inspect the tool-call card in the conversation. Then attempt a write and note whether an approval prompt appears.
5. **Reflection:** write down which of the four permission layers would stop a malicious or buggy tool call in each case.

**What you learned:** custom connector setup, dynamic tool discovery, and how to audit a server's tool surface before trusting it.

---

### 5.3.7 Integration strategy: choosing your path

Not every integration problem needs the same tool. Use this decision table:

| Path | Best when | Pros | Cons | Example |
|---|---|---|---|---|
| **Native Directory connector** | The service is listed and its tool surface covers your need | One-click setup; reviewed against MCP Directory Policy; per-user OAuth built in | You inherit the vendor's tool design and pace of updates | Google Drive, Slack, HubSpot |
| **Third-party bridge (e.g., Zapier)** | No native connector, but the target app is in the bridge's catalog (~7,000+ apps) | No code; broad coverage | Extra vendor in the data path; coarse-grained actions; another subscription | Pulling data from a niche CRM via Zapier |
| **Anthropic API (`mcp_servers`)** | You are building a product or automated pipeline, not chatting | Programmatic control; embeds in your app | Engineering effort; you own auth, retries, observability | Nightly job that summarizes Jira via API |
| **Custom MCP server** | Internal systems, proprietary APIs, or fine-grained tool design you must control | Exact tools, exact scopes, your hosting and logging | You build and maintain it; must be HTTPS-reachable from Anthropic's cloud; **cannot attach to scheduled routines (as of Aug 2026)**; Directory review takes weeks if you publish | Internal inventory system exposed with 3 read tools and 1 approval-gated write tool |

**Rule of thumb:** try the Directory first; bridge with Zapier for breadth; use the API when a human is not in the loop; build custom MCP only when control of the tool surface is the requirement. In all four paths, the four-layer permission model still applies — the source system's permissions remain the ultimate ceiling.

---

### Chapter summary

- Connectors are remote MCP servers reached from Anthropic's cloud: add from the Directory or by URL, authenticate per-user via OAuth, and Claude discovers tools dynamically.
- Effective permission = source-system permissions ∩ OAuth scopes ∩ tool design ∩ admin controls. Claude never exceeds the connecting user's access.
- The catalog grew from 10 launch partners (May 2025) to a Directory (Jul 2025) to 800+ listings by mid-2026 (community-mirror count — point-in-time).
- Enterprise governance covers org enable/disable, per-action allow/approval/block, IdP-managed auth (Beta), MDM allowlists, RBAC, and audit — with an open default posture you must actively restrict.
- Custom MCP servers close every gap, on every plan (Free: one connector), with a flagged inability to attach to scheduled routines as of August 2026.


---
