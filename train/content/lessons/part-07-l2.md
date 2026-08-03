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
