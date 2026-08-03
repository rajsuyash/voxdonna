### 5.3.4 MCP Apps: interactive connectors

On 2026-01-26 Anthropic launched **MCP Apps** (an open MCP extension that renders live, interactive UI inside the Claude conversation). Instead of a textual tool result, the connector returns a working interface — a Kanban board, a design canvas, a chart you can manipulate (VentureBeat, Jan 2026).

The nine launch apps: **Amplitude, Asana, Box, Canva, Clay, Figma, Hex, monday.com, Slack** (the Slack app comes from Salesforce). Salesforce followed with bi-directional MCP Apps support on 2026-02-02, expanding toward Agentforce 360.

Availability: web and desktop, on Pro, Max, Team, and Enterprise — with **no additional charge** beyond the paid plan. "Connectors require a paid Claude plan — Pro, Max, Team, or Enterprise — but there is no additional charge associated with using connectors." — Sean Strong, Anthropic PM for MCP Apps (VentureBeat, Jan 2026). MCP Apps are not available on Free.

:::exercise Try it — Exercise 1: Connect and interrogate
1. Open **Settings > Customize > Connectors** and connect **Google Drive** (or Box/OneDrive if you are on those stacks). Complete the OAuth consent and note exactly which scopes you granted — that is layer 2 of the permission model.
2. In a new chat, ask: `List the ten most recently modified documents you can see, and for each say whether you can edit or only read it.`
3. Now ask Claude to do something you know *you* cannot do (for example, read a colleague's private folder). Observe the refusal or empty result — that is layer 1 enforcing itself.
4. Disconnect the connector in Settings and confirm the tools disappear from a fresh conversation.

**What you learned:** dynamic tool discovery, per-user OAuth scoping, and why Claude's access is capped by your own permissions.
:::

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

:::exercise Try it — Exercise 2: Connect a public MCP server as a custom connector
1. Pick a public, HTTPS-reachable MCP server you have authorization to use (for example, GitHub's remote server at `https://api.githubcopilot.com/mcp`, or Notion's hosted server).
2. Go to **Settings > Customize > Connectors > + Add custom connector**, give it a name, paste the URL, and complete OAuth.
3. Ask Claude: `What tools do you have from the connector we just added? Describe each one's read vs. write behavior.`
4. Trigger one read-only call and inspect the tool-call card in the conversation. Then attempt a write and note whether an approval prompt appears.
5. **Reflection:** write down which of the four permission layers would stop a malicious or buggy tool call in each case.

**What you learned:** custom connector setup, dynamic tool discovery, and how to audit a server's tool surface before trusting it.
:::

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
