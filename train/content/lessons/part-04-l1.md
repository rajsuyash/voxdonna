This chapter takes you from zero to administrator-level fluency on Claude Enterprise, Anthropic's top-tier commercial plan. You will learn what the plan actually contains, how its billing works, how to run the Admin Console day to day, how identity and access controls fit together, how audit and compliance tooling works, and how Anthropic protects your data. The chapter closes with a governance framework you can adapt and a cost-optimization playbook.

A note before we begin: enterprise features change quickly. Wherever a fact is volatile — pricing, thresholds, retention windows — this chapter flags it with an "as of August 2026" callout. Verify those items against current Anthropic documentation before making procurement or compliance decisions.

---

### 4.1 Enterprise Architecture: One Plan, Three Surfaces

Claude Enterprise is a single plan that bundles all three of Anthropic's work surfaces under one enterprise security and compliance envelope (Anthropic, anthropic.com/enterprise, Aug 2026):

- **Chat (claude.ai)** — the conversational interface for knowledge work: research, writing, analysis, connectors, Projects, and Artifacts.
- **Claude Code** — the agentic coding tool (CLI, IDE extensions, web, and mobile) for your engineering teams.
- **Cowork (GA)** — the agentic knowledge-work surface that executes multi-step tasks autonomously.

All three are included in every Enterprise plan, and entitlements — which users and groups get access to which surface and which models — are managed with role-based access controls (RBAC) from organization settings (Anthropic, enterprise page FAQ, Aug 2026). This is the key architectural idea: **you do not buy three products and integrate them; you buy one organization and grant capabilities.**

A concrete example. Meridian Insurance, a fictional 400-seat deployment, provisions one Claude Enterprise organization. The actuarial group is entitled to chat plus Cowork with Google Workspace and Salesforce connectors. The engineering group is entitled to Claude Code with GitHub, plus chat. The compliance team gets no model access at all — instead they hold Admin roles and read-only Compliance API keys. One contract, one identity integration, one audit trail.

Why buy Enterprise at all? The honest answer — and the organizing principle of this chapter — is that **enterprise differentiation is governance, not the model.** Competitors increasingly run the same Claude models inside their own products (Microsoft Copilot, for example). What only Enterprise gives you is the control plane: SSO and domain capture, SCIM provisioning, audit logs, the Compliance API, spend controls, zero data retention, HIPAA BAAs, and configurable retention. If you do not need those controls, Team or API may be the right tier; if you do, they are the reason to buy.

---

### 4.2 Plan Structure and Billing

#### 4.2.1 Where Enterprise sits in the lineup

The plan ladder runs Free → Pro → Max → Team → Enterprise. Team serves smaller groups (roughly 5–150 members) with shared projects and basic admin controls; Enterprise starts at 20 seats and adds the full compliance stack described in this chapter (Tactiq, Apr 2026; corroborated by Anthropic's enterprise FAQ).

#### 4.2.2 Self-serve vs sales-assisted

Enterprise comes in two procurement variants that share the same base seat price (Anthropic, enterprise FAQ, Aug 2026):

| Dimension | Self-serve Enterprise | Sales-assisted Enterprise |
|---|---|---|
| Payment | Card or ACH, up front | Monthly invoicing in arrears |
| Usage funding | Prepaid shared credit pool; usage stops org-wide when the pool hits zero | Billed against invoice; tailored terms |
| Contract terms | Standard | Tailored (e.g., custom DPAs, zero data retention) |
| HIPAA-ready | Not available | Available (BAA enabled in-app by Primary Owner) |
| Best for | 20–100 seat orgs that want to start this week | Regulated industries, custom terms, large rollouts |

Both variants are also available through **AWS Marketplace**, where Enterprise purchases can draw down your existing AWS committed spend (Anthropic, enterprise FAQ, Aug 2026). The API itself is additionally available on Amazon Bedrock, Google Vertex AI, and Microsoft Azure — relevant when you need EU data residency (Section 4.9).

#### 4.2.3 Pricing

> **As of August 2026 — verify against current Anthropic documentation.** Claude Enterprise is listed at **$20 per seat per month, billed annually, with a 20-seat minimum**. Usage is billed as you go **at API rates** on top of the seat price (Anthropic, anthropic.com/enterprise, Aug 2026). Note that this pricing is drawn from a single official page, and older third-party figures ($60–100/user) circulating online are outdated. Team-plan pricing is in flux across sources; this guide deliberately avoids quoting exact Team seat pricing.

The two-part cost model matters for budgeting: the seat fee buys access and governance; the metered usage is the real variable cost. A 100-seat deployment costs $24,000/year in seats, but a heavy Claude Code engineering team can easily exceed that in API-rate usage — which is exactly why spend controls (Section 4.8) exist.

:::exercise Try it — Exercise 1: Plan-fit decision worksheet
Before you talk to sales or swipe a card, answer these five questions in writing:

1. How many seats do we need in month 1, and month 12? (Below 20 → Enterprise is not available; evaluate Team.)
2. Do we need SAML/OIDC SSO with our IdP, domain capture, and SCIM? (Yes → Enterprise.)
3. Do we have a regulatory driver (HIPAA, GDPR processor terms, ZDR)? (Yes → sales-assisted Enterprise.)
4. Do we have an AWS commit we want to burn down? (Yes → buy via AWS Marketplace.)
5. What is our monthly usage budget at API rates, and who owns it? (This answer feeds Section 4.8.)
:::

---

### 4.3 The Admin Console

The Admin Console (organization settings) is the control plane for everything in this chapter. The official Enterprise feature list as of August 2026 includes (Anthropic, anthropic.com/enterprise):

- SSO/SAML and domain capture
- SCIM provisioning
- Role-based access control (RBAC)
- Usage analytics and reporting
- Spend controls
- Data retention controls *(Enterprise only)*
- Audit logs and OpenTelemetry monitoring *(Enterprise only)*
- Compliance API
- HIPAA-ready offering

Admin analytics are **content-free by design**: you see per-user message counts, token consumption, connector and skill usage, and Claude Code metrics — never the substance of conversations (aiopsschool, Apr 2026, citing Anthropic docs). Full content access is a separate, deliberate act via data exports (Primary Owner) or the Compliance API (Section 4.6).

#### 4.3.1 July 2026 governance additions

> **Caveat — single-source reporting.** On July 2, 2026, Anthropic reportedly shipped a major governance release for Enterprise: org- and user-level spend limits, **spend alerts at 75% and 90%** of budget, a usage/cost analytics dashboard, **model defaults and entitlements**, Analytics Chat, an **Analytics API**, and an **Admin API** (Orbilon Tech, Jul 2026 — third-party report of an Anthropic release; not yet verified against the official changelog as of this writing). Treat the 75%/90% alert thresholds as probable but unconfirmed, and check the Anthropic changelog before building automations around them.

---

### 4.4 User Management and Roles

#### 4.4.1 The standard role hierarchy

Enterprise organizations use a four-level standard hierarchy (DevelopersIO, Jun 2026, based on Anthropic's "Roles and permissions" documentation):

| Role | Count | Capabilities |
|---|---|---|
| **Primary Owner** | Exactly 1 per org | Everything: billing, security settings, data & privacy toggles (HIPAA, Compliance API), member control, data exports |
| **Owner** | Multiple | Broad org administration; can export audit logs |
| **Admin** | Multiple | Invite/remove members, view analytics. **Cannot** manage billing, security settings, or integrations |
| **User** | Many | Standard product access per entitlements |

The Primary Owner role deserves special attention in your runbook: it is the only role that can enable the Compliance API, accept a HIPAA BAA, and perform full data exports. Document who holds it, and plan succession — a Primary Owner who leaves the company without a handoff creates an operational incident.

#### 4.4.2 Custom roles and groups (Enterprise only)

Custom roles are an **Enterprise-only** capability. Two constraints to know (single high-quality secondary source — verify in the current console):

1. Custom roles are assigned to **groups, not individuals**.
2. Standard roles and custom roles are **mutually exclusive per assignment** — a group gets one or the other, not both (DevelopersIO, Jun 2026).

Groups plus custom roles are how you implement least-privilege at scale. Example: create an "External Consultants" group with a custom role granting chat access but no Claude Code, no connectors to internal systems, and no Cowork; drop contractor accounts into that group via SCIM; remove them from the IdP group at contract end, which deactivates them automatically.

#### 4.4.3 Workspace and permissions management

Within the organization, admins manage **workspaces** — containers that scope access to projects, connectors, and (for API users) model availability. Entitlements across chat, Claude Code, and Cowork are scoped via RBAC from organization settings (Anthropic, enterprise FAQ, Aug 2026). The July 2026 release reportedly added **model defaults and entitlements**, letting admins set which models each group can use — useful both for cost control (Haiku 4.5 by default for high-volume teams) and for compliance (Section 4.8.2).

---
