# Part 4: Claude Enterprise — Feature Deep Dive

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

#### Try it — Exercise 1: Plan-fit decision worksheet

Before you talk to sales or swipe a card, answer these five questions in writing:

1. How many seats do we need in month 1, and month 12? (Below 20 → Enterprise is not available; evaluate Team.)
2. Do we need SAML/OIDC SSO with our IdP, domain capture, and SCIM? (Yes → Enterprise.)
3. Do we have a regulatory driver (HIPAA, GDPR processor terms, ZDR)? (Yes → sales-assisted Enterprise.)
4. Do we have an AWS commit we want to burn down? (Yes → buy via AWS Marketplace.)
5. What is our monthly usage budget at API rates, and who owns it? (This answer feeds Section 4.8.)

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

### 4.5 Identity: SSO, Domain Capture, and SCIM

#### 4.5.1 SSO/SAML

Enterprise SSO supports **SAML 2.0 and OIDC** with Okta, Microsoft Entra ID (Azure AD), and Google Workspace. (For contrast, Team plan SSO is limited to Google/Microsoft only — one of the clearest feature gates between the tiers.) (morphllm, Jun 2026; docs.anthropic.com, Jul 2026.)

Setup walkthrough (SAML with Okta as the example):

1. In the Admin Console, open **Organization settings → Security** and begin SSO configuration; copy the ACS URL and Entity ID Anthropic provides.
2. In Okta, create a new SAML 2.0 app integration, paste the ACS URL and Entity ID, and map attributes (email as NameID, plus first/last name).
3. Download the IdP metadata XML (or copy the SSO URL and certificate) and upload it back in the Anthropic console.
4. Test with a pilot group before enforcing org-wide.
5. Enforce SSO so password logins are disabled for your domain.

#### 4.5.2 Domain capture

**Domain capture** claims your corporate email domain (verified via DNS TXT record) so that every login from `@yourcompany.com` routes through your SSO, and — critically — **existing individual accounts on your domain are pulled into the managed workspace** (morphllm, Jun 2026; docs.anthropic.com). This solves the shadow-IT problem: employees who signed up for personal Claude accounts with work email before your rollout are swept into governance. Communicate this to staff before you flip it; their conversation history moves into an org you administer.

#### 4.5.3 SCIM provisioning

**SCIM** (System for Cross-domain Identity Management) automates the account lifecycle from your IdP. On Claude Enterprise, SCIM is Enterprise-gated and **requires SSO to be configured first**. It handles account creation, role updates, and deactivation; IdP group membership can drive seat assignment and role mapping, and SCIM-provisioned members are activated automatically (Stitchflow, Mar 2026; vantagepoint, Jul 2026).

Typical flow: Okta group "Claude-Engineering" → push via SCIM → accounts created, mapped to the Engineering group and its custom role → engineer leaves the company → IdP deactivation → Claude account deactivated, seat freed, no orphan access.

> **Flag:** Several secondary sources list **IP allowlisting** as an Enterprise network-level control, but it did not appear on the official enterprise feature list as of August 2026, and a public GitHub feature request implies it is absent on Pro/Max. Verify with your Anthropic account team before relying on it.

---

### 4.6 Audit Logs, the Compliance API, and SIEM Integration

Enterprise gives you three layers of visibility, with a sharp privacy line between them (aiopsschool, Apr 2026):

| Layer | Who | What you see | Content? |
|---|---|---|---|
| Aggregated analytics | Admins, Owners | Per-user message counts, tokens, connector/skill usage, Claude Code metrics | No |
| **Audit logs** *(Enterprise only)* | Owners, Primary Owners | Event metadata, past **180 days** | No — UUIDs only |
| **Data exports / Compliance API** *(Enterprise only)* | Primary Owner-enabled | Full activity logs, chat data, file content | Yes |

#### 4.6.1 Audit logs

Audit logs are exported from Admin settings by Owners or Primary Owners and cover the past 180 days. They are **metadata-only**: chat and project titles and content are not included — only their unique identifiers (UUIDs). Every entry carries `created_at`, `actor_info`, `event`, `event_info`, `entity_info`, `ip_address`, `device_id`, `user_agent`, and `client_platform`. The event taxonomy covers sign-ins, SSO/domain events, invites, projects, conversations, files, and data exports (aiopsschool; generalanalysis, May 2026, citing Anthropic audit-log documentation).

Audit logs answer "who did what, when, from where" — e.g., "user X exported data at 02:14 from an unfamiliar IP." They do not answer "what did the conversation say."

#### 4.6.2 Compliance API

When you need content — for e-discovery, insider-risk investigation, or regulated-industry record-keeping — the **Compliance API** (Enterprise only) provides programmatic access to activity logs, chat data, and file content. It is deliberately gated:

1. The **Primary Owner** enables it under **Organization settings → Data and privacy**.
2. You authenticate with an **Admin API key** (prefix `sk-ant-admin01-`) scoped to `read:compliance_activities` (Datadog integration docs).
3. Calls are rate-limited at roughly 600 requests per minute.

Minimal example:

```bash
curl https://api.anthropic.com/v1/organizations/compliance/activities \
  -H "x-api-key: $ANTHROPIC_ADMIN_KEY" \
  -H "anthropic-version: 2023-06-01"
```

#### 4.6.3 Datadog SIEM integration

Anthropic maintains an official **Datadog integration** that ingests Compliance API logs into your SIEM (Datadog docs). Prerequisites are exactly the three steps above: an Enterprise plan, the Compliance API enabled, and an `sk-ant-admin01-` key with `read:compliance_activities`. From there you can build detections — for example, alerting when a single user's token consumption spikes 10× day-over-day, or when data exports occur outside business hours.

> **Flag:** One third-party source reported in May 2026 that **Cowork sessions were not captured** in audit logs or compliance data. Cowork has since reached GA, so this gap may be closed — verify current coverage before promising auditors end-to-end visibility.

---

### 4.7 Data Privacy, Retention, and Residency

#### 4.7.1 No training on customer data

On all commercial products — Claude for Work (Team and Enterprise), the API, Education, and Government — **your prompts, data, and results are not used to train models by default**. This is contractual; there is no opt-in/opt-out toggle, and commercial customers were explicitly excluded from the September 2025 consumer-tier policy changes (Anthropic, enterprise page, Aug 2026; anarlog.so, Mar 2026).

#### 4.7.2 Default retention and Enterprise retention controls

> **As of August 2026 — verify; these windows have changed repeatedly.** The API default is that inputs/outputs are deleted after **7 days** (reduced from 30 days on September 14, 2025), with a 30-day opt-in available via your Data Processing Addendum; deleted conversations are purged within 30 days. Enterprise adds **configurable data retention controls** (Enterprise-only) in the Admin Console.

#### 4.7.3 Zero data retention (ZDR)

For the strictest posture, **zero data retention** is available to qualified enterprise/API accounts via commercial agreement — it is not self-serve. Under ZDR, inputs and outputs are not stored at rest after the API response is returned; abuse screening happens in-pipeline, though User Safety classifier results are still retained (meetily.ai, May 2026; aptible, Jul 2026).

Know the boundaries:

- **Covered:** Messages API and Token Counting API.
- **Excluded:** Batch API, Files API, Skills API, code execution, programmatic tool calling, MCP connector, Console/Workbench.
- **Model exclusion:** Anthropic's designated "Covered Models" — currently **Claude Fable 5 and Claude Mythos 5** — require 30-day retention and are incompatible with ZDR-only workspaces.

Practical consequence: a ZDR workspace cannot use Fable 5, cannot batch, and cannot use the Files API. Design your architecture around that before you sign the ZDR amendment.

#### 4.7.4 Data residency

First-party surfaces (claude.ai and the direct API) default to **US-based infrastructure**. Anthropic documents two distinct controls (padiso.co, Jun 2026, citing Anthropic docs):

- **Inference geography** — where prompts are processed; override per request with the `anthropic-client-geo` header.
- **Workspace geography** — where account metadata (keys, logs, billing) is stored; set in workspace Settings → Data Residency.

**EU residency is not offered on first-party surfaces.** The EU path runs through the cloud providers: AWS Bedrock EU profiles (Frankfurt, Ireland, Paris) or Google Vertex AI EU regions, under the provider's DPA/BAA (compound.law, Apr 2026). If EU residency is a hard requirement, your procurement decision is really "Claude via Bedrock/Vertex," not claude.ai Enterprise.

#### 4.7.5 Encryption and certifications

All data is encrypted in transit (**TLS 1.2+**) and at rest (**AES-256**); Anthropic holds the keys — no customer-managed key option is documented on first-party (Anthropic; DPA Schedule 2, Aug 2026). Anthropic holds SOC 2 Type I & II, ISO 27001:2022, and ISO/IEC 42001:2023 certifications, with reports available through the Trust Portal (trust.anthropic.com) under an NDA/access-request flow. For GDPR, Anthropic acts as processor; the Article 28 DPA with EU SCCs is automatically incorporated into the Commercial Terms for Team and Enterprise, with a subprocessor list and 15-day change notice. (Certification dates and DPA details from secondary registries — pull current certificates from the Trust Portal during your vendor review.)

---

### 4.8 Spend Controls and Cost Optimization

#### 4.8.1 The control set

As of the July 2026 governance release (single-source — verify against the changelog), Enterprise admins have:

- **Org-level spend limits** — a hard ceiling on total metered usage.
- **User-level spend limits** — per-seat caps, e.g., $50/month for analysts, $400/month for engineers.
- **Spend alerts at 75% and 90%** of budget — email/console warnings before the ceiling hits.
- **Usage/cost analytics dashboard and Analytics API** — for chargeback and trend analysis; **Analytics Chat** for natural-language cost queries.
- **Model defaults and entitlements** — restrict expensive models to groups that need them.
- **Admin API** — automate seat, group, and limit management.

On self-serve plans, the prepaid credit pool acts as a built-in circuit breaker: usage stops org-wide at zero. On sales-assisted invoicing there is no automatic stop — **you must set explicit limits or you can overrun.**

#### 4.8.2 A governance framework example

Here is a complete, adaptable framework — the "Meridian Insurance AI Governance Standard":

1. **Ownership.** Primary Owner = Head of IT Security. Owners = CISO delegate + Procurement lead. Admins = one per business unit.
2. **Identity.** SSO enforced via Entra ID; domain capture on; SCIM push groups mapped to business units; quarterly access recertification driven by IdP group exports.
3. **Entitlements.** Default role = User, chat + Cowork, Haiku/Sonnet-class models. Claude Code entitlement requires manager approval. Opus/Fable-class models restricted to the Engineering group. ZDR workspace for the claims-adjudication API project (no Fable 5, no Batch).
4. **Spend.** Org limit = 120% of quarterly forecast; user limits by role band; 75%/90% alerts routed to the FinOps channel; monthly chargeback to cost centers via the Analytics API.
5. **Monitoring.** Weekly audit-log review (sign-ins, exports, SSO events); Compliance API streamed to Datadog; alerts on data-export events and off-hours spikes.
6. **Privacy.** DPA executed; 30-day retention opt-in declined (default 7-day); annual Trust Portal certificate pull for the vendor file.
7. **Change management.** Anthropic changelog reviewed monthly by the platform owner; volatile facts (pricing, thresholds) re-verified quarterly.

#### 4.8.3 Cost-optimization playbook

Six levers, roughly in order of ROI:

1. **Right-size models with entitlements.** Most knowledge work does not need the largest model; default groups to mid-tier and make premium models an approved exception.
2. **Use prompt caching on API workloads** (5-minute and 1-hour cache windows) for repeated context such as system prompts and policy documents.
3. **Route non-urgent API jobs to the Batch API** at a 50% discount — but note Batch is excluded from ZDR.
4. **Set user-level limits and alerts** before the first big invoice, not after.
5. **Watch Claude Code per-developer burn** (industry average roughly $13/developer/day is a useful benchmark); set engineering-group limits accordingly.
6. **Audit the analytics monthly** for outliers: idle seats to reclaim, power users to train, and connectors nobody uses.

#### Try it — Exercise 2: Admin readiness checklist

Work through this checklist in your own organization (or a sandbox). Every "no" is an action item.

- [ ] Primary Owner identified, documented, and has a named successor
- [ ] SSO (SAML or OIDC) configured, tested with a pilot group, and enforced
- [ ] Domain capture verified via DNS TXT; staff notified about account migration
- [ ] SCIM provisioning live; joiner/mover/leaver flow tested end-to-end
- [ ] At least one custom role assigned to a group (not individuals)
- [ ] Org-level and user-level spend limits set; alert routing tested
- [ ] Audit-log export performed once; you can read `actor_info`, `event`, and `ip_address` fields
- [ ] Decision recorded on Compliance API (enabled vs deliberately disabled), and on ZDR (needed vs not)
- [ ] Retention setting chosen and documented (default vs configured)
- [ ] Changelog review calendar invite created (monthly)

---

### 4.9 Chapter Summary

Claude Enterprise is one plan spanning chat, Claude Code, and Cowork, sold at $20/seat/month (annual, 20-seat minimum, usage at API rates — as of August 2026, verify) in self-serve and sales-assisted variants. Its real product is governance: the Admin Console, a four-level role hierarchy plus Enterprise-only custom roles and groups, SSO/SAML with domain capture, SCIM lifecycle automation, metadata-only 180-day audit logs, the content-level Compliance API with official Datadog SIEM integration, contractual no-training guarantees, configurable retention up to contract-based zero data retention (with explicit API and model exclusions), US-first-party residency with EU paths via Bedrock/Vertex, AES-256/TLS encryption, and a July 2026 wave of spend limits, alerts, and analytics/admin APIs. Master these controls, and you can give every employee frontier-model access with the guardrails your auditors, lawyers, and CFO actually require.


---
