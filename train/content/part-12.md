# Part 12: Administration & Security

Chapter 4 walked you through what Claude Enterprise *can do*. This chapter is about what you, the administrator, must *operate*: provisioning users, controlling spend, monitoring usage, enforcing governance policy, and standing in front of your CISO or auditor with evidence. We assume you hold the Owner or Primary Owner role in an Enterprise organization, and we progress from day-one console operations to full compliance frameworks.

> **Volatility note:** Pricing, seat minimums, and feature gates in this chapter are accurate **as of August 2026 — verify against current Anthropic documentation** before quoting to stakeholders.

### 10.1 The Admin Console: Operations Walkthrough

The Admin Console is the control plane for your Enterprise organization. Anthropic's official feature list for Enterprise includes: SSO/SAML with domain capture, SCIM provisioning, role-based access control (RBAC), spend controls, usage analytics and reporting, audit logs, OpenTelemetry (OTEL) monitoring, data retention controls, and the Compliance API (Anthropic, Aug 2026). Data retention controls and OTEL monitoring are currently **Enterprise only**; audit logs are also Enterprise-gated.

Key console areas you will use weekly:

| Console area | What you do there | Access |
|---|---|---|
| Organization settings → Members | Invite, remove, and re-role users | Owner, Admin |
| Organization settings → Roles & groups | Assign standard roles; define custom roles mapped to groups | Owner (custom roles: Enterprise only) |
| Organization settings → Data and privacy | Enable Compliance API, configure retention, accept BAA (HIPAA) | Primary Owner |
| Billing / Usage | Monitor credit pool or invoiced usage; set spend limits and alerts | Primary Owner, Owner |
| Analytics | Dashboards, Analytics Chat, Analytics API access | Owner, Admin |
| Audit logs | Export metadata-only event logs (past 180 days) | Owner, Primary Owner |

A July 2026 governance release added org- and user-level spend limits, spend alerts (reported at 75% and 90% thresholds), model defaults and entitlements, Analytics Chat, an Analytics API, and an Admin API — all Enterprise-only (third-party release reporting, Jul 2026). *Caveat: the exact alert thresholds and release contents come from secondary reporting; confirm against Anthropic's changelog.*

**Role hierarchy.** Standard roles run Primary Owner (one per org; controls billing, security, and membership) → Owner → Admin (can invite/remove members and view analytics; cannot manage billing, security, or integrations) → User. Custom roles are Enterprise-only and are assigned to **groups**, not individuals; a given assignment is either a standard role or a custom role, not both (Anthropic docs via secondary reporting, Jun 2026 — single-source constraint; verify in your console). RBAC scopes capabilities across chat, Claude Code, and Cowork; entitlements are managed from organization settings.

#### Try it — Console orientation (Exercise 1, part A)

1. Open Organization settings and identify your Primary Owner. If that is not you, note the escalation path.
2. List every Owner and Admin. Flag any account without SSO sign-in.
3. Export one month of analytics and locate your top five users by token consumption.
4. Set an org-level spend limit if none exists, and record who receives the spend alert.

### 10.2 User Lifecycle: Onboarding to Offboarding

A disciplined lifecycle prevents the two classic Enterprise AI failures: orphaned seats (paying for departed users) and shadow accounts (personal Claude accounts using corporate data).

**Stage 1 — SSO onboarding.** Enterprise SSO supports SAML 2.0 and OIDC with Okta, Microsoft Entra ID, and Google Workspace (Team plan SSO is limited to Google/Microsoft). **Domain capture** claims your corporate email domain via DNS TXT verification: after capture, all logins with that domain route through your SSO, and existing individual accounts on the domain are pulled into the managed workspace (Anthropic docs, Jul 2026). Do domain capture *before* announcing rollout — it converts shadow accounts into managed ones.

**Stage 2 — SCIM provisioning.** SCIM (Enterprise-gated, requires SSO) automates account creation, role updates, and deactivation directly from your identity provider (IdP). IdP group membership can drive seat assignment and role mapping; members provisioned via SCIM are activated automatically. Build IdP groups like `claude-users-engineering` or `claude-admins` so that joining a group *is* the onboarding.

**Stage 3 — Role assignment.** New users land as User by default. Elevate deliberately: Admin for team leads who manage membership, Owner for a small deputy set, and custom roles via groups for fine-grained entitlements (e.g., a group entitled to Claude Code but not Cowork).

**Stage 4 — Workspace placement and entitlements.** Place users in the correct workspace and apply model entitlements/defaults so they land on approved models. Confirm connector policies apply to their group (see §10.5).

**Stage 5 — Offboarding / deprovisioning.** With SCIM, disabling the user in the IdP deactivates their Claude account automatically — this is your primary control. Your runbook should also: (1) verify deactivation in the Members list within one business day of departure; (2) transfer ownership of the user's Projects and shared artifacts; (3) review audit log entries for the user's final 30 days for anomalous data exports; (4) confirm seat count is adjusted for billing; (5) for Owners/Admins departing, re-assign their elevated roles first (there must always be exactly one Primary Owner).

#### Exercise 1 — Design an offboarding runbook

Draft a one-page offboarding runbook for your organization covering: trigger (HR termination event), SCIM deactivation verification, project/artifact ownership transfer, a 30-day audit-log review of the departing user (sign-ins, exports, file events), seat reclamation, and a sign-off checklist. Identify who owns each step (IT, manager, Claude admin) and the SLA for each. Bonus: write the IdP-side automation (e.g., Okta lifecycle rule) that removes the user from the `claude-users-*` groups.

### 10.3 Billing & Licensing Models

Enterprise comes in two commercial variants (Anthropic, Aug 2026):

| Dimension | Self-serve Enterprise | Sales-assisted Enterprise |
|---|---|---|
| Contract | Card/ACH, standard terms | Invoicing, tailored terms |
| Usage billing | Prepaid shared credit pool; usage stops org-wide at zero | Billed monthly in arrears at API rates |
| HIPAA-ready | Not available in-app | Available (BAA) |
| Best for | Fast procurement, predictable cap | Regulated industries, custom DPAs |

Seat pricing is **$20/seat/month, billed annually, minimum 20 seats**, with usage billed as-you-go at API rates (Anthropic, Aug 2026 — Medium confidence from a single official page; verify). Enterprise is also available via **AWS Marketplace**, where it can draw down your existing AWS commit — useful if procurement prefers consolidated cloud spend.

The **usage-based billing model (April 2026 onward)** means your seat fee is the floor, not the total: heavy Claude Code and API-style consumption bills at API rates on top. Operationally this makes spend controls a first-class admin duty:

1. Set an **org-level spend limit** as the hard ceiling (self-serve: the credit pool is the ceiling).
2. Set **user-level limits** for high-variance populations (developers on Claude Code).
3. Configure **spend alerts** — reported at 75% and 90% of budget (secondary source; verify).
4. Review the usage/cost analytics dashboard monthly; attribute spend per user or per group before renewal season.

> **Callout:** Seat pricing, the 20-seat minimum, and usage rates are volatile. As of August 2026 — verify against current Anthropic documentation before budgeting.

### 10.4 Usage Analytics & Monitoring

Anthropic separates visibility into three layers — understand which one answers which question (per Anthropic docs via secondary reporting, Apr 2026):

| Layer | Contents | Access | Use it for |
|---|---|---|---|
| Aggregated analytics | Per-user message counts, token consumption, connector/skill usage, Claude Code metrics — **content-free** | Owner, Admin | Adoption tracking, cost attribution |
| Audit logs (Enterprise only) | Metadata-only events, past 180 days; chat/project titles and content NOT included, only UUIDs | Owner, Primary Owner export | Security review, anomaly hunting |
| Data exports & Compliance API | Full content access | Primary Owner enables; Admin API keys | eDiscovery, DLP/SIEM pipelines |

**Audit log fields.** Every entry carries `created_at`, `actor_info`, `event`, `event_info`, `entity_info`, `ip_address`, `device_id`, `user_agent`, and `client_platform`. The event taxonomy covers sign-ins, SSO/domain events, invites, projects, conversations, files, and data exports.

**Audit log review workflow (weekly, 30 minutes):**

1. Export the past week's logs from Admin settings.
2. Filter for `data export` events — every export should map to a known, justified request.
3. Filter sign-ins by `ip_address`/`client_platform` anomalies (unexpected geographies, unknown devices).
4. Review invite and role-change events against your change tickets.
5. Archive the export and your notes to your evidence store (auditors will ask).

**Compliance API.** The Primary Owner enables it under Organization settings → Data and privacy. It gives programmatic access to activity logs, chat data, and file content using Admin API keys (prefix `sk-ant-admin01-`) with the `read:compliance_activities` scope; a rate cap of roughly 600 requests/minute has been reported (Datadog integration docs + community SDK, 2026).

**OTEL monitoring (Enterprise only).** OpenTelemetry export streams usage telemetry into your observability stack for near-real-time dashboards and alerting — complement it with the audit log (which is retrospective) rather than treating them as interchangeable.

**Datadog SIEM.** An official Datadog integration ingests Anthropic compliance logs. Prerequisites: Enterprise plan, Compliance API enabled, and an Admin API key with the compliance scope. Wire it into your SIEM detection rules for bulk-download and off-hours-activity patterns.

> **Caveat:** Cowork sessions were reported (May 2026, single source) as **not captured** in audit logs/compliance data. This may have changed after Cowork GA — verify current coverage before relying on these logs for complete surveillance.

### 10.5 Governance Operating Model

Governance is a recurring operating rhythm, not a one-time setup. We recommend a quarterly cadence owned by the Primary Owner, with a standing policy template library covering three control families:

**1. Connector policies.** Connectors (remote MCP servers from Anthropic's Directory, launched July 2025 and grown to 800+ entries by July 2026) extend Claude into Google Workspace, M365, Slack, Jira, GitHub, and more. Policy template decisions: which connectors are *approved* for the org, which are group-scoped (e.g., Salesforce only for Sales Ops), and which are banned. Review the directory quarterly — new connectors appear constantly.

**2. Model entitlements.** Use the July 2026 model defaults & entitlements controls (Enterprise only) to set the default model per group and restrict access to premium or preview models. Note that Anthropic's "Covered Models" (currently Fable 5 and Mythos 5) require 30-day retention and are incompatible with ZDR-only workspaces — entitlement policy and retention policy interact (Anthropic docs via secondary reporting, Jul 2026).

**3. Retention controls.** Enterprise offers configurable data retention (Enterprise only). Baselines to choose from: API inputs/outputs are deleted after 7 days by default (reduced from 30 days in September 2025; a 30-day window is available via DPA opt-in — retention windows have changed repeatedly, verify current policy), and deleted conversations are purged within 30 days. Align your configured retention with legal-hold and records-management requirements, and document the choice.

A minimal governance rhythm: monthly spend review, quarterly connector/entitlement audit, semiannual access recertification (all Owners and Admins), annual policy refresh.

### 10.6 Compliance Deep Dive

#### Certifications

| Framework | Status (as of Aug 2026) | Evidence |
|---|---|---|
| SOC 2 Type I & Type II | Held; Type II covers API and Claude for Work/Enterprise (Type II date reported Jan 2026 — secondary registry, verify) | Trust Portal report under NDA |
| ISO 27001:2022 | Held (reported Jan 2026 — verify) | Trust Portal |
| ISO/IEC 42001:2023 (AI management systems) | Held; announced 2025-01-13, issued by Schellman (ANAB-accredited) — among the first frontier labs | Trust Portal |
| FedRAMP (commercial) | **Not held** for commercial products — see Claude for Government below | — |

Reports are distributed through the **Trust Portal (trust.anthropic.com)** under an NDA/access-request flow, not public download. Build "request latest reports" into your annual vendor-review calendar.

#### GDPR

Anthropic acts as **processor**. The Data Processing Addendum (DPA, GDPR Art. 28) is automatically incorporated into the Commercial Terms for the API and Claude for Work (Team + Enterprise); consumer tiers (Free/Pro/Max) have no DPA. The DPA includes the **2021 EU Standard Contractual Clauses, Modules 2 and 3**, plus UK and Swiss addenda; a subprocessor list lives at trust.anthropic.com with 15-day change notice; breach notification is "without undue delay" (≤48 hours per the DPA summary); deletion/return occurs within 30 days of termination (law-firm analyses, May–Jun 2026). *Caveat: sources conflict on Anthropic's EU-US Data Privacy Framework participation — verify at dataprivacyframework.gov.* Also note: EU data residency is **not** offered on first-party surfaces; EU processing paths run through AWS Bedrock EU profiles or Google Vertex AI EU regions under the cloud provider's DPA.

#### HIPAA

The HIPAA-ready offering requires a Business Associate Agreement (BAA) and is available on **sales-assisted Enterprise** (and legacy/AWS Marketplace SKUs) — the Primary Owner enables HIPAA under Organization settings → Data and privacy and accepts the BAA; self-serve Enterprise cannot enable it in-app. On the Claude Platform/API, a BAA is available with **no ZDR requirement**, and HIPAA-enabled orgs auto-block non-eligible features (Anthropic official FAQ, Aug 2026).

Exclusions matter. Covered: Messages API (with prompt caching), structured outputs, memory, web search, bash/text-editor tools, Token Counting/Models/Org Management/Compliance APIs. **Not covered:** Console/Workbench, Free/Pro/Max/Team, Cowork, Batch/Files/Skills APIs, Code Execution, Computer Use, Web Fetch, and beta features. **Claude Code is covered only with Zero Data Retention (ZDR) enabled** — and only CLI/Desktop-local mode; Desktop remote mode, Web, Code Review, and Code Security are excluded (privacy.claude.com BAA article via secondary reporting, Jul 2026).

**ZDR** itself is available for qualified accounts via commercial agreement (not self-serve): inputs/outputs are not stored at rest after the response, with abuse screening in-pipeline. Scope: Messages API and Token Counting API; excludes Batch, Files, Skills, code execution, MCP connectors, and Console. Covered Models (Fable 5, Mythos 5) require 30-day retention and cannot run in ZDR-only workspaces.

#### Claude for Government

Claude for Government is a FedRAMP High-authorized application on AWS and Google Cloud, with authorizations up to **FedRAMP High and DoD IL5**; Claude Code and Cowork are live in the FedRAMP High environment in **public beta**. Separate **Claude Gov models** serve classified environments on AWS for US national-security missions (classified document handling, tuned refusals for intelligence analysis), restricted to classified environments and subject to the same safety evaluations as commercial Claude (Anthropic, Aug 2026). Commercial Claude does **not** hold FedRAMP — route public-sector prospects accordingly.

#### Encryption & privacy baseline

All data is encrypted in transit (TLS 1.2+) and at rest (AES-256); Anthropic holds the keys (no customer-managed keys on first-party surfaces). On commercial products, prompts, data, and results are **not used to train models by default** — contractual, with no opt-in/opt-out toggle (Anthropic, Aug 2026).

### 10.7 AI Safety & Responsible Use

Anthropic positions safety as a core design property: models are trained with Constitutional AI techniques, evaluated pre-release (including the same evaluation suite for Gov models), and governed by a public **Usage Policy** that prohibits categories such as weapons development, surveillance abuse, and deceptive practices. As an admin, your responsibilities are: (1) communicate the Usage Policy to your users — enterprise contracts do not exempt you from it; (2) route policy violations and suspected misuse through your internal reporting channel and Anthropic's; (3) keep an acceptable-use addendum in your internal policy that maps Anthropic's categories to your industry rules; (4) prefer ISO/IEC 42001 alignment (Anthropic is certified) when building your own AI management system, so your controls and your vendor's controls share a vocabulary.

### 10.8 Security Best-Practice Checklist for Admins

1. Enforce SSO (SAML/OIDC) for 100% of users; block password sign-in.
2. Complete domain capture before rollout to absorb shadow accounts.
3. Enable SCIM; make IdP group membership the only onboarding path.
4. Keep exactly one Primary Owner, with a documented succession plan.
5. Minimize Owners; use Admin or custom roles instead.
6. Use custom roles via groups for fine-grained entitlements.
7. Set org-level spend limits on day one.
8. Set user-level spend limits for Claude Code-heavy developers.
9. Enable spend alerts and route them to a monitored mailbox.
10. Review analytics monthly for dormant seats and usage outliers.
11. Export and review audit logs weekly; archive for your evidence retention period.
12. Alert on every data-export event.
13. Enable the Compliance API and pipe it to your SIEM (e.g., Datadog).
14. Deploy OTEL monitoring for near-real-time telemetry.
15. Maintain an approved/banned connector list; review quarterly.
16. Set model defaults and entitlements per group.
17. Configure retention controls; document the legal basis for the chosen window.
18. For PHI, use sales-assisted Enterprise with a BAA — never self-serve; require ZDR before any Claude Code PHI use.
19. For EU data, plan on Bedrock/Vertex EU paths rather than first-party surfaces.
20. Recertify all elevated roles semiannually; test offboarding with a tabletop exercise annually.

### 10.9 Exercise 2 — Build your compliance evidence binder

Assemble (on paper or in your GRC tool) an evidence binder you could hand to an auditor tomorrow: (a) latest SOC 2 Type II and ISO certificates requested from trust.anthropic.com; (b) your executed DPA location and its SCC modules; (c) a screenshot/export of your retention settings; (d) one month of archived audit-log exports with your review notes; (e) your connector allowlist and model-entitlement matrix; (f) your offboarding runbook from Exercise 1 with one completed example. For any gap you find, write the remediation step and owner. This binder is the difference between "we believe we're compliant" and "here is the proof."

---

**Key takeaways:** Operate the lifecycle through SSO + SCIM, treat usage-based billing as a standing control problem, separate the three visibility layers (analytics, audit logs, Compliance API), run governance as a quarterly rhythm over connectors/models/retention, and keep your compliance evidence current — certifications, DPA, BAA, and ZDR scope all have sharp edges that vary by plan variant and change over time. Verify every volatile fact in this chapter against current Anthropic documentation before relying on it contractually.


---
