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
