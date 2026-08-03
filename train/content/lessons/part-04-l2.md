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
