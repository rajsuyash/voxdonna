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

:::exercise Try it — Console orientation (Exercise 1, part A)
1. Open Organization settings and identify your Primary Owner. If that is not you, note the escalation path.
2. List every Owner and Admin. Flag any account without SSO sign-in.
3. Export one month of analytics and locate your top five users by token consumption.
4. Set an org-level spend limit if none exists, and record who receives the spend alert.
:::

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
