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

:::exercise Try it — Exercise 2: Admin readiness checklist
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
:::

---

### 4.9 Chapter Summary

Claude Enterprise is one plan spanning chat, Claude Code, and Cowork, sold at $20/seat/month (annual, 20-seat minimum, usage at API rates — as of August 2026, verify) in self-serve and sales-assisted variants. Its real product is governance: the Admin Console, a four-level role hierarchy plus Enterprise-only custom roles and groups, SSO/SAML with domain capture, SCIM lifecycle automation, metadata-only 180-day audit logs, the content-level Compliance API with official Datadog SIEM integration, contractual no-training guarantees, configurable retention up to contract-based zero data retention (with explicit API and model exclusions), US-first-party residency with EU paths via Bedrock/Vertex, AES-256/TLS encryption, and a July 2026 wave of spend limits, alerts, and analytics/admin APIs. Master these controls, and you can give every employee frontier-model access with the guardrails your auditors, lawyers, and CFO actually require.


---
