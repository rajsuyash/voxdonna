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
