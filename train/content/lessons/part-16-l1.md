This chapter distills everything in the guide into operational doctrine. Each section gives you the principles first — the "why" that survives product changes — then a numbered checklist you can run as a procedure. Where a fact is volatile (pricing, limits, release cadence), it is dated and flagged for verification, because Anthropic ships roughly monthly and prices and model names change quarterly (Cross-Dimension Insights, Aug 2026).

---

### 12.1 Prompt Engineering Best Practices

Chapter 9 covers prompting in depth. This section is the condensed field guide — what to remember when you are too busy to re-read a chapter.

**Principles**

1. **The Golden Rule of clarity.** Show your prompt to a colleague with minimal context and ask them to follow it. If they would be confused, Claude will be too. Treat Claude as a brilliant but brand-new employee who lacks your norms and workflow context (Anthropic Docs, Prompting best practices, Aug 2026).
2. **Write for adaptive thinking-era models.** On Claude 4.7+ and all 5-series models, adaptive thinking replaced manual `budget_tokens` (which now returns a 400 error), and Opus 5 thinks by default. Much pre-2026 prompting folklore — manual chain-of-thought scaffolding, prefilled responses, aggressive "CRITICAL: You MUST..." trigger language — is now counterproductive. Prefer general instructions ("think thoroughly") over prescriptive step lists, and remove explicit verification instructions when migrating to Opus 5, where they cause over-verification (Anthropic Docs, Aug 2026; Cross-Dimension Insight #3).
3. **Structure with tags and sections.** Organize prompts into distinct sections (`<background_information>`, `<instructions>`, output description) using XML tags or Markdown headers, at the "right altitude": specific enough to guide, flexible enough to generalize. Note that Anthropic itself observes prompt formatting matters less as models improve — tags are increasingly about human maintainability (Anthropic Engineering Blog, Sept 2025).
4. **Curate examples, don't accumulate them.** 3–5 diverse, canonical few-shot examples steer format and tone reliably; laundry lists of edge cases do not (Anthropic Docs, Aug 2026).
5. **Engineer context, not just prompts.** Context is a finite resource with diminishing returns ("context rot"). Aim for the smallest set of high-signal tokens; put long documents at the top and the query at the end; ground answers in quoted source text before analysis (Anthropic Docs, Aug 2026).
6. **Know when not to prompt.** Not every failure is a prompting failure. Sometimes the fix is a different model, a different effort level, or a tool. Establish success criteria and an empirical test before iterating (Anthropic Docs, Aug 2026).

**Checklist — before you ship or share any prompt:**

1. Run the Golden Rule test on a colleague unfamiliar with the task.
2. State what Claude should do, not what it should not do.
3. Separate instructions, context, examples, and variable input with consistent XML tags.
4. Include 3–5 diverse examples wrapped in `<example>` tags; delete edge-case accumulations.
5. For 20k+ token inputs, put documents first and the question last.
6. If thinking quality is shallow, raise the effort level instead of adding prompt scaffolding.
7. Remove legacy prefill tricks (deprecated since Claude 4.6) and migrate JSON-forcing to Structured Outputs.
8. Define one measurable success criterion and test against it before calling the prompt done.

---

### 12.2 Team Adoption

**Principles**

- **Use the champion model.** Adoption spreads through people, not mandates. Identify one credible practitioner per team — someone whose peers already ask "how did you do that?" — and make them the first-line coach. Champions model real workflows in shared Projects rather than delivering slide decks.
- **Pilot, then scale.** Start with one team and one well-bounded workflow where capability boundaries are understood (see §12.4 and Chapter 5: the PDF 100-page vision cutoff, XLSX requiring code execution, and unsupported PPTX/ZIP/audio inputs are the limits that trip users most, not prompting skill — Cross-Dimension Insight #7). Prove the workflow, document it, then replicate.
- **Teach one mental model, not siloed products.** Chat, Claude Code, and the API share the same agent primitives — instructions + tools + memory + permissions. Train that single model and users can transfer skills across surfaces (Cross-Dimension Insight #1).
- **Build training paths by role.** General users start with Projects and prompt fundamentals; analysts add file-capability boundaries and data-analysis patterns; developers add Claude Code, MCP, and subagents; admins add governance and the Compliance API. MCP literacy is the highest-leverage advanced skill across all paths (Cross-Dimension Insight #2).

**Checklist — rolling out to a new team:**

1. Select a pilot team with a bounded, high-frequency workflow.
2. Recruit a champion per team and give them early access and a feedback channel.
3. Define the pilot's success criteria empirically before starting (time saved, review passes, adoption).
4. Train the shared mental model: instructions + tools + memory + permissions.
5. Document the capability limits the pilot will hit (files, connectors, context size) up front.
6. Collect the champion's best prompts into a shared Project as reusable instructions.
7. Review pilot results with the sponsor; only then expand to the next team.
8. Convert proven pilot workflows into onboarding material for the next cohort.

---

### 12.3 Governance

**Principles**

Governance is the actual reason enterprises buy Claude: audit logs, the Compliance API, SCIM, spend controls, and retention controls differentiate the Enterprise plan, not the model itself (Cross-Dimension Insight #4). Anthropic holds SOC 2 Type I & II, ISO 27001:2022, and ISO/IEC 42001:2023 certifications, and commercial customer data is not used for training by default (Anthropic, Aug 2026). Your governance job is to map those vendor guarantees onto your own policies.

- **Policy templates.** Maintain three living documents: an *acceptable-use policy* (what data classes may enter Claude; recall no PPTX/ZIP/audio/video inputs are supported anyway), a *connector policy* (which of the 800+ directory connectors are approved, for which roles, and with what scopes — connectors are remote MCP servers, so apply the same review rigor as any integration), and a *model entitlements policy* (which roles may use which models — enforced through RBAC and the model defaults & entitlements controls added in the July 2026 governance release).
- **Audit cadence.** Audit logs are Enterprise-only, metadata-only (UUIDs, not titles or content), and cover the past 180 days (Anthropic Docs, Apr 2026). Full content access runs through data exports and the Compliance API (Admin API keys with `read:compliance_activities` scope; official Datadog SIEM integration exists). Because logs expire at 180 days, export on a schedule or stream via the Compliance API — do not discover this limit during an investigation. ⚠️ Cowork sessions were reported as not captured in audit/compliance data (single secondary source, May 2026) — verify current coverage before relying on Cowork in regulated workflows.
- **Flagged uncertainty.** The 75%/90% spend-alert thresholds and July 2, 2026 governance-release details come from a single secondary source — verify against the Anthropic changelog (Anthropic release reporting, Jul 2026). IP allowlisting appears in secondary sources but not the official feature list; confirm with your account team.

**Checklist — standing up governance:**

1. Draft acceptable-use, connector, and model-entitlement policies; route through legal/security review.
2. Enable SSO (SAML/OIDC) with domain capture, then SCIM provisioning from your IdP.
3. Assign roles (Primary Owner → Owner → Admin → User); use custom roles on groups, Enterprise only.
4. Approve connectors explicitly; document scopes and owning team for each.
5. Configure model entitlements and defaults per role in organization settings.
6. Set org- and user-level spend limits and alerts (Enterprise only).
7. Schedule audit-log exports well inside the 180-day window, or integrate the Compliance API with your SIEM.
8. Calendar a quarterly governance review (see §12.8).

---
