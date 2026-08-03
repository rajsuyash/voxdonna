# Part 16: Best Practices

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

### 12.4 Productivity

**Principles**

- **Projects hygiene.** Projects (with RAG-based knowledge retrieval) are your persistent workspace; chats are ephemeral. Keep project knowledge curated and current — stale documents in project knowledge silently degrade every answer. Treat the project instructions field as a maintained system prompt: version it, review it, apply §12.1.
- **Artifact workflows.** Artifacts (6+ types, with publish/remix and Live Artifacts since April 2026) are the durable output surface. Promote anything you will reuse — documents, code, dashboards — into an artifact rather than leaving it in scrollback; publish and remix rather than copy-paste.
- **Keyboard-driven usage.** Power users stay in flow by learning the interface's keyboard shortcuts and command palettes rather than reaching for menus; make shortcut literacy part of onboarding (verify current shortcut reference in Anthropic's help center, as bindings change with releases).
- **Routines.** Routines (research preview April 2026, with daily caps) automate recurring prompts. Use them for standing tasks — morning briefings, weekly report scaffolding — rather than re-typing the same prompt.
- **Respect capability boundaries.** PDFs over 100 pages are processed text-only; XLSX needs code execution enabled; PPTX/ZIP/audio/video are not supported as inputs; chat uploads are up to 500MB per file as of 2026 (recently raised — verify current limits) (Anthropic Docs, 2026).

**Checklist — personal productivity setup:**

1. Create a Project per ongoing body of work; migrate valuable chats into them.
2. Curate project knowledge monthly: remove stale files, add current source documents.
3. Maintain project instructions as you would a production prompt (§12.1 checklist).
4. Move reusable outputs into artifacts; publish those others should remix.
5. Learn the keyboard shortcuts for your five most frequent actions.
6. Automate recurring prompts as Routines within daily caps.
7. Check file-type support before uploading; enable code execution for spreadsheets.
8. Start a fresh chat when context drifts — a new window often beats a long degraded one.

---

### 12.5 Cost Optimization

**Principles**

- **Right-size the model.** Per the selection framework (Chapter on plans and models): Haiku 4.5 ($1/$5 per MTok) for high-volume simple tasks, Sonnet 5 for the default middle, Opus 5 ($5/$25) for hard reasoning, Fable 5 ($10/$50) for frontier needs. Note Sonnet 5's introductory $2/$10 pricing rises to $3/$15 on 2026-09-01 — *as of August 2026, verify against current Anthropic documentation*. Routing easy questions to smaller models and hard ones to larger models is Anthropic's own canonical cost pattern (Anthropic Engineering Blog, "Building effective agents," Dec 2024).
- **Use prompt caching.** Cache stable prefixes (system prompts, tool definitions, long documents) with 5-minute or 1-hour TTLs to cut repeated input costs (Anthropic Docs, 2026).
- **Use the Batch API.** Non-interactive workloads (evals, bulk classification, overnight reports) cost 50% less via the Message Batches API (Anthropic Docs, 2026). Note the Batch API is excluded from ZDR scope.
- **Set spend controls.** Enterprise admins can set org- and user-level spend limits with alerts (reportedly at 75% and 90% of budget — verify); self-serve plans draw from a shared prepaid credit pool that stops org-wide at zero (Anthropic, Jul 2026).
- **Monitor continuously.** Use the usage/cost analytics dashboard and Analytics API (Enterprise only, July 2026 governance release — verify against changelog). Watch agentic workloads specifically: Anthropic reports agents consume roughly 4× the tokens of chat, and multi-agent research systems roughly 15× (Anthropic Engineering Blog, Jun 2025). Claude Code averages roughly $13/developer/day (Anthropic Docs, 2026).

**Checklist — monthly cost review:**

1. Pull the usage/cost analytics dashboard; rank top users and workspaces by token consumption.
2. Audit model selection: flag Opus/Fable usage on tasks that fit Sonnet or Haiku.
3. Confirm spend limits and alert thresholds are set at org and user level.
4. Identify repeated long prompts and move stable prefixes into prompt caching.
5. Convert eligible non-interactive jobs to the Batch API (−50%).
6. Review Claude Code and agentic-workflow spend separately (4×–15× token multipliers).
7. Re-check current pricing — model prices change quarterly (Sonnet 5 change 2026-09-01).
8. Report cost per outcome, not just cost, to the budget owner.

---

### 12.6 Security

**Principles**

- **Baseline guarantees.** Commercial plans carry contractual no-training-on-your-data by default, TLS 1.2+ in transit, AES-256 at rest, SOC 2 / ISO 27001 / ISO 42001 certifications, and a GDPR DPA with SCCs automatically incorporated into Commercial Terms (Anthropic, Aug 2026). Default API retention is 7 days (30-day opt-in via DPA); verify current retention terms, as windows have changed repeatedly.
- **Apply ZDR deliberately.** Zero Data Retention (commercial agreement, not self-serve) means inputs/outputs are not stored at rest after the response. But scope matters: ZDR covers the Messages API and Token Counting API and excludes the Batch API, Files API, Skills API, code execution, and MCP connectors — and designated Covered Models (Fable 5, Mythos 5) require 30-day retention and are incompatible with ZDR-only workspaces (Anthropic Docs, Jul 2026). Enable it where data sensitivity demands it; do not assume org-wide coverage.
- **Review connector permissions on a schedule.** Every connector is a remote MCP server with its own scopes into a third-party system (Google Workspace, M365, Slack, Salesforce, etc.). Treat each as a vendor integration: least-privilege scopes, named owner, periodic re-review.
- **Shared-chat caution.** Shared and published conversations can propagate further than users expect — links get forwarded, remixes get published, and shared content can outlive the sharer's intent. Following the July 2026 sharing incident reported in internal guidance, the working rule for this guide is: *never share a chat containing customer data, credentials, personal data, or pre-release business information; review the full thread — including earlier turns and artifacts — before sharing; prefer sharing a cleaned artifact over a raw chat.* (⚠️ Details of the incident are not documented in the research corpus; treat this as a cautionary policy, verify against your organization's current guidance.)
- **Offboard completely.** SCIM deactivation from your IdP removes access, but also rotate any user-created API keys, reassign ownership of shared Projects, and review connectors the user authorized. Deleted conversations are purged within 30 days; Enterprise retention controls are configurable.

**Checklist — quarterly security review:**

1. Re-confirm data-classification rules against acceptable-use policy.
2. Audit every enabled connector: owner, scopes, last-used, still justified.
3. Verify ZDR scope matches assumptions for regulated workloads (exclusions above).
4. Re-run shared-chat hygiene training; spot-check shared links and published artifacts.
5. Test the offboarding runbook end-to-end on a test account (SCIM, keys, Projects, connectors).
6. Review audit-log export pipeline and SIEM integration health.
7. Verify retention configuration against current Anthropic terms (7-day default; 30-day DPA opt-in).
8. Confirm HIPAA/regulated configurations: BAA signed, non-eligible features auto-blocked.

---

### 12.7 Collaboration

**Principles**

- **Share through Projects, with roles.** Projects are the collaboration unit on Team and Enterprise plans: share the project, and its knowledge and instructions come with it. Assign sharing roles deliberately — restrict edit rights on project knowledge and instructions to curators, and give consumers read/use access, so the shared brain does not drift.
- **Curate knowledge as a team sport.** Project knowledge is only as good as its curation. Nominate a knowledge owner per shared project who prunes stale documents, resolves contradictions (Claude will try to follow contradictory instructions), and onboards new documents with source metadata. Retrieval quirks in Projects' RAG make document hygiene more impactful than prompt tuning (Cross-Dimension Insight #7).
- **Version what you share.** Treat shared instructions, CLAUDE.md files, and published artifacts as versioned artifacts: change-log them, review changes before publishing, and keep the prior version recoverable. Publish/remix workflows give you a natural fork-and-merge model — remix a published artifact rather than editing the canonical one.

**Checklist — running a shared project well:**

1. Name a knowledge owner and a backup for every shared project.
2. Set explicit roles: who may edit knowledge/instructions vs. who consumes.
3. Onboard new documents with source, date, and owner noted.
4. Prune or refresh stale documents on a monthly cadence.
5. Resolve contradictory instructions rather than layering new ones on top.
6. Version-control shared instruction files; log each material change.
7. Publish canonical artifacts; have others remix rather than overwrite.
8. Offboard departing members' edit rights promptly (§12.6).

---

### 12.8 Change Management

**Principles**

Anthropic's release cadence is itself an operational fact you must manage: roughly monthly feature releases through 2025–2026, with prices, limits, and model names changing quarterly — e.g., the Sonnet 5 price change on 2026-09-01 and the Opus 4.1 retirement on 2026-08-05 (Cross-Dimension Insight #8). Organizations that treat "verify against release notes" as a standing process absorb change cheaply; those that don't get surprised by deprecations like `budget_tokens` and prefill removal.

- **Release-note monitoring process.** Assign an owner to review Anthropic's release notes and changelog monthly. Triage each item into: *communicate* (users must know), *configure* (an admin must change a setting or entitlement), or *ignore*. Deprecations and model retirements get a migration owner and a deadline.
- **Quarterly policy reviews.** Once a quarter, re-run the governance, security, and cost checklists (§§12.3, 12.5, 12.6) against the current feature set. Quarterly matches Anthropic's pricing/model change rhythm.
- **Internal communications templates.** Keep three short templates ready:

```text
[NEW FEATURE]
What changed: <feature, status tag (GA/Beta/Preview)>
Who it affects: <roles/teams>
What to do: <action or "nothing required">
Effective: <date> | Source: <release notes URL>
```

```text
[DEPRECATION / RETIREMENT]
What is going away: <feature/model, date>
Impact: <workflows affected>
Migration: <steps, owner, deadline>
```

```text
[PRICING / LIMIT CHANGE]
What changed: <old → new, effective date>
Budget impact: <estimate from analytics dashboard>
Action: <right-sizing or limit adjustments>
```

**Checklist — your change-management loop:**

1. Assign a release-notes owner and a monthly review slot.
2. Triage every release item: communicate / configure / ignore.
3. Attach an owner and deadline to every deprecation or model retirement.
4. Update internal training material when the shared mental model changes.
5. Re-verify volatile facts (pricing, limits, model availability) against current Anthropic documentation each quarter.
6. Run the quarterly governance, security, and cost checklists.
7. Send communications using the templates above; log what was sent and when.
8. Feed lessons from each change back into your policy templates and training paths.

---

#### Try It

1. Run the §12.1 checklist against one prompt your team actually uses in production; document what you changed and why.
2. Draft your three governance policy templates (acceptable use, connectors, model entitlements) as one page each, using your current connector list.
3. Do a right-sizing pass: pick last month's ten most expensive workflows from the analytics dashboard and assign each a target model per the selection framework.
4. Write one [DEPRECATION] communication using the template above for a real upcoming change (e.g., a model retirement), and identify its migration owner.


---
