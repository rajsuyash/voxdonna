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
