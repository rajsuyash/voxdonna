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
