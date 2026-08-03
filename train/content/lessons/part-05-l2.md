### 5.4 Shared Chats — and the July 2026 Privacy Lesson

#### How sharing works

Clicking **Share** in a chat generates a public link (`claude.ai/share/…`) containing a **snapshot** of the conversation up to the moment you shared it. Later messages you add are not included. Attached files are excluded from the shared view. You can review and revoke every link you have ever created at **Settings → Privacy → Shared Chats** (Anthropic support documentation, cited Jul 2026). On Team plans, you can also share chats into a **project activity feed** so teammates see project-related discussions without a public link.

#### The incident you must know about

Between **July 25 and July 27, 2026**, shared Claude chats and published artifacts were **indexed by Google** because the share pages were missing `noindex` directives — meaning content users had shared (sometimes assuming only their intended recipient would see it) was discoverable through ordinary web searches. Anthropic remediated the issue and stated: *"These shareable links are not guessable or discoverable unless people choose to share them"* (TechCrunch, Jul 27, 2026).

Treat this as a standing rule, not a one-time bug:

1. **A share link is a publication.** Anyone with the URL can read the snapshot — there is no login gate on the recipient side.
2. **Never share chats containing customer data, credentials, unreleased financials, or personal information** via public link, even "just to one colleague." Use your plan's internal collaboration features (project activity feed, shared projects) instead.
3. **Audit periodically.** Once a quarter, open Settings → Privacy → Shared Chats and revoke anything stale.
4. **Assume search engines can find public links.** Even after remediation, the safe mental model is: *if it has a public URL, it is public.*

---

### 5.5 Prompt Libraries

Anthropic maintains two official prompt libraries you should bookmark (availability as of August 2026 — verify URLs, as the documentation site structure evolves):

- **Anthropic Prompt Library** (`docs.anthropic.com/docs/en/resources/prompt-library`) — roughly 60+ ready-made prompts covering business and personal tasks: meeting summarization, code review, data extraction, tone rewriting, and more. Each is a copy-paste starting point with placeholders you fill in.
- **Claude Code Prompt Library** (`code.claude.com/docs/en/prompt-library`) — roughly 50+ prompts organized by developer role and task.

Note that these are **documentation resources**, not an in-app consumer feature — there is no confirmed built-in "prompt library" panel inside claude.ai itself. In practice, enterprises build their own internal equivalents: a shared document or project whose knowledge base contains the organization's approved prompt patterns (Section 5.6 shows how Projects make this natural).

**How to use a library prompt well:** treat it as a draft. Adapt the role, the audience, the output format, and the constraints to your context, and add your data. A library prompt with your specifics pasted in outperforms the generic version every time.

---

### 5.6 Projects: Persistent Workspaces

#### What a Project is

A **Project** (GA since June 25, 2024; Pro, Max, Team, and Enterprise plans — *not* available on Free) is a persistent workspace that bundles three things (Anthropic, Jun 2024):

1. **A set of chats** — every conversation started inside the project lives there.
2. **Project knowledge** — files you upload once (documents, spreadsheets, code, style guides) that are available to *every* chat in the project automatically.
3. **Custom instructions** — standing directions Claude applies to every chat in the project (tone, format, domain rules).

Each project has a **200K-token context window** (500K on Enterprise plans). A token is roughly three-quarters of a word; 200K tokens is on the order of a 500-page book.

#### Creating a Project

1. In the sidebar, click **Projects → New Project**.
2. Give it a name and description (the description helps collaborators understand scope).
3. Open the project and click **Add content** (or drag files in) to build the knowledge base.
4. Open the project's **custom instructions** field and write standing guidance, e.g.:

```text
You are assisting the Acme Corp legal-ops team. Answer in plain English,
cite the specific uploaded policy document you relied on, and flag any
question that requires a licensed attorney rather than answering it.
```

5. Start chats inside the project. Every chat now sees the knowledge base and instructions.

#### Project knowledge and the 10x RAG expansion

Project knowledge files count against the project's context window — until they don't. When your knowledge base grows beyond what fits in context, Claude automatically switches to **RAG mode** (*retrieval-augmented generation*: instead of loading every file into the conversation, Claude retrieves only the relevant excerpts for each question). This effectively expands the knowledge capacity **up to 10x** the context window (Anthropic feature reporting, 2025–2026). RAG mode became available as the knowledge base scaling mechanism rolled out in mid-2025.

> **⚠ Caveat — RAG trigger threshold.** Multiple practitioner reports indicate RAG mode can engage at a surprisingly low threshold — reportedly around **13 files** in the knowledge base, regardless of total token count — rather than only when the context window is genuinely full. When RAG is active, Claude reads excerpts rather than whole files, which can reduce answer quality for questions that require synthesizing an entire document. This behavior is not officially documented; if your work depends on Claude reading complete files, keep knowledge bases lean and verify behavior in your own project.

Other knowledge limits: the same per-file upload cap as regular chat applies; there is no strict file-count cap — the soft cap is the context window (or RAG retrieval quality). Knowledge files are shared with everyone who has project access.

#### Sharing and role-based collaboration (Team/Enterprise)

Projects are private by default. On Team and Enterprise plans you can invite collaborators (individually or via **bulk email invitations**) at one of three permission levels (Northeastern ITS, Sep 2025):

| Role | Can read chats & knowledge | Can chat in project | Can add/edit knowledge & instructions | Can manage members |
|---|---|---|---|---|
| **View** | ✅ | ✅ | ❌ | ❌ |
| **Edit** | ✅ | ✅ | ✅ | ❌ |
| **Owner** (creator) | ✅ | ✅ | ✅ | ✅ |

Two privacy rules matter for collaboration:

- **Chats inside a shared project are private to their author by default.** A teammate can see the project's knowledge and activity, but not your conversations unless you share them into the **project activity feed** (Team plans), which is the sanctioned way to make a discussion visible to the team — no public links required.
- **Artifacts created inside a project are visible only to project members**, not to the whole organization and never to the public unless explicitly published.

#### Best practices

- **One project per durable context** (a client, a product, a course) — not one per task. Knowledge accumulates value over time.
- **Curate, don't dump.** Because of the RAG-trigger caveat above, upload the 10 files that matter, not the 200 that exist.
- **Write real custom instructions.** "You are a helpful assistant" wastes the feature; encode audience, format, citation, and escalation rules.
- **Name knowledge files clearly** (`pricing-policy-2026H2.pdf`, not `final_v3_FINAL.pdf`) — retrieval quality depends partly on file identity.
- **Review membership quarterly** on shared projects; revoke access for departed team members through your admin controls.

#### Enterprise use cases

- **Legal-ops review:** contracts + playbooks as knowledge; instructions enforce citation and attorney-escalation.
- **Sales enablement:** product sheets, pricing, competitive battlecards; reps ask prospect-specific questions against approved material.
- **Support documentation:** full help-center export as knowledge; agents draft responses grounded in current docs.
- **Engineering onboarding:** architecture docs, runbooks, style guides; new hires query the project instead of interrupting senior engineers.
- **Executive briefing:** board papers and KPI dashboards in one project; leadership asks ad-hoc questions with consistent framing.

:::exercise Try it #2: Build a working Project
1. Create a Project called "Meeting Intelligence."
2. Upload three documents you own (e.g., three past meeting notes or reports). Write custom instructions: *"Summarize decisions before discussion points. Always cite the source document by filename."*
3. Ask: *"What decisions were made across all uploaded documents, and are any of them in conflict?"*
4. Add a fourth file and repeat the question. Notice the answers now reflect the combined knowledge — that is project knowledge doing work no single chat could do.
:::

---
