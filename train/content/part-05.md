# Part 5: Feature Deep Dive I — Interface, Projects & Artifacts

In this chapter you move from *talking to Claude* to *working with Claude*. You will learn how the claude.ai web interface is organized, how to manage and search conversations, how to share chats safely (including a cautionary incident every enterprise user must know), how to use Anthropic's official prompt libraries, and how to master the two features that separate casual users from power users: **Projects** (persistent workspaces) and **Artifacts** (live, rendered output). By the end you will be able to structure an entire team's knowledge around a Project and publish interactive, shareable work products directly from a conversation.

> **Verify-as-you-go note.** Interface details, plan limits, and feature availability described in this chapter are accurate as of August 2026 — verify against current Anthropic documentation before quoting them to stakeholders. Feature status tags used throughout: (GA) generally available, (Beta), (Preview), (Research Preview), (Experimental), (Enterprise only), (Team/Enterprise only).

---

### 5.1 The Web Interface: Navigation and Chat Anatomy

Everything in this section assumes you are signed in at **claude.ai** in a browser. The desktop app (a free download from claude.ai/download for macOS 11+ and Windows 10+, GA) mirrors the web layout and adds three surfaces — **Chat, Cowork, Code** — plus extras like a Quick Entry global shortcut and built-in dictation (claudeai.guide, Jul 2026). This chapter focuses on the Chat surface, which is identical on web and desktop.

#### The sidebar

The left sidebar is your persistent navigation. Since June 2025 it is organized into distinct areas (Anthropic, Jun 2025):

- **Chats** — your conversation history, most recent first. Hover over any chat for rename/delete options.
- **Projects** — your persistent workspaces (Section 5.5). Each project expands to show the chats inside it.
- **Artifacts space** — a dedicated gallery of every artifact you have created, independent of the chat that produced it. Anthropic reported over half a billion artifacts created within a year of GA (Anthropic, Jun 2025).
- **Scheduled** — your scheduled tasks and routines (covered in the automation chapter).

#### The chat interface, element by element

When you open a chat, the main pane contains these UI elements. Since this manual is text-only, learn to recognize them by description:

1. **Model picker** (top of the chat). A dropdown showing the current model. Paid plans let you switch among the available models (e.g., the Opus, Sonnet, and Haiku tiers); Free users get the default tier. *Model availability and naming change frequently — verify the current lineup at anthropic.com as of your reading date.*
2. **Message composer** (bottom center). The text field where you type. **Shift+Enter** inserts a line break; **Enter** (or Cmd/Ctrl+Enter, depending on your settings) sends.
3. **Attachment button** (paperclip or "+" icon in the composer). Opens file upload: PDFs, DOCX, TXT, MD, HTML, CSV, XLSX, JSON, RTF, ODT, EPUB, images (JPEG/PNG/GIF/WebP up to 8000×8000 px), and code files as plain text. Video, audio, and PPTX are *not* supported as input. The per-file upload cap was historically 30 MB and has since been raised — sources in 2026 cite chat uploads up to 500 MB per file (Anthropic Docs, 2026). Per-conversation file counts are plan-gated (roughly 5 files per chat on Free, ~20 on paid plans — Anthropic does not publish exact numbers, so treat these as approximate).
4. **"Search and tools" menu** (a slider/tune icon near the composer). This opens toggles for web search, connectors, extended thinking on supported plans, and **Styles** (Normal, Concise, Formal, Explanatory, or a Custom Style built from your own writing samples — GA, all plans). Anything you toggle here applies per conversation.
5. **Response controls** (under each Claude reply): copy, retry/regenerate, thumbs up/down feedback, and — when Claude produces one — an **artifact panel** that opens on the right side of the screen (Section 5.6).
6. **Share button** (top right of the chat). Creates a public snapshot link — see Section 5.4 before you ever click it in an enterprise context.
7. **Incognito chat** (ghost icon, desktop Chat surface). Starts a session that is not saved to history or memory. Availability on the web app is unconfirmed as of August 2026 — treat as desktop-only unless Anthropic documentation says otherwise.

#### Try it #1: Interface orientation drill

1. Open claude.ai and locate each of the seven elements above. Write down where you found the "Search and tools" menu — many users never discover it.
2. Open the Style picker inside "Search and tools" and switch a single conversation between **Concise** and **Explanatory**. Ask the same question both ways ("Explain what an API rate limit is") and compare the responses.
3. Press **Cmd/Ctrl+K** and type the name of any chat from earlier this week. Jump to it without touching the mouse.

---

### 5.2 Keyboard Shortcuts

Keyboard shortcuts are the cheapest productivity upgrade available to you. The table below lists the commonly used shortcuts on web and desktop. **Caveat:** Anthropic's official shortcut list could not be verified directly for this edition; this table is drawn from reputable secondary sources (eliteaiadvantage.com, May 2026) and should be confirmed in-app — press **Cmd/Ctrl + /** to open the built-in shortcut overlay and compare.

| Action | macOS | Windows/Linux |
|---|---|---|
| Quick navigation / search all chats | Cmd + K | Ctrl + K |
| New chat | Cmd + Shift + N | Ctrl + Shift + N |
| Project switcher | Cmd + Shift + O | Ctrl + Shift + O |
| Show shortcut overlay | Cmd + / | Ctrl + / |
| Edit your last message | Cmd + ↑ | Ctrl + ↑ |
| Send message | Cmd + Enter (or Enter, per settings) | Ctrl + Enter |
| New line inside message | Shift + Enter | Shift + Enter |

Two habits pay for themselves immediately: **Cmd/Ctrl+K** instead of scrolling the sidebar, and **Cmd/Ctrl+↑** to fix a typo in your last prompt instead of starting a new chat.

---

### 5.3 Conversation Management & Search

#### Organizing and deleting chats

Every conversation is saved to your history automatically (unless you use an Incognito chat). Housekeeping basics:

- **Rename** a chat from the sidebar hover menu so it is findable later ("Q3 vendor analysis" beats "New chat").
- **Delete** chats individually, or use the sidebar's multi-select mode to delete in bulk.
- **Move chats into Projects** to group related work (Section 5.5). Chats inside a shared project remain private to you by default — see the collaboration rules in Section 5.5.

#### Searching across past conversations

Claude can search and reference your previous chats directly — you can literally ask, *"Have we ever discussed our refund policy for enterprise contracts?"* and Claude will surface the relevant prior conversation (Northeastern ITS, Sep 2025). Key behaviors:

- The capability is called **"Search and reference chats"** and is on by default. Manage it at **Settings → Capabilities → Memory**.
- It **respects project boundaries**: Claude distinguishes chats that live inside a project from those outside, so a question asked inside your "Legal Review" project does not silently pull in unrelated personal chats.
- You can disable it entirely, and you can manage what Claude remembers at **Settings → Capabilities → Memory** ("Generate memory from chat history," "View and manage memory"). Memory — rolled out to all plans including Free in March 2026 — stores synthesized summaries (your role, preferences, formatting habits), not full transcripts (Syracuse ITS, Jun 2026).

> **Enterprise caution.** On Team and Enterprise plans, your administrator controls data retention policies. Deleting a chat removes it from your view, but retention and audit behavior are governed by your organization's settings — do not assume deletion equals instant erasure from compliance systems.

---

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

#### Try it #2: Build a working Project

1. Create a Project called "Meeting Intelligence."
2. Upload three documents you own (e.g., three past meeting notes or reports). Write custom instructions: *"Summarize decisions before discussion points. Always cite the source document by filename."*
3. Ask: *"What decisions were made across all uploaded documents, and are any of them in conflict?"*
4. Add a fourth file and repeat the question. Notice the answers now reflect the combined knowledge — that is project knowledge doing work no single chat could do.

---

### 5.7 Artifacts: Deep Dive

#### What an Artifact is

An **Artifact** (preview June 2024, GA August 27, 2024, all plans including Free) is a substantial, self-contained piece of content that Claude renders in a **side panel** next to the conversation instead of burying it in the chat stream. Claude decides to create an artifact when the output is something you will want to reuse, edit, or share: a long document, a program, a diagram, an interactive page. Short answers stay inline.

Artifacts are iterative: you refine them conversationally ("make the header blue," "add error handling"), and Claude updates the panel in place. Since June 2025, all your artifacts also live in the dedicated **Artifacts space** in the sidebar.

#### Every render type

| Type | What it renders as | Typical use |
|---|---|---|
| **Markdown document (.md)** | Formatted rich text | Reports, specs, emails, documentation |
| **Code** | Syntax-highlighted, copyable | Scripts, functions, config files in any language |
| **HTML (single-page)** | Live rendered page | Landing pages, interactive explainers, dashboards |
| **React (.jsx)** | Live interactive app | Data tools, calculators, mini-applications |
| **SVG (.svg)** | Vector graphic | Logos, icons, illustrations |
| **Mermaid (.mermaid)** | Rendered diagram | Flowcharts, sequence diagrams, org charts |
| **PDF (.pdf)** | Rendered document preview | Print-ready layout review |

React artifacts run under constraints: a single default-exported component, Tailwind core utility classes for styling, and a curated library set including lucide-react (icons), recharts, mathjs, lodash, d3, Plotly, and Three.js; other external scripts must come from cdnjs (Anthropic system documentation, Jan 2026). Separately, the "create files" capability (feature preview) produces downloadable **.docx, .pptx, .xlsx, and .pdf** outputs — those are files for download, distinct from in-panel artifacts.

#### Editing and version history

You never edit an artifact's code by hand unless you want to — you ask Claude to change it, and the panel updates. Every revision is kept: use the **version selector** in the artifact panel to step backward through previous versions, compare, and restore. The panel also offers **view code / copy / download** controls so you can take the artifact's source with you. Since July 2025 you can also upload files *into* an artifact workflow, and since October 2025 artifacts gained MCP integration and persistent storage, enabling more stateful, app-like artifacts.

#### Sharing, publishing, and remixing

- **Share within a project:** artifacts in a project are visible to project members automatically.
- **Publish:** clicking **Publish** generates a public link to the artifact — anyone with the link can view it. The same July 2026 Google-indexing incident (Section 5.4) affected published artifacts, so apply the same discipline: publishing *is* publication.
- **Remix:** anyone viewing a published artifact can click **"Remix this Artifact"** to start a new chat with their own copy as the starting point — a powerful pattern for distributing templates (a team lead publishes a dashboard skeleton; each analyst remixes it with their own data).

#### Live Artifacts and interactive apps

**Live Artifacts** (introduced April 2026 in the Cowork desktop surface; paid plans) extend artifacts from static renders into **persistent, running interactive apps**: they can maintain state, respond to ongoing input, and function as lightweight tools your team returns to rather than one-off outputs (getmasset.com, May 2026). Combined with MCP connections and persistent storage, an artifact can behave like a small internal application — a live metrics dashboard, an approval workflow mockup, an interactive training quiz — built conversationally in minutes. As of August 2026, treat Live Artifacts as an evolving capability and verify current plan gating before designing processes around them.

#### Five concrete examples to try

1. **Mermaid onboarding flowchart** — *"Create a Mermaid flowchart of our employee onboarding process: HR paperwork → IT provisioning → manager intro → 30/60/90 check-ins, with a decision branch for remote vs. on-site."* Refine: *"Make the remote branch amber."*
2. **React retirement calculator** — *"Build an interactive React app: inputs for current age, savings, monthly contribution, and expected return; chart the projected balance with recharts."*
3. **SVG logo concepts** — *"Draft three minimalist SVG logo concepts for a coffee brand called Northbeam. Use only two colors each."* Iterate on the winner.
4. **HTML training microsite** — *"Create a single-page HTML onboarding guide for new sales reps: hero section, three numbered steps, FAQ accordion, brand colors #1a2e4a and #f5b942."*
5. **Markdown incident postmortem template** — *"Create a blameless incident postmortem template as a Markdown document with sections for timeline, root cause, contributing factors, action items with owners, and lessons learned."* Save it to your team's project knowledge so every postmortem starts from the same artifact-derived standard.

#### Best practices

- **Ask for artifacts deliberately.** If the deliverable is a document, diagram, or tool, say so ("create this as a React artifact") rather than hoping Claude infers it.
- **Iterate in small steps.** One change per message keeps version history meaningful and makes regressions easy to roll back.
- **Name artifacts well** — they accumulate in your Artifacts space, and "Q3 dashboard v2" is findable; "Untitled" is not.
- **Publish sparingly; remix generously.** Public links are for external audiences only. Internal distribution should ride on projects.
- **Check React constraints before requesting complexity.** If your idea needs an npm package outside the supported list, expect Claude to substitute or simplify.

---

### 5.8 Collaboration & Version Management: Putting It Together

The three systems in this chapter compose into a complete collaboration pattern:

1. **Projects** hold the shared context — knowledge, instructions, membership, and (via the activity feed) the team's shared chats.
2. **Conversations** inside the project stay private to each author unless deliberately shared; **Memory and chat search** let individuals retrieve their own history without leaking across boundaries.
3. **Artifacts** are the work products: versioned automatically, visible to project members, publishable externally only by explicit action, and remixable so good work becomes reusable templates.

The corresponding governance habits: quarterly membership and share-link audits, curated knowledge bases (mind the RAG trigger caveat), custom instructions that encode your organization's rules once instead of in every prompt, and a standing rule that public links — chat or artifact — are treated as publications, a lesson the July 2026 indexing incident taught the entire industry the hard way.

#### Try it #3: End-to-end collaboration exercise

1. Create a Project, upload two reference documents, and write custom instructions for a realistic team scenario.
2. In a chat inside the project, produce a **Mermaid diagram artifact** summarizing a process from your documents. Iterate twice with follow-up requests, then use the version selector to restore the first version and compare.
3. If you are on a Team/Enterprise plan, invite a colleague at **View** level and share your chat into the project activity feed. If not, simulate the audit habit instead: open Settings → Privacy → Shared Chats and review (or create and revoke) a share link — and write down your team's rule for when public links are acceptable.

You now have the interface fluency, project architecture, and artifact craft to use Claude as a durable team capability rather than a one-off chatbot. The next chapter moves into Claude's research and connector features, which plug these same workspaces into the wider information landscape.


---
