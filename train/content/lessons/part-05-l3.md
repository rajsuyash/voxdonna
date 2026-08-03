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

:::exercise Try it #3: End-to-end collaboration exercise
1. Create a Project, upload two reference documents, and write custom instructions for a realistic team scenario.
2. In a chat inside the project, produce a **Mermaid diagram artifact** summarizing a process from your documents. Iterate twice with follow-up requests, then use the version selector to restore the first version and compare.
3. If you are on a Team/Enterprise plan, invite a colleague at **View** level and share your chat into the project activity feed. If not, simulate the audit habit instead: open Settings → Privacy → Shared Chats and review (or create and revoke) a share link — and write down your team's rule for when public links are acceptable.

You now have the interface fluency, project architecture, and artifact craft to use Claude as a durable team capability rather than a one-off chatbot. The next chapter moves into Claude's research and connector features, which plug these same workspaces into the wider information landscape.
:::

---
