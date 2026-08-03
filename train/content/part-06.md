# Part 6: Feature Deep Dive II — Files, Vision, Data, Research & Agentic Features

In the first half of this chapter you learned how conversations, Projects, and Artifacts structure your work in Claude. This second half goes deeper into the capabilities that turn Claude from a chat partner into a working analyst: uploading and processing files, understanding images, running real code against your data, searching and researching the web, and — the biggest shift of 2026 — delegating multi-step work to agentic features such as Routines and Cowork. Each section starts with the fundamentals and builds to the practices enterprise power users rely on. Limits and plan gates are noted as of August 2026 — verify volatile details against current Anthropic documentation.

---

### 5.9 File Uploads: What Claude Accepts and How It Processes It

The fastest way to make Claude useful is to hand it your actual documents. Drag files into the chat composer (or use the attachment icon) and Claude reads them as part of your conversation.

#### Supported file types

| Category | Types | Notes |
|---|---|---|
| Documents | PDF, DOCX, TXT, MD, HTML, ODT, RTF, EPUB | Text extraction; PDFs get special tiered handling (below) |
| Data | CSV, TSV, JSON, XLSX | **XLSX requires "code execution and file creation" to be enabled** in your account (Claude Help Center, "Upload files to Claude") |
| Images | JPEG, PNG, GIF, WebP | Up to 8000 × 8000 pixels |
| Code | Any code file | Treated as plain text |

**Not supported as uploads:** PowerPoint (.pptx), ZIP archives, video, and audio files. Claude can *create* .pptx files via code execution, but cannot ingest them — convert slides to PDF first. For audio/video, transcribe externally (or use voice dictation, covered later) and upload the text (Claude Help Center, Aug 2026).

#### Limits (as of August 2026 — verify; these changed during 2026)

| Limit | Value |
|---|---|
| File size (chat uploads) | **500 MB per file** — raised from the long-standing 30 MB cap during 2026; older guides still cite 30 MB |
| Files per chat | Up to **20 files** (paid plans); third-party comparisons report ~5 per chat on Free |
| Image dimensions | Up to 8000 × 8000 px; 20 images per message |
| PDF length | Up to 1000 pages |
| Project knowledge files | 30 MB per file, unlimited count, total must fit the context window (RAG expands effective capacity ~10×) |
| API Files API (Beta) | 500 MB per file, server-side persistence via `file_id` |

> **Caveat — the 30 MB / 500 MB conflict.** Anthropic's code-execution help article still states a 30 MB maximum per file *for uploads and downloads passing through the code-execution sandbox*, while the upload article states 500 MB for chat attachments generally. Read this as: chat attachments up to 500 MB; files moved into (or created by) the sandbox capped at 30 MB. Two official pages are not fully reconciled — verify if your workflow depends on it.

#### How PDFs are processed: the three tiers

PDF handling is tiered by page count, and the tier determines whether Claude *sees* your document or merely *reads* it (Claude Help Center):

1. **1–100 pages:** Claude analyzes **both text and visual elements** — images, charts, and graphics on each page.
2. **101–1000 pages:** Claude processes **text only**; charts and figures are not analyzed.
3. **Over 1000 pages:** upload rejected ("file is too large"). Split the document.

Practical implications: keep visually rich documents (annual reports, design decks exported to PDF) under 100 pages when the charts matter. For long text-only documents, split by chapter and use a Project so Claude can draw on all parts. When referencing pages, use the page numbers **as shown in the PDF viewer**, not the numbers printed on the page. For non-PDF documents, note that extraction is text-only — embedded images inside a DOCX are not read.

#### Try it: file triage

1. Export any slide deck as PDF (if over 100 pages, split it) and upload it to a new chat.
2. Ask: "Summarize the argument of this document in five bullets, then list every claim supported by a chart, citing the PDF page number."
3. Upload a CSV alongside it and ask Claude to reconcile the two ("Does the data support the claim on page 12?"). Observe which file types trigger the code-execution environment.

---

### 5.10 Vision: Images, OCR, Charts, and Design Review

Claude's vision capability lets it interpret images you upload — photographs, screenshots, scanned pages, diagrams — and reason about them in natural language.

#### What vision does well

- **Document and screenshot understanding:** reading dense pages, forms, and UI screenshots. On Claude 4.7-and-later models, a high-resolution vision tier processes images up to a 2576 px long edge (about 3.75 MP), marketed for computer use, screenshot understanding, and dense documents (platform.claude.com vision docs).
- **Charts and diagrams:** extracting trends, axes, and approximate values from plots; explaining flowcharts, architecture diagrams, and Mermaid sources.
- **UI analysis and design review:** a documented workflow is to paste a screenshot and ask Claude to first describe the UI elements, then infer the user journey, then propose UX improvements. Anthropic Labs' **Claude Design** (Research Preview, Apr 2026; Pro/Max/Team/Enterprise), powered by Opus 4.7, extends this — it reads design files to extract fonts, colors, and components and produces interactive prototypes and wireframes (support.claude.com; third-party corroboration).

#### OCR and handwriting

Claude performs optical character recognition (OCR) — converting text in images to machine-readable text — as part of vision. On printed and typed documents, third-party benchmarks put accuracy at roughly 95% or better. Handwriting is harder: an independent 2026 benchmark measured Claude Sonnet 4.6 vision at about **11% word error rate (WER)** on standard handwritten English prose — competitive with general cloud OCR but well behind dedicated handwriting-OCR tools (~1% WER) (handwritingocr.com, 2026; independent benchmark, not Anthropic-published). Roboflow's July 2026 OCR benchmark ranked Claude Fable 5 highest among tested models at 94.0%. Treat these numbers as directional third-party measurements.

**Known limitations (official):** Claude can err or hallucinate on low-quality, rotated, or very small images (under ~200 px); object counting is approximate; it cannot identify people in images, cannot judge whether an image is AI-generated, and should not be used to interpret complex diagnostic scans such as CT or MRI (platform.claude.com vision docs).

**Getting the best results:**

1. Use clear images, at least 1000 × 1000 px; avoid heavy JPEG compression on text.
2. Place images **before** the text of your prompt.
3. Crop or pre-resize; if you send many images, keep each under ~2000 px per dimension.
4. For handwriting, tell Claude the context ("this is a doctor's referral note from 1987") — context materially improves transcription.

#### Try it: OCR reality check

1. Photograph or scan a page containing a table and a short handwritten note.
2. Prompt: "Transcribe the handwritten note verbatim inside a quote block. Then extract the table as CSV. Flag any words or cells you are unsure of with [?]."
3. Compare against the original. Note where errors cluster (cursive, faded ink, small fonts) — that tells you where human verification is mandatory in production workflows.

---

### 5.11 Data Analysis: Code Execution, File Creation, and Dashboards

This is where Claude stops describing data and starts *computing* on it.

#### Code execution and file creation (GA; all plans — Free through Enterprise)

The original JavaScript "analysis tool" has been superseded by **code execution and file creation**: Claude runs code in a sandboxed Linux container (Ubuntu 24, Python-centric) directly inside your conversation, on web, desktop, and mobile, enabled by default on **all plans** (Claude Help Center, "Create and edit files with Claude," Apr 2026). Pre-installed scientific Python libraries include **pandas, numpy, scipy, matplotlib, and scikit-learn**; Bash and filesystem access (uploads and outputs directories) are available inside the sandbox.

What it can do:

- Analyze uploaded CSV/TSV/XLSX data with real Python — cleaning, joins, statistics, regressions, ML models.
- **Create downloadable files:** Excel workbooks with *working formulas*, PowerPoint decks, Word documents, and PDFs (the docx/pptx/xlsx/pdf Skills are auto-selected), plus charts as PNG.
- Process files you upload through the sandbox and return results as download links, or save to Google Drive.

Constraints you must design around:

- The sandbox is **isolated**: no access to your filesystem, no persistence beyond the session, task duration limited.
- **Network access is restricted to approved domains** (package indexes such as pypi, npm, github, crates.io, Ubuntu archives, api.anthropic.com). On Free/Pro/Max network access is on by default within that allowlist; on **Team/Enterprise it is off by default** — an admin enables it. Anthropic's hardening guidance: start with network off, enable package managers, then allowlist domains, and note that MCP connections bypass network-egress settings (Claude Help Center, Apr 2026).
- Files through the sandbox are capped at 30 MB each (see the caveat in §5.9).

#### CSV and statistical workflows

The canonical workflow: upload a CSV, ask a question in plain language, and Claude writes and runs pandas code, shows its work, and returns tables, charts, or a cleaned file. Because the code is real, results are reproducible — ask Claude to "show me the exact code you ran" and you can audit or rerun it. For Excel specifically, two paths exist:

1. **In chat:** upload the workbook (code execution enabled) and Claude reads, analyzes, and rewrites it with formulas preserved.
2. **Claude for Excel add-in** (Pro/Max/Team/Enterprise): Claude lives inside Excel, reads multi-tab workbooks, explains calculations with **cell-level citations**, updates assumptions while preserving formula dependencies, and creates pivot tables and charts (Microsoft AppSource listing, Aug 2026). M365 add-ins for Excel, PowerPoint, and Word reached GA in May 2026.

#### Dashboards via Artifacts

For interactive output, Claude builds **React artifacts** — dashboards rendered in a side panel using pre-installed libraries including Recharts, D3, Plotly, Tailwind, and Lucide icons. A typical prompt produces a filterable, interactive dashboard from your CSV in one shot. **Live Artifacts** (Apr 2026, paid plans, Cowork/Desktop) re-execute their code when reopened so dashboards refresh with current data. Artifacts can be published to a public link and remixed by colleagues.

#### Try it: from CSV to dashboard

1. Upload any CSV export (sales, tickets, expenses — at least a few hundred rows).
2. Prompt: "Profile this dataset: row count, column types, missing values, and three things worth investigating. Run the analysis in code and show me the key numbers."
3. Follow up: "Build an interactive React dashboard artifact with a date-range filter, a trend line of the top metric, and a breakdown table. Use Recharts."
4. Finally: "Create an Excel file summarizing the findings, with a working formula computing the month-over-month change." Download and verify the formula in Excel.

---

### 5.12 Web Search and Research

#### Web search (GA; all plans)

Web search lets Claude fetch current information from the internet instead of relying solely on training data. It became globally available to all paid plans in May 2025, and 2026 plan pages list web search capability for Free as well (Anthropic, May 2025; claudelog pricing, Jul 2026 — free-plan limits not officially published).

**How it works:** when your prompt needs current facts, Claude issues search queries, reads results, and synthesizes an answer with linked citations you can click through. You can also force it with phrasing like "search the web for…".

**Prompting practices:**

- Be specific about the entity and timeframe: "Search for Anthropic's enterprise plan features announced in 2026" beats "what's new."
- Ask for comparison of sources: "If sources disagree, tell me."
- Request citations explicitly and **verify them** — click through before acting on prices, legal, medical, or compliance claims. Search synthesis can compress nuance; the citation is the source of truth.

#### Research (agentic reports; Pro/Max/Team/Enterprise)

The **Research** button escalates web search into an agentic, multi-step investigation. Claude decomposes your question into sub-questions, searches across the web, Google Workspace, and connected apps, cross-checks findings, and delivers a comprehensive report with citations — typically in **5 to 45 minutes** depending on scope (Anthropic/SiliconANGLE, Apr–May 2025; feature launched ~Apr 2025 for Max/Team/Enterprise, expanded with Integrations, now included in Pro).

Use Research when: the question is open-ended ("compare the EHR integration landscape for mid-size hospital systems"), requires many sources, or needs a citable deliverable. Use ordinary web search when: you need one current fact fast.

**Verification discipline:** Research reports cite their sources inline. Skim the citations in any section you plan to act on; pay special attention to dates in fast-moving domains. Treat the report as a strong first draft of an investigation, not the final word.

---

### 5.13 Thinking, Memory, Styles, Voice, and Incognito

#### Extended and adaptive thinking

**Extended thinking** (paid plans; launched with Claude 3.7 Sonnet, Feb 2025) lets Claude reason step-by-step through hard problems before answering. The 2026 model generations evolved this into **adaptive thinking**: an effort ladder (standard / high / xhigh / max on current models) that trades speed and cost against reasoning depth, with effort control available in claude.ai and Cowork on all plans since May 2026 (Anthropic, "Claude Opus 4.8," May 2026). The newest models think adaptively by default, spending more effort when the problem warrants it. In the UI you choose effort in the model/effort controls; use higher effort for multi-step analysis, lower effort for quick drafting.

#### Memory (GA; all plans since March 2026)

Claude maintains persistent, cross-conversation **memory**: synthesized summaries of your role, preferences, and formatting habits — not full transcripts. Team and Enterprise received memory in September 2025; it rolled out to all users including Free in March 2026 (university IT guides; rollout date partly single-sourced — verify). Manage it at **Settings → Capabilities → Memory**, where you can toggle "Search and reference chats" and "Generate memory from chat history," and view or delete individual memories. You can also say "add to memory: I prefer answers with an executive summary first." Memory respects project boundaries, and Enterprise admins control retention separately.

#### Styles (GA; all plans)

Styles control how Claude writes. Four presets — **Normal, Concise, Formal, Explanatory** — plus **Custom Styles** built from your writing samples or explicit instructions. Switch per conversation via the "Search and tools" (slider) menu; styles sync across devices. In enterprises, custom styles are the cheapest brand-voice governance you will ever deploy: build one from three exemplar documents and share the instructions with the team.

#### Voice mode (Beta; all plans, expanded July 2026)

Two-way spoken conversation on web, desktop, and mobile. The July 2026 rebuild lets paid users run voice on Sonnet or Opus (defaulting to your last text model), pull context from connected apps such as Gmail and Calendar, and converse in 11 languages; Free users are limited to Haiku and a single connected app. It is turn-based rather than full-duplex, offers five preset voices, saves transcripts to history, and counts toward usage limits (Engadget, Jul 2026 — feature is explicitly Beta and evolving). Mobile **dictation** (mic-to-text input) is separate; audio is deleted after transcription.

#### Incognito chat

The desktop app offers **Incognito chat** (ghost icon): the session is not saved to history and does not touch memory — the analogue of a browser's private window. Use it for sensitive one-off questions. (Feature confirmed via cross-product references and university IT documentation; no dedicated official help article was retrievable — treat web-app availability as unverified.)

---

### 5.14 Agentic Features: Routines and Cowork

The defining enterprise shift of 2026: Claude stopped waiting for your next prompt.

#### Routines (Research Preview, April 2026)

**Routines** in Claude Code are saved, repeatable agent runs: a prompt plus repositories and connectors, executed on Anthropic's cloud (your laptop can be off) or locally. Three trigger types (tessl.io; hatchworks, Apr–Jul 2026):

1. **Schedule** — hourly, daily, weekly (cron-style).
2. **API webhook** — an external system fires the routine.
3. **GitHub event** — e.g., run on every new pull request.

Daily execution caps by plan: **Pro 5 / Max 15 / Team and Enterprise 25** (as of August 2026 — Routines is explicitly a Research Preview; caps and behavior can change, and execution bugs were reported in April 2026). Pushes are restricted to `claude/`-prefixed branches by default. A sibling surface, **Cowork Scheduled Tasks** (`/schedule` or the Scheduled sidebar page), runs recurring desktop tasks but requires the computer awake with the desktop app open; missed runs re-fire on reopen.

#### Cowork: the desktop agent (Research Preview Jan 2026 → GA spring 2026)

**Cowork** is a no-code agent surface in the Claude desktop app, sitting beside Chat and Code. You grant it a local folder (and optionally connectors like Slack and Google Workspace, Chrome browser control, or full desktop control as a fallback), describe an outcome, and it plans and executes multi-step work autonomously — reading, writing, and organizing files, filling spreadsheets, browsing — with **permission prompts** gating sensitive actions. It can spawn sub-agents for parallel workstreams.

Timeline and availability: research preview January 12, 2026 (macOS, Max); Windows beta February 2026; **GA in spring 2026** on macOS and Windows for every paid plan from Pro up (exact GA date conflicts across sources — Anthropic release notes cite April 9, 2026). In **July 2026 Cowork expanded to web and mobile** with cloud-hosted remote sessions (Beta, Max first, then Pro): tasks keep running after you close your laptop, scheduled tasks run with no device online, and approvals arrive as push notifications (Wired, Jul 2026). Companion pieces: **Dispatch** (Research Preview, Mar 2026) — assign and monitor desktop Cowork tasks from your phone — and **computer use inside Cowork** (Research Preview, Mar 2026, macOS Pro/Max), where Claude operates the desktop directly with permission gates. Desktop requirements: Apple Silicon Mac or Windows Pro/Enterprise with Hyper-V; Intel Macs and Windows Home get Chat and Code only.

#### Planning, iteration, and safety

Cowork works in a plan–act–check loop: it drafts a plan, executes steps in a sandboxed environment, self-checks results, and asks when it hits something irreversible or ambiguous. Enterprise controls shipped with GA include RBAC, analytics, and OpenTelemetry instrumentation; admins govern which folders, connectors, and capabilities users can grant.

**Safety practices for enterprises:**

1. Grant the narrowest folder scope that fits the task; never a home directory.
2. Keep permission prompts on for destructive or external actions (sends, deletes, purchases); review the plan before approving execution.
3. Start scheduled agents in "report-only" mode (analyze and summarize, don't change anything) before graduating to write access.
4. Remember: MCP connections bypass the sandbox's network-egress settings — audit connectors before enabling them in agent workflows.

**Enterprise applications that work well today:** recurring report generation from local data, file and inbox triage, spreadsheet consolidation across folders, monitoring dashboards via Live Artifacts, marketing-ops bundles, and scheduled code review via Routines.

#### Image generation: status

One boundary to set expectations: **Claude does not generate or edit raster images** — no text-to-image, inpainting, or style transfer — as of August 2026. This is a deliberate product boundary. Claude *can* produce SVG graphics, Mermaid diagrams, charts, and interactive visuals via Artifacts and code, and can connect to external image generators through MCP. Reports of internal `create_image` functions come from an unverified February 2026 code leak — treat as rumor, not roadmap.

#### Try it: your first agent

1. In the desktop app, open the Cowork tab and grant it access to a *test* folder containing a few files you don't mind reorganizing.
2. Task: "Inventory this folder. Produce a Markdown report of file types, sizes, and duplicates, and propose — but do not execute — a reorganization plan."
3. Review the plan, then approve execution of one step only.
4. On the Scheduled page, create a weekday-morning task that regenerates the inventory report. Observe the permission prompts and the report-only pattern before granting any write access.

---

### Chapter recap

You can now match the feature to the job: uploads and tiered PDF processing for documents (§5.9), vision and OCR for anything you can screenshot (§5.10), code execution for real computation and file output (§5.11), web search for facts and Research for investigations (§5.12), personalization features that shape every interaction (§5.13), and Routines/Cowork for delegating recurring and multi-step work (§5.14). In the next chapter we turn to administration: plan entitlements, security controls, and governance for these same capabilities.


---
