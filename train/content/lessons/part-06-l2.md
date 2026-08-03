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

:::exercise Try it: from CSV to dashboard
1. Upload any CSV export (sales, tickets, expenses — at least a few hundred rows).
2. Prompt: "Profile this dataset: row count, column types, missing values, and three things worth investigating. Run the analysis in code and show me the key numbers."
3. Follow up: "Build an interactive React dashboard artifact with a date-range filter, a trend line of the top metric, and a breakdown table. Use Recharts."
4. Finally: "Create an Excel file summarizing the findings, with a working formula computing the month-over-month change." Download and verify the formula in Excel.
:::

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
