# Part 8: Hands-on Tutorials

This chapter walks you through eight complete, do-along tutorials that progress from your first well-structured chat to scheduled, automated briefings. Each tutorial states a goal, the plan or feature you need, numbered steps, the expected result, and a "go further" extension. Everything below is based on documented Claude behavior as of August 2026 — where a feature is in preview or limits are volatile, you will see a callout telling you to verify against current Anthropic documentation.

Before you start, make sure you can reach claude.ai in a browser or the desktop app (free download at claude.ai/download; macOS 11+, Windows 10+, ChromeOS) and that you know which plan you are on: Free, Pro, Max, Team, or Enterprise (Anthropic plan pages, Aug 2026).

---

### Tutorial 1 — Your first effective chat (prompt anatomy basics)

**Goal.** Learn the four parts of an effective prompt — task, context, format, constraints — and produce a usable business email.

**Prerequisites.** Any plan, including Free. The chat interface (GA, all plans) is the sidebar plus a composer with a model picker and a "Search and tools" menu (slider icon) (Anthropic Docs, Jul 2026).

**Steps.**

1. Open claude.ai and click **New chat** (or press Cmd/Ctrl+Shift+N). Leave the model picker at its default for now.
2. In the composer, write a prompt with four clearly labeled parts:

```text
Task: Write a 120-word email to a customer whose shipment is delayed.
Context: We are a furniture retailer; the customer's sofa ships 5 days late
because of a warehouse backlog. They ordered 3 weeks ago.
Format: Subject line, then the email body. No bullet points.
Constraints: Apologetic but not defensive. Offer a 10% discount code (SORRY10).
Do not mention internal systems.
```

3. Send the message (Cmd/Ctrl+Enter) and read the reply critically.
4. Iterate in the same conversation. Follow-ups carry context, so refine rather than restart: "Make the tone warmer and shorten the second paragraph."
5. Optional: change the response register using **Styles** (GA, all plans) — open the "Search and tools" menu and switch between the Normal, Concise, Formal, and Explanatory presets, or define a Custom Style from a writing sample (Anthropic Docs, Jul 2026). Re-send the prompt and compare.

**Expected result.** A ready-to-send email that follows all four constraints. Notice that naming the format and the constraints — not writing a longer prompt — is what removes the guesswork.

**Go further.** Pin your house email style as a Custom Style so every future chat starts on-brand, and try the same prompt with the "Explanatory" preset to see how Claude verbalizes its choices — a fast way to learn prompt technique.

---

### Tutorial 2 — Set up a Project with knowledge + custom instructions

**Goal.** Create a persistent workspace so Claude always answers in your team's context.

**Prerequisites.** Pro, Max, Team, or Enterprise — Projects are not available on the Free plan (Anthropic, Projects launch, Jun 2024; plan pages Aug 2026). Projects include a 200K-token context window (500K on Enterprise), and when project knowledge approaches the window limit, retrieval (RAG) mode automatically expands effective capacity up to ~10x (Anthropic Docs, Jul 2026).

**Steps.**

1. In the sidebar, click **Projects**, then **New project**. Name it (e.g., "Customer Support — APAC").
2. Add **project knowledge**: upload reference files such as your support policy DOCX, a product FAQ (TXT/MD), and a pricing CSV. Project files are capped at 30 MB each, with unlimited file count, but the total content must fit the context window (Claude Help Center, "Upload files to Claude," 2026). Note that non-PDF documents are processed as text extraction only — embedded images are not read.
3. Open the project's **custom instructions** field and write standing guidance:

```text
You are a support specialist for our APAC team. Always cite the policy document
by section number when you state a rule. If the answer is not in the project
knowledge, say so instead of guessing. Reply in under 150 words.
```

4. Start a chat inside the project and test it: "A customer wants a refund after 40 days — what does our policy say?" Confirm the answer cites your uploaded policy, not general knowledge.
5. (Team/Enterprise) Share the project: use the sharing controls to invite colleagues by email with **View** or **Edit** access; Private is the default. Chats you start inside a shared project remain private to you by default, and artifacts created in the project are visible only to project members (Anthropic Projects documentation, 2025–2026).

**Expected result.** Every chat in the project answers against your knowledge base and follows the custom instructions, with no repeated setup.

**Go further.** Deliberately overload the knowledge base (e.g., dozens of policy files) and watch Claude switch into retrieval mode when the window fills. Note a documented discrepancy: one user-reported issue suggests retrieval may activate at a low file count regardless of token size — if answers seem to miss files, re-test with fewer, larger documents (conflicting evidence; verify in product, Aug 2026).

---

### Tutorial 3 — Analyze a PDF report and produce a summary artifact

**Goal.** Turn a long PDF into a one-page executive summary you can share.

**Prerequisites.** Any plan. Claude analyzes both text and visual elements (charts, graphics) in PDFs of 100 pages or fewer; PDFs of 101–1000 pages are processed text-only, and PDFs over 1000 pages are rejected (Claude Help Center, 2026). Chat uploads are limited to 500 MB per file and 20 files per chat (raised from 30 MB in 2026 — older guides still cite 30 MB; verify current limits). Artifacts are GA on all plans.

**Steps.**

1. Start a new chat. Drag your PDF into the composer (or use the attach control). For this walkthrough, use a report of ≤100 pages that contains charts.
2. Give a structured instruction:

```text
Read this quarterly industry report. Produce: (1) the five findings with the
strongest evidence, (2) three risks the authors understate, (3) a chart-by-chart
note on anything surprising in the figures. Reference page numbers as shown in
the PDF viewer, not the printed page numbers.
```

3. Ask one probing follow-up to test comprehension, e.g., "Which finding depends on the smallest sample size?"
4. Request the deliverable as an artifact: "Create an artifact: a one-page executive summary of this report for our leadership team, with a short 'What we should do' section." The summary opens in the side panel as a formatted Markdown document you can iterate on in place.
5. Refine conversationally ("cut section two, add the retention figure to the headline") — the artifact updates without regenerating the whole chat.

**Expected result.** A polished one-page summary artifact, grounded in the PDF with correct page references, that you can copy or download.

**Go further.** Ask Claude to also produce a Mermaid-diagram artifact of the report's causal chain (Mermaid is a supported artifact type), or export the summary as a downloadable .docx or .pdf using the file-creation capability covered in the next tutorial.

---

### Tutorial 4 — Upload a CSV → analysis + chart + downloadable xlsx

**Goal.** Go from raw CSV data to an analyzed, charted Excel workbook.

**Prerequisites.** Any plan, including Free. Enable **code execution and file creation** (feature preview; available on all plans and enabled by default on web/desktop/mobile) — Claude runs Python in a sandboxed Linux container with pandas, matplotlib, and other scientific libraries pre-installed (Claude Help Center, "Create and edit files with Claude," Apr 2026). Files moved through the sandbox are capped at 30 MB each, uploads and downloads (note: this 30 MB figure conflicts with the 500 MB chat-upload limit on a different official page — treat 30 MB as the working cap for this workflow).

**Steps.**

1. Check Settings to confirm code execution and file creation is on. Note the network defaults: on Free/Pro/Max, sandbox network access is on by default but limited to approved domains (pypi, npm, github, crates.io, Ubuntu archives, api.anthropic.com); on Team/Enterprise it is off by default (Claude Help Center, 2026).
2. Start a chat and upload your CSV (e.g., 12 months of sales by region and product).
3. Prompt the analysis:

```text
Analyze this sales CSV. Compute month-over-month growth per region, flag the
three products with the highest variance, and test whether the Q4 spike is
consistent across regions. Show your working briefly.
```

4. Request a visualization: "Create a chart of monthly revenue by region as a PNG." Claude renders charts as image files through the sandbox.
5. Request the deliverable: "Create an Excel workbook with three tabs — cleaned data, regional summary with working formulas, and the variance flags." Excel files created this way contain working formulas, not pasted values (Claude Help Center, 2026).
6. Click the download link in the reply. You can also save the file to Google Drive from the same flow.

**Expected result.** A downloaded .xlsx with multiple tabs and live formulas, plus a chart image — reproducible by re-running the conversation.

**Go further.** Upload an XLSX directly next time (XLSX upload requires code execution enabled), and ask Claude to amend an existing workbook while preserving formula dependencies. If you live in Excel, look at the Claude for Excel add-in (Pro/Max/Team/Enterprise; Microsoft AppSource) for cell-level citations inside your spreadsheet.

---

### Tutorial 5 — Build an interactive React dashboard artifact and share it

**Goal.** Build an interactive dashboard as a React artifact and publish it to a link.

**Prerequisites.** Any plan. React artifacts render in the side panel with pre-installed libraries including Recharts, D3, Tailwind core classes, Lucide icons, lodash, mathjs, Plotly, and Three.js; external scripts load via cdnjs (Anthropic artifact specifications, 2026).

**Steps.**

1. Start a chat and paste or upload the data from Tutorial 4 (small datasets can be pasted as CSV text).
2. Prompt the build:

```text
Build an interactive React dashboard artifact for this sales data.
Requirements: a Recharts line chart of revenue by month, a region filter,
a KPI strip (total revenue, best region, worst month), and a bar chart of
product variance. Default export; Tailwind for layout; Lucide icons.
```

3. The dashboard renders in the side panel. Test the filter and hover states yourself.
4. Iterate: "Add a toggle between absolute revenue and % growth" — React artifacts update in place as you refine.
5. **Publish:** use the artifact's publish control to create a public link, then send it to a colleague. Recipients can use **Remix this Artifact** to start their own chat from your published artifact and adapt it.
6. ⚠ **Privacy caution (Aug 2026):** in late July 2026, published artifacts and shared chats were briefly indexed by Google due to a missing noindex directive; Anthropic remediated and states that share links are not guessable unless you share them (TechCrunch, Jul 2026). Publish only non-sensitive data.

**Expected result.** A working, filtered dashboard at a shareable URL, with no code written by you.

**Go further.** On paid plans, persistent artifact storage (up to 20 MB) keeps richer artifacts alive, and Live Artifacts (paid plans; Cowork/Desktop, Apr 2026) refresh their data when opened — move this dashboard to a Live Artifact for a weekly metrics view.

---

### Tutorial 6 — Run a Research report on a market question

**Goal.** Get a cited, multi-source research report you can defend in a meeting.

**Prerequisites.** Research (GA-evolving) requires Pro, Max, Team, or Enterprise (Anthropic/SiliconANGLE, 2025–2026). A Research run takes roughly 5–45 minutes depending on depth.

**Steps.**

1. Start a new chat and click the **Research** button in the composer.
2. Frame a question that is specific, bounded, and decision-relevant:

```text
Research: What is the current size and 3-year growth outlook of the European
market for warehouse robotics for mid-size e-commerce firms? I need: market
size estimates (with who published each), the top 5 vendors and their
positioning, regulatory factors in DE/FR/NL, and risks to adoption.
```

3. Review the plan Claude proposes — Research breaks the question into sub-questions before investigating. Adjust scope if needed, then let it run.
4. While it runs, keep working elsewhere; you'll be notified when the report is ready.
5. **Verify the sources.** Open the finished report and click through its citations. Spot-check the three load-bearing claims: does the cited page actually say what the report claims? This verification habit is the whole point of citation-first reports.
6. Follow up in the same chat: "Turn the vendor section into a comparison table" or "Summarize this in six slides' worth of bullets" (you can then make a real .pptx via file creation — PPTX is an output type, not an upload type).

**Expected result.** A long-form report with inline citations across web sources (and your connected apps, if you've linked any — see Tutorial 7), plus a verified shortlist of claims you trust.

**Go further.** Combine Research with a Project: run the research inside your market-analysis project so the report lands alongside your knowledge files, and reuse it as project knowledge in later chats.

---

### Tutorial 7 — Connect Google Drive and run cross-document Q&A

**Goal.** Connect Google Drive via a connector and ask questions across your documents.

**Prerequisites.** Connectors are built on the Model Context Protocol (MCP) and are managed at **Settings → Connectors** (or the + menu in the composer → Connectors). The Google Workspace connectors (Drive, Gmail, Calendar) are first-party and broadly available, including Free per multiple 2026 sources; other directory connectors are paid-plan features — gating for Free users is inconsistent across sources, so verify per connector in product (Anthropic Connectors Directory, 2025–2026).

**Steps.**

1. Go to **Settings → Connectors**, find **Google Drive** (you can also browse the full catalog in the Connectors Directory), and toggle it on.
2. Complete the Google OAuth consent. Key facts: Claude acts as *you* — it inherits your Google permissions and never gets broader access; tokens are stored encrypted; Anthropic does not persistently store connector data; you can disconnect anytime (Anthropic connector documentation, 2026). For work accounts, your Workspace admin must mark Claude a trusted app (Security → API controls).
3. Start a chat and confirm the connection: "List the five most recent documents in my Drive." The Drive connector can search and read Docs, Sheets, Slides, PDFs, and Office files.
4. Run the cross-document question:

```text
Search my Drive for the vendor evaluation docs from Q1 and Q2. Across both
documents: which evaluation criteria changed, which vendors were dropped,
and where do the two docs disagree on pricing? Quote each document when you
attribute a claim.
```

5. Note the limits: images embedded inside Drive documents are invisible (text extraction only), and Gmail via the connector is draft-only — Claude can create drafts but cannot send email on your behalf (Anthropic, 2026).
6. (Team/Enterprise admins) Review connector policy: org Owners can set per-connector **Always allow / Needs approval / Blocked** controls, and the effective permission is the intersection of the user's source-system permissions, the OAuth scopes, and your org policy.

**Expected result.** An answer that synthesizes two or more Drive documents with per-document attribution, delivered without you downloading or uploading anything.

**Go further.** Add a second connector (e.g., Slack search/retrieval or Notion) and run a genuinely cross-system question: "Compare what the Drive evaluation doc says about Vendor X with what the team said in Slack last month."

---

### Tutorial 8 — Set up a Routine (scheduled task) for a weekly briefing

**Goal.** Automate a recurring Monday-morning briefing.

**Prerequisites and important status notes.** There are two scheduling surfaces, and both carry caveats:

- **Cowork Scheduled Tasks (GA):** hourly, daily, weekdays, weekly, or manual schedules, configured via `/schedule` in Cowork or the Scheduled page in the sidebar. ⚠ The computer must be **awake with the desktop app open** at run time; missed runs re-fire when you reopen the app. Cowork requires Pro, Max, Team Premium, or Enterprise, and specific hardware (macOS Apple Silicon or Windows Pro/Enterprise/Education with Hyper-V).
- **Claude Code Routines (Research Preview, Apr 2026):** run in Anthropic's cloud with schedule, API webhook, or GitHub-event triggers. Daily caps: **Pro 5, Max 15, Team/Enterprise 25 routines per day**. ⚠ Research Preview means limits and behavior can change, and execution bugs have been reported — verify current caps in Anthropic documentation as of your reading (tessl.io/howdoiuseai, Apr 2026; Anthropic release notes).

The steps below use Cowork Scheduled Tasks, the no-code path.

**Steps.**

1. Open the Claude desktop app and go to the **Cowork** tab (requires a supported plan and OS; Free accounts get Chat only in the desktop app).
2. Type `/schedule` (or open the **Scheduled** page in the sidebar) and create a new scheduled task.
3. Set the cadence to **weekly**, Monday 08:00.
4. Write the task prompt:

```text
Every Monday: pull the key threads from my connected Slack channels from the
past 7 days, check my Google Calendar for the week's external meetings, and
produce a briefing artifact: (1) decisions made last week, (2) meetings needing
prep, (3) top 3 open questions. Keep it under 400 words.
```

5. Connect the required connectors first (Tutorial 7) — Cowork works with connectors such as Slack and Google Workspace. Known gap: **custom MCP connectors cannot currently be attached to scheduled routines** (documented issue, May 2026), so stick to first-party connectors here.
6. Save the routine. Remember the runtime requirement: leave your computer awake with the desktop app open at the scheduled time, or the run will re-fire the next time you open the app.
7. After the first run, review the briefing and refine the task prompt — treat the first two runs as calibration.

**Expected result.** A recurring Monday briefing artifact generated automatically, bounded by your plan's scheduling model and caps.

**Go further.** If you are on Team or Enterprise and comfortable with Claude Code, rebuild the same briefing as a cloud-based Routine (at claude.ai/code/routines) so it runs without your laptop — you get up to 25 routines per day, within the Research Preview's documented limits.

---

### Where to go next

You have now used the full claude.ai surface: structured prompting, Projects, file analysis, code execution, artifacts, Research, connectors, and scheduling. The natural next step is Chapter 7's administration material — connector policies, audit logs, and spend controls — or, for builders, the Claude Code and API chapters, where the same concepts (projects, tools, retrieval, scheduling) reappear as programmable primitives.


---
