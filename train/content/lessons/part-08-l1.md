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
