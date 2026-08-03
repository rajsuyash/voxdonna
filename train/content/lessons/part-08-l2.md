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
