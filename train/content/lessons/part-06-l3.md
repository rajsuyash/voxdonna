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

:::exercise Try it: your first agent
1. In the desktop app, open the Cowork tab and grant it access to a *test* folder containing a few files you don't mind reorganizing.
2. Task: "Inventory this folder. Produce a Markdown report of file types, sizes, and duplicates, and propose — but do not execute — a reorganization plan."
3. Review the plan, then approve execution of one step only.
4. On the Scheduled page, create a weekday-morning task that regenerates the inventory report. Observe the permission prompts and the report-only pattern before granting any write access.
:::

---

### Chapter recap

You can now match the feature to the job: uploads and tiered PDF processing for documents (§5.9), vision and OCR for anything you can screenshot (§5.10), code execution for real computation and file output (§5.11), web search for facts and Research for investigations (§5.12), personalization features that shape every interaction (§5.13), and Routines/Cowork for delegating recurring and multi-step work (§5.14). In the next chapter we turn to administration: plan entitlements, security controls, and governance for these same capabilities.


---
