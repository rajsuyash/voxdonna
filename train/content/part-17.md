# Part 17: Common Pitfalls — The Top 100 Claude Mistakes

Most Claude failures are not model failures — they are setup, prompting, or expectation failures. Anthropic's own documentation names many of them explicitly, and the rest trace to documented capability limits: file-type boundaries, context-window behavior, connector permission models, sandboxing rules, and API error semantics. This chapter catalogs the 100 mistakes enterprise users, admins, and developers make most often, organized into ten categories. Each entry states the mistake and gives a one-sentence fix. Where a behavior is volatile — limits, pricing, preview features — it is flagged: **as of August 2026 — verify against current Anthropic documentation.**

---

### Category 1: Prompting (Mistakes 1–10)

**Mistake 1: Vague, under-specified prompts** — Anthropic's golden rule is to show your prompt to a colleague with minimal context; if they would be confused, Claude will be too (Anthropic Docs — Prompting best practices, 2026). Fix: State the task, audience, output format, and constraints explicitly before sending.

**Mistake 2: Telling Claude what NOT to do** — Negative instructions ("Do not use markdown") are a documented failure mode; Claude responds better to positive direction (Anthropic Docs — "Control the format of responses"). Fix: Reframe as what TO do, e.g., "Your response should be composed of smoothly flowing prose paragraphs."

**Mistake 3: Skipping few-shot examples** — Anthropic calls examples "one of the most reliable ways to steer Claude's output format, tone, and structure" and recommends 3–5 relevant, diverse examples in `<example>` tags (Anthropic Docs, 2026). Fix: Add 3–5 canonical input/output pairs wrapped in `<examples>`.

**Mistake 4: Stuffing edge cases into the prompt** — Anthropic's context-engineering guidance explicitly warns against a "laundry list" of edge-case examples; examples should be diverse and canonical, not exhaustive (Anthropic Engineering, Sept 2025). Fix: Curate a small, representative example set and handle true edge cases in code or evals.

**Mistake 5: Contradictory instructions left unresolved** — When a prompt contains conflicting rules, Claude will try to follow both, producing inconsistent output (Anthropic Docs — common failure modes). Fix: Audit long system prompts for contradictions and rank rules by precedence.

**Mistake 6: Brittle hardcoded if-else logic in system prompts** — Anthropic warns against both extremes: rigid if-else chains and vague high-level guidance; system prompts should sit at the "right altitude" (Anthropic Engineering — Effective context engineering). Fix: Replace brittle branches with heuristics and clearly organized sections (`<instructions>`, `## Output description`).

**Mistake 7: Aggressive "CRITICAL: You MUST…" tool-trigger language** — Prompts written to force tool use or stop "laziness" on older models cause overtriggering and overthinking on Claude 4.6+ models (Anthropic Docs, 2026). Fix: Remove anti-undertrigger language when migrating to current models; describe the desired outcome instead.

**Mistake 8: Writing your own step-by-step reasoning plan** — On current models, "prefer general instructions over prescriptive steps"; a prompt like "think thoroughly" often beats a hand-written reasoning chain (Anthropic Docs — Thinking and reasoning). Fix: Give the goal and let adaptive thinking handle the reasoning; reserve manual CoT (`<thinking>`/`<answer>` tags) for when thinking is off.

**Mistake 9: Mixing instructions, context, and data without delimiters** — Undifferentiated prompt blobs cause misinterpretation when prompts mix instructions, context, examples, and variable inputs (Anthropic Docs — Use XML tags). Fix: Wrap each content type in its own tag (`<instructions>`, `<context>`, `<input>`) with consistent, descriptive names.

**Mistake 10: Prompt engineering without success criteria or evals** — Anthropic's own guide assumes you already have clear success criteria, empirical tests, and a first-draft prompt; some failures are better fixed by changing the model or cost/latency tradeoff (Anthropic Docs — Prompt engineering overview). Fix: Define measurable success criteria and a small eval set before iterating on wording.

#### Try it
Take your vaguest production prompt and run the "colleague test": paste it to a teammate with no other context. Rewrite it with an explicit role, numbered steps, one XML-tagged input section, and three `<example>` pairs — then compare outputs side by side.

---

### Category 2: Context & Long Documents (Mistakes 11–20)

**Mistake 11: Putting the question before the document** — For 20k+ token inputs, queries placed at the END improve response quality by up to 30% in Anthropic's tests (Anthropic Docs — Long context prompting). Fix: Put longform data at the top of the prompt; put the question last.

**Mistake 12: Assuming the full context window is fully usable** — "Context rot" is documented: as tokens increase, recall degrades; treat context as a finite attention budget (Anthropic Engineering, Sept 2025). Fix: Curate the smallest set of high-signal tokens; do not fill a 1M window just because it exists.

**Mistake 13: Assuming every plan has a 1M-token window** — 1M tokens is standard on 5-series/4.6+ models, but Haiku 4.5 and consumer plans are 200K, and Claude Code defaults to 200K unless you opt in (Anthropic Docs, Jul 2026). Fix: Check the model and surface before loading a large corpus.

**Mistake 14: Not grounding answers in quotes on long documents** — Anthropic's documented anti-hallucination technique is to have Claude first extract relevant quotes (e.g., in `<scratchpad>` tags) and then answer (Anthropic prompt tutorial, Ch. 8). Fix: Ask Claude to quote the relevant passages before performing the task.

**Mistake 15: Using printed page numbers instead of viewer page numbers** — Anthropic's PDF guidance says to reference page numbers as shown in the PDF viewer, not the printed folios, which often differ (support.claude.com). Fix: Reference viewer page numbers when asking about specific pages.

**Mistake 16: Letting one conversation run until quality collapses** — Anthropic's Claude Code guidance: if you've corrected Claude more than twice, run `/clear` and start fresh with a more specific prompt (Claude Code best practices). Fix: Clear context between unrelated tasks and after repeated corrections.

**Mistake 17: Ignoring compaction and note-taking strategies on long tasks** — Anthropic documents three long-horizon techniques — compaction, structured note-taking (NOTES.md / memory tool), and sub-agent architectures — for work that exceeds one window (Anthropic Engineering, Sept 2025). Fix: Pick a strategy up front for multi-session work instead of hoping the window holds.

**Mistake 18: Pre-loading everything instead of just-in-time retrieval** — Anthropic recommends lightweight identifiers (file paths, queries, links) and progressive disclosure over front-loading all context (Anthropic Engineering). Fix: Give Claude pointers and let it retrieve what it needs.

**Mistake 19: RAG-ing a knowledge base that fits in context** — Anthropic Engineering's own guidance: if your knowledge base is under ~200K tokens (~500 pages), include it whole with prompt caching instead of RAG (anthropic.com/engineering/contextual-retrieval). Fix: Prefer full-context + prompt caching for small corpora.

**Mistake 20: Ignoring ordering and formatting details** — Anthropic's tutorial notes Claude is more likely to pick the second of two options (ordering bias) and responds measurably worse to sloppy prompts (prompt tutorial; Simon Willison's notes). Fix: Audit option order and proofread prompts — typos degrade results.

#### Try it
Take a 100-page PDF Q&A task. First ask your question the naive way (question first). Then re-run with the document at the top, question last, plus "Quote the relevant passages in `<scratchpad>` before answering." Compare precision.

---

### Category 3: Files & Uploads (Mistakes 21–30)

**Mistake 21: Expecting visual analysis on a 150-page PDF** — Claude analyzes both text and visual elements (charts, images) only in PDFs of 100 pages or fewer; pages 101–1000 are processed text-only (support.claude.com — Upload files to Claude). Fix: Split large PDFs into ≤100-page chunks when charts and figures matter.

**Mistake 22: Uploading a PDF over 1000 pages** — PDFs over 1000 pages are rejected outright ("Uploaded file is too large") (support.claude.com). Fix: Split the document or upload sections separately.

**Mistake 23: Uploading XLSX without enabling code execution** — XLSX uploads require the "code execution and file creation" feature to be enabled in your account (support.claude.com). Fix: Enable code execution and file creation before uploading spreadsheets.

**Mistake 24: Trying to upload PPTX, ZIP, audio, or video** — The official supported-upload list does not include PowerPoint, ZIP, MP3/WAV, or MP4; PPTX is supported only as an output Claude creates (support.claude.com, Apr 2026). Fix: Convert PPTX to PDF, unzip archives locally, and transcribe audio/video externally before uploading text.

**Mistake 25: Believing the old 30MB chat upload limit** — Chat uploads were raised to **500 MB per file** (up to 20 files per chat) in 2026; older guides still cite 30MB — as of August 2026, verify current limits (support.claude.com). Fix: Re-check the upload article; note the code-execution sandbox itself still caps at 30MB per file (the two official pages conflict — flagged).

**Mistake 26: Expecting embedded images in DOCX to be read** — Non-PDF documents get text extraction only; embedded images are not read (support.claude.com). Fix: Extract images and upload them separately as JPEG/PNG, or convert to PDF (≤100 pages).

**Mistake 27: Uploading low-quality or tiny images** — Claude's documented vision limitations include errors on low-quality, rotated, or very small (<200px) images, and lossy JPEG compression hurts text legibility (platform.claude.com — Vision). Fix: Use images ≥1000×1000 px, crop/straighten, and avoid heavy re-compression.

**Mistake 28: Putting images after the text** — "Claude works best when images come before text" (Anthropic Docs — Vision). Fix: Place images first, then the prompt; label multiple images ("Image 1:", "Image 2:").

**Mistake 29: Asking Claude to identify people, judge AI-generated images, or do diagnostic scans** — Documented limitations: no person identification, cannot judge whether an image is AI-generated, approximate object counting, and not for CT/MRI-style diagnosis (platform.claude.com — Vision). Fix: Design workflows around what vision supports; route identity/medical tasks elsewhere.

**Mistake 30: Asking Claude to generate or edit raster images** — Claude does not generate or edit raster images (no text-to-image or inpainting); it produces SVG, Mermaid, charts, and code-based visuals instead (Anthropic Docs FAQ, 2026). Fix: Ask for an SVG/diagram artifact, or connect an external generator via MCP.

#### Try it
Upload a 120-page report with charts. Ask about a figure on page 105 and observe the text-only answer. Re-upload just pages 100–110 as a separate PDF and ask again — note the visual analysis difference.

---

### Category 4: Projects & Knowledge Management (Mistakes 31–40)

**Mistake 31: Expecting Projects on the Free plan** — Projects are a Pro/Max/Team/Enterprise feature; Free accounts do not get them (Anthropic — Projects, 2024-06-25; plan tables, 2026). Fix: Upgrade, or use chat-level uploads and memory instead.

**Mistake 32: Exceeding the 30MB project-file cap** — Project knowledge files are capped at 30MB each (vs 500MB chat uploads), with unlimited file count subject to the context window (support.claude.com). Fix: Split oversized files before adding them to project knowledge.

**Mistake 33: Assuming RAG activates exactly at the context limit** — Officially, project RAG (project_knowledge_search) activates as content approaches the window limit, expanding capacity ~10x; but a reported bug (claude-code issue #25759, Feb 2026) shows RAG activating at ~13 files regardless of size — flagged discrepancy. Fix: Verify retrieval quality empirically for your project size; don't assume the documented trigger.

**Mistake 34: Putting images inside project documents expecting vision** — Project files get text extraction only (except multimodal PDFs), so images in DOCX knowledge files are invisible (support.claude.com). Fix: Use PDFs (≤100 pages) for knowledge that depends on figures.

**Mistake 35: Treating project knowledge as a database, not context** — Total project content must fit the context window (or RAG's expanded ~10x capacity); it is retrieval into a finite window, not queryable storage (support.claude.com). Fix: Curate knowledge files; remove stale ones.

**Mistake 36: Assuming shared-project chats are visible to teammates** — Chats inside shared projects are private by default; sharing is explicit (permission levels Private/View/Edit) (its.northeastern.edu, 2025). Fix: Deliberately share chats into the project activity feed when collaboration is intended.

**Mistake 37: Forgetting artifacts in projects aren't workspace-visible** — Artifacts created inside a project are shared only with project members, not the whole Team workspace (dim02 research, 2026). Fix: Publish or export artifacts that need broader distribution.

**Mistake 38: Not setting project custom instructions** — Projects support custom instructions; skipping them wastes the main benefit over plain chats (Anthropic — Projects). Fix: Add role, style, and standing constraints to each project's instructions.

**Mistake 39: Assuming memory sees everything equally** — Claude's cross-chat search respects project boundaries: chats outside projects vs within are treated separately (university IT documentation, 2025–2026). Fix: Keep sensitive work inside projects; verify what memory can reference at Settings → Capabilities → Memory.

**Mistake 40: Expecting memory to store transcripts** — Memory stores synthesized summaries (role, preferences, formatting), not full chat transcripts (Anthropic memory rollout, Mar 2026). Fix: Put durable facts into project knowledge or say "add to memory…" explicitly for key items.

---

### Category 5: Artifacts & Sharing (Mistakes 41–50)

**Mistake 41: Publishing an artifact assuming only your recipient can see it** — In July 2026, published artifacts and shared chats were indexed by Google due to a missing noindex directive (TechCrunch, 2026-07-27; remediated). Anthropic's position: share links "are not guessable or discoverable unless people choose to share them" — but the incident proves "unguessable" is not "private." Fix: Treat every publish/share link as potentially public; never include confidential data.

**Mistake 42: Expecting attached files to travel with a shared chat** — Shared chats (claude.ai/share/…) are snapshots and attached files are excluded (Anthropic support docs, 2026). Fix: Re-attach files in the receiving conversation or export them separately.

**Mistake 43: Not revoking stale share links** — Share links persist until revoked; management lives at Settings → Privacy → Shared Chats (Anthropic support docs). Fix: Periodically audit and revoke old links — a direct lesson of the July 2026 indexing incident.

**Mistake 44: Using unsupported React patterns in artifacts** — Artifact React components require a default export, Tailwind core classes only, and a fixed library set (lucide-react, recharts, d3, Plotly, Three.js…); arbitrary npm imports fail (official system prompt constraints, 2026). Fix: Design artifacts within the documented library set; external scripts only via cdnjs.

**Mistake 45: Expecting artifacts to persist unlimited data** — Persistent artifact storage is capped at 20MB on paid plans (dim10 research, 2026). Fix: Keep artifact state small; store large data in project files or externally.

**Mistake 46: Confusing "Publish" with "Remix"** — Publish creates a public link; "Remix this Artifact" starts a NEW chat from someone else's published artifact — edits don't flow back (Anthropic artifacts documentation). Fix: Use remix for reuse, publish for distribution; don't expect two-way sync.

**Mistake 47: Expecting Live Artifacts everywhere** — Live Artifacts (refresh-on-open) launched April 2026 for paid plans in Cowork/Desktop contexts (dim10 research, 2026 — Medium-High confidence; verify availability). Fix: Confirm your plan/surface supports Live Artifacts before designing dashboards around them.

**Mistake 48: Sharing a chat that contains files uploaded for analysis** — Even though files are excluded from the share snapshot, quoted file content in the transcript is shared (behavior follows from §7 snapshot semantics). Fix: Review the transcript for pasted confidential excerpts before sharing.

**Mistake 49: Assuming artifact file creation works without the feature enabled** — Downloadable .docx/.pptx/.xlsx/.pdf output requires the "create files"/code-execution feature (a feature preview), enabled per account (support.claude.com, Apr 2026). Fix: Enable code execution and file creation first; note Team/Enterprise network access is off by default in the sandbox.

**Mistake 50: Treating shared links as access-controlled** — Share links carry no per-viewer authentication; anyone with the URL can view (implied by the July 2026 incident and Anthropic's "not guessable" statement). Fix: For controlled distribution, share within projects/Team feeds with View/Edit permissions instead of public links.

#### Try it
Open Settings → Privacy → Shared Chats right now. Count your live links, revoke any older than 90 days, and write a one-line team policy: "No customer data in published artifacts or shared chats."

---

### Category 6: Models & Settings (Mistakes 51–60)

**Mistake 51: Repeating outdated model folklore** — Older claims (e.g., "200K context everywhere," "Opus is always best," stale benchmark percentages) lag the 2026 lineup: Fable 5, Opus 5 (GA 2026-07-24), Sonnet 5, Haiku 4.5, invite-only Mythos 5 (cross-verified model research, Aug 2026). Fix: Check the current model page before advising others — as of August 2026, verify against Anthropic's pricing/models docs.

**Mistake 52: Sending `budget_tokens` to Claude 4.7+ models** — Manual extended thinking with `budget_tokens` is deprecated and returns a 400 error on Claude 4.7+; adaptive thinking (`thinking: {type: "adaptive"}` + effort levels) replaced it (Anthropic Docs, 2026). Fix: Migrate to adaptive thinking with `effort` (low→max) instead of a fixed thinking budget.

**Mistake 53: Writing manual chain-of-thought prompts on adaptive-thinking models** — On current models, prescriptive "think step by step" scaffolding is a fallback for when thinking is OFF; Opus 5 thinks by default (Anthropic Docs — Thinking and reasoning). Fix: Remove manual CoT boilerplate; use effort settings and, if needed, "think thoroughly."

**Mistake 54: Carrying over verification boilerplate to Opus 5** — Anthropic documents that explicit verification instructions cause OVER-verification on Opus 5; remove them when migrating (Anthropic Docs, 2026). Fix: Strip "verify your answer against X" instructions on Opus 5 unless you observe real failures.

**Mistake 55: Using temperature folklore on 4.7+ models** — Older advice to crank temperature up/down for "creativity" predates adaptive-thinking 4.7+/5-series models, where behavior is steered primarily via prompts and the effort ladder (Anthropic Docs, 2026; flagged as evolving guidance). Fix: Steer with explicit instructions and effort level; treat temperature tweaks as a last resort and test empirically.

**Mistake 56: Using prefilled assistant responses on Claude 4.6+** — Prefill (putting words in Claude's mouth to force JSON) is no longer supported from Claude 4.6 onward — it returns a 400 error (Anthropic Docs — Migrating away from prefilled responses). Fix: Use Structured Outputs (GA) for forced JSON/YAML, or system instructions ("Respond directly without preamble").

**Mistake 57: Setting `max` effort everywhere** — Anthropic's own guidance: `max` can overthink; `xhigh` is recommended for coding/agentic work, minimum `high` for intelligence-sensitive tasks (Anthropic Docs — Prompting Claude Opus 4.7). Fix: Right-size effort; raise it only if you observe shallow reasoning at lower settings.

**Mistake 58: Using the word "think" on Opus 4.5 with thinking disabled** — Opus 4.5 (thinking off) is documented as sensitive to the word "think"; use "consider," "evaluate," or "reason through" instead (Anthropic Docs, 2026). Fix: Reword thinking-trigger language when targeting that model configuration.

**Mistake 59: Ignoring the Sonnet 5 pricing change** — Sonnet 5 intro pricing ($2/$10 per MTok) steps up to $3/$15 on 2026-09-01 — as of August 2026, verify current rates (Anthropic pricing, flagged). Fix: Re-cost workloads before September 2026 budgets lock.

**Mistake 60: Assuming long context costs extra** — The 1M-token window has been GA at standard pricing since March 2026 (no long-context surcharge) on supported models (Anthropic Docs). Fix: Don't artificially chunk workloads to avoid a surcharge that no longer exists — but still respect context rot (Mistake 12).

---

### Category 7: Connectors & Integrations (Mistakes 61–70)

**Mistake 61: Assuming Claude gains permissions you don't have** — Effective connector permission is the intersection of the user's source-system permissions, OAuth scopes granted, MCP tool design, and Claude-side admin controls; Claude never gets broader access than the connecting user (technovids/Sunpeak connector guides, 2026). Fix: Audit the intersection, not just the connector toggle — a read-only user stays read-only.

**Mistake 62: Expecting Gmail to send email** — The Google connector is draft-only: "Claude creates drafts in your Gmail account, but cannot send emails on your behalf," and Gmail attachments aren't readable (Anthropic documentation, 2026). Fix: Design workflows around draft creation + human send; pull attachments via Drive instead.

**Mistake 63: Treating the connector default posture as locked down** — The default enterprise posture is open: users can enable catalog connectors without approval unless admins restrict them (Harmonic Security, 2026-03-10). Fix: Set org-level connector policies (Always allow / Needs approval / Blocked) and deploy `managed-mcp.json` allowlists.

**Mistake 64: Connecting a localhost or VPN-only MCP server** — Remote connectors are reached from Anthropic's cloud, not your machine; servers behind VPNs, firewalls, private DNS, or IP allowlists will fail (Sunpeak, 2026-07-29). Fix: Expose a public HTTPS endpoint (tunnel for dev) or use desktop extensions/local MCP.

**Mistake 65: Granting broad OAuth scopes out of convenience** — MCP security guidance: minimum-necessary grants, prefer read-only, treat third-party tool descriptions as untrusted (MCP security best practices; OWASP MCP Top 10). Fix: Scope OAuth grants tightly at consent time and prefer read-only tool sets.

**Mistake 66: Trusting directory listing as a security guarantee** — Anthropic reviews submissions against the MCP Directory Policy, but a listing is not a guarantee of security, uptime, or tool quality; review is human and queue-based (Directory FAQ; MCP registry guidance). Fix: Vet third-party connectors yourself; pin versions and re-review on updates ("rug pull" risk is documented).

**Mistake 67: Expecting custom connectors to work in scheduled routines** — A documented gap: custom MCP connectors cannot be attached to scheduled routines (no UUID discovery path — claude-code issue #63233, May 2026). Fix: Use first-party connectors in routines, or run connector-dependent automations interactively until this ships.

**Mistake 68: Forwarding tokens across servers (token passthrough)** — Passing a token issued for one server to another is an explicitly forbidden anti-pattern in the MCP spec (MCP security best practices). Fix: Validate token audience per server; issue separate tokens per resource.

**Mistake 69: Assuming web search respects egress controls** — Web search is a built-in Anthropic-managed capability (not a connector), and in Cowork it bypasses network egress restrictions (Harmonic Security, 2026-03-10); MCP connections also bypass code-execution egress settings (support.claude.com). Fix: Treat web search and MCP as separate exfiltration paths in your threat model.

**Mistake 70: Assuming every connector writes as well as reads** — Write surfaces vary and shift: Notion and Google connectors were read/create-only in early 2026 with write support expanding mid-year (conflicting sources — flagged); Teams remains read-only in the M365 connector (2026-07-07 release notes). Fix: Verify the current tool list per connector before promising write workflows.

#### Try it
Pick your riskiest connector. Document its four-layer permission intersection (source permissions × OAuth scopes × tool design × org policy) and downgrade every grant that isn't read-only.

---

### Category 8: Claude Code (Mistakes 71–80)

**Mistake 71: Running `bypassPermissions` outside a container** — Anthropic documents `--dangerously-skip-permissions`/bypassPermissions as for "isolated environments like containers or VMs" only (Claude Code — Configure permissions). Fix: Use `acceptEdits` or `auto` mode interactively; reserve bypass for sandboxed CI.

**Mistake 72: Not understanding permission-mode semantics** — Six modes exist (default/Manual, acceptEdits, plan, auto, dontAsk, bypassPermissions) with deny → ask → allow rule precedence, and rules are enforced by Claude Code, not the model (Claude Code docs). Fix: Learn the modes (Shift+Tab cycles them) and encode rules in settings rather than re-answering prompts.

**Mistake 73: Over-specified CLAUDE.md files** — Anthropic lists "over-specified CLAUDE.md" as a failure pattern and targets under 200 lines: longer files consume context and reduce adherence (Claude Code — Memory/best practices). Fix: Keep CLAUDE.md concise; move path-specific rules into `.claude/rules/*.md` with `paths:` frontmatter.

**Mistake 74: Writing instructions in AGENTS.md expecting Claude Code to read them** — Claude Code reads CLAUDE.md, not AGENTS.md (Claude Code — Memory). Fix: Create a CLAUDE.md that imports your AGENTS.md via `@path/to/import` syntax.

**Mistake 75: Treating the Bash sandbox as a complete security boundary** — Documented limitations: no TLS inspection by default, Unix-socket escalation paths, "not a complete isolation boundary"; native Windows is unsupported (Claude Code — Sandboxing). Fix: Combine sandboxing with permission rules and managed enforcement (`failIfUnavailable`, `allowUnsandboxedCommands: false`).

**Mistake 76: The kitchen-sink session** — Anthropic's documented failure patterns include mega-sessions that mix unrelated tasks and "correcting over and over" (Claude Code — Best practices). Fix: `/clear` between tasks; after two failed corrections, restart with a sharper prompt.

**Mistake 77: No verification loop** — "Give Claude a way to verify its work… the single highest-leverage thing you can do" (Claude Code — Best practices). Fix: Provide tests, linters, or screenshot checks so Claude can confirm changes against the running app.

**Mistake 78: Surprise at cost and rate-limit windows** — Claude Code draws from a per-seat allowance on rolling 5-hour and weekly windows shared with chat and Cowork; API-billed usage averages ~$13/developer/active day (Claude Code — Manage costs). Fix: Monitor with `/usage`; route routine tasks to cheaper models via subagents; set `--max-budget-usd` in automation.

**Mistake 79: Assuming cloud sessions work with your org's IP allowlist** — Claude Code on the web shares account rate limits and org IP allowlists break cloud sessions; it is also unavailable on Bedrock/Vertex/Foundry (Claude Code on the web docs). Fix: Check infrastructure constraints before adopting `--cloud` workflows.

**Mistake 80: Assuming there's a repo index** — There is no separate indexing step; Claude Code explores agentically at query time (Glob/Grep/Read + Explore subagent), guided by CLAUDE.md (Claude Code docs). Fix: Invest in a good CLAUDE.md and clear code layout instead of waiting for an "indexing" to finish.

#### Try it
Audit one repo: is CLAUDE.md under 200 lines? Run `/permissions` and confirm no lingering `bypassPermissions` allowances; then add one PreToolUse hook that blocks `rm -rf` (documented example) and test it.

---

### Category 9: Enterprise Admin & Security (Mistakes 81–90)

**Mistake 81: Confusing audit logs with the Compliance API** — Audit logs (Enterprise-only, 180 days) are metadata-only: chat/project titles and content are NOT included, only UUIDs; full content requires the Compliance API (Admin API keys with `read:compliance_activities`) or Primary-Owner data exports (Anthropic audit-log docs, 2026). Fix: Use audit logs for who/when/what-event; Compliance API for content investigations.

**Mistake 82: Assuming Cowork sessions are audited** — A reported gap: Cowork sessions are not captured in audit logs/compliance data (claudeforoperators, May 2026 — Medium confidence; may have changed since Cowork GA). Fix: Verify current Cowork audit coverage with Anthropic before relying on logs for Cowork oversight.

**Mistake 83: Assuming ZDR covers everything** — Zero Data Retention covers the Messages API and Token Counting API but EXCLUDES Batch API, Files API, Skills API, code execution, programmatic tool calling, MCP connectors, and Console/Workbench; Covered Models (Fable 5, Mythos 5) require 30-day retention and are incompatible with ZDR-only workspaces (Anthropic ZDR docs, 2026). Fix: Map each workload against the ZDR scope list before claiming zero retention.

**Mistake 84: Routing PHI through non-eligible features** — Under a BAA, HIPAA covers the Messages API plus specified tools/APIs but NOT Console/Workbench, Free/Pro/Max/Team, Cowork, Batch/Files/Skills APIs, Code Execution, Computer Use, Web Fetch, or betas (privacy.claude.com — BAA for Commercial Customers, 2026). Fix: Restrict PHI workflows to HIPAA-eligible surfaces; note Claude Code CLI is covered only with ZDR enabled.

**Mistake 85: Enabling HIPAA on self-serve Enterprise** — The HIPAA-ready configuration is available on sales-assisted Enterprise (and legacy/AWS Marketplace SKUs); self-serve Enterprise cannot enable it in-app (Anthropic Enterprise FAQ, 2026). Fix: Engage Anthropic sales for a BAA-backed HIPAA configuration.

**Mistake 86: Quoting stale API retention defaults** — API inputs/outputs default to 7-day retention (reduced from 30 days on 2025-09-14), with 30-day retention available via DPA opt-in (Anthropic policy — flagged as repeatedly changed). Fix: Verify the current retention article; opt in via the DPA if your compliance posture needs 30 days.

**Mistake 87: Assuming consumer data policies apply to Enterprise** — On commercial products (Team/Enterprise/API) prompts and results are NOT used for training by default — contractual, with no opt-in/opt-out toggle, unlike consumer tiers post-Sept 2025 (Anthropic Enterprise page). Fix: State the commercial default correctly in internal privacy reviews; don't extrapolate consumer-policy news to Enterprise.

**Mistake 88: Expecting EU data residency on first-party surfaces** — EU residency is not offered on claude.ai or the direct API; EU paths exist only via AWS Bedrock EU profiles or Google Vertex AI EU regions (Anthropic residency docs, 2026). Fix: Route EU-residency requirements through Bedrock/Vertex under the cloud provider's DPA.

**Mistake 89: Underestimating shared-chat and published-artifact exposure** — The July 2026 indexing incident showed shared chats/artifacts becoming Google-indexed; share links have no per-viewer auth (TechCrunch, 2026-07-27). Fix: Set an org policy for public sharing, audit links regularly, and prefer project-scoped sharing with View/Edit permissions.

**Mistake 90: Skipping spend controls until the invoice arrives** — Enterprise offers org- and user-level spend limits with alerts (reported at 75%/90% thresholds — single secondary source, flagged) plus usage analytics; self-serve draws from a shared prepaid credit pool that stops org-wide at zero (Anthropic, Jul 2026). Fix: Configure spend limits and alerts at rollout, not after the first surprise bill.

---

### Category 10: API & Developers (Mistakes 91–100)

**Mistake 91: Treating 429 and 529 the same** — 429 `rate_limit_error` is your problem (requests too fast — respect `retry-after`); 529 `overloaded_error` is Anthropic-wide capacity (retry with capped exponential backoff + jitter) (Anthropic error docs, 2026). Fix: Branch your retry logic on error type and headers, not just "any failure → retry."

**Mistake 92: Status-code-only error handling on streams** — Streaming connections open with HTTP 200 and can deliver `overloaded_error` as an in-stream error event; status-code checks alone miss it (documented streaming behavior). Fix: Parse stream events for error types and handle mid-stream failures.

**Mistake 93: Caching misuse — mutating the prefix** — Prompt-cache invalidation follows a hierarchy (tools → system → messages); any byte change in a prefix invalidates everything after it (Anthropic — Prompt caching). Fix: Put stable content first, volatile content last, and place `cache_control` breakpoints deliberately (max 4 per request).

**Mistake 94: Assuming cache TTL and minimums are universal** — Default TTL is 5 minutes (1-hour option at 2× write cost), minimum cacheable prefix varies by model (e.g., 1,024 tokens Sonnet 4.5/4.6; 4,096 Haiku 4.5), and Claude Code cache lifetime is an hour on subscription vs five minutes on API keys (Anthropic docs, 2026). Fix: Check per-model minimums and choose TTL per workload; cache reads cost 0.1× input.

**Mistake 95: Sending `Authorization: Bearer` with an API key** — API keys authenticate via the `x-api-key` header (bearer is for short-lived OAuth/Workload Identity tokens), plus required `anthropic-version` (Anthropic authentication docs). Fix: Use `x-api-key` + `anthropic-version` headers; store the key as `ANTHROPIC_API_KEY`.

**Mistake 96: Returning `tool_result` for server-side tools** — Server tools (web search, code execution) use `srvtoolu_` IDs and execute on Anthropic infrastructure; never send `tool_result` for them (Anthropic API docs). Fix: Only return tool results for client-side tools (`toolu_` IDs) your application executes.

**Mistake 97: Ignoring new stop reasons** — `pause_turn` (long multi-search requests) and `model_context_window_exceeded` are documented stop reasons that naive completion checks miss (Anthropic API docs, 2026). Fix: Handle all stop reasons explicitly; continue on `pause_turn` instead of assuming the turn ended.

**Mistake 98: Expecting streaming or speed from the Batch API** — Message Batches are asynchronous (results within 24h, most <1h), 50% cheaper, retained 29 days, no streaming, and not available on Claude Platform on AWS (Anthropic — Batch API). Fix: Use Batch for offline bulk jobs; use the streaming Messages API for interactive latency.

**Mistake 99: Assuming Files API uploads are downloadable and covered by ZDR** — Uploaded files cannot be re-downloaded (only files Claude creates can be), files persist until explicitly deleted (an exception to auto-deletion), and the Files API is excluded from ZDR (Anthropic — Files API beta; ZDR scope). Fix: Keep source copies locally; delete files explicitly; exclude Files API flows from ZDR-scoped pipelines.

**Mistake 100: Building agent frameworks before exhausting simple patterns** — Anthropic's own guidance: "find the simplest solution possible… this might mean not building agentic systems at all"; agents cost ~4× and multi-agent ~15× the tokens of chat, and errors compound in sandboxes (Anthropic Engineering — Building effective agents; multi-agent research system). Fix: Start with prompt chaining, routing, or a single augmented LLM; graduate to orchestrator-workers or autonomous agents only when measured need exists.

#### Try it
Load-test your error handler: force a 429 (burst past your RPM), observe a mid-stream 529 simulation, and verify your code reads `retry-after`, applies jittered backoff for 529, and parses in-stream error events. Then check one cached workload's `usage` for cache-read hit rate.

---

### Closing note

Patterns across all 100: (1) most failures are documented behaviors, not model defects; (2) volatile facts — limits, pricing, preview features — change quarterly, so treat every number here as **as of August 2026 — verify against current Anthropic documentation**; (3) the strongest debugging habit is Anthropic's own: define success criteria, test empirically, and change one variable at a time.


---
