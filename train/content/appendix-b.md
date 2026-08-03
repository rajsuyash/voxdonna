# Appendix B: Certification-Style Quiz — 100 Questions

This chapter is your readiness check for the whole guide. It contains exactly 100 multiple-choice questions (four options each, one correct answer), organized into ten sections of ten that mirror Chapters 1–10. Difficulty is mixed deliberately: roughly 40 questions test recall, 40 test comprehension, and 20 put you in a scenario where you must apply what you know. Attempt a full section before checking the answer key at the end. A passing bar we suggest for enterprise certification candidates is 80/100, with no section below 6/10.

All questions are drawn from documented behaviors, capability limits, and feature statuses as of August 2026. Where a fact is volatile (pricing changes, limits), the question or answer key says so — always verify against current Anthropic documentation before quoting a number to a customer.

---

### Section 1 — Products & Plans

**Q1.** Which plan tier adds Claude Code, Claude Cowork, Research, and unlimited Projects on top of the Free tier?
A) Free
B) Pro
C) Team Standard
D) Enterprise

**Q2.** What are the two Max plan usage multipliers over Pro, and their headline monthly prices (as of August 2026)?
A) 2x at $50, 5x at $100
B) 5x at $100, 20x at $200
C) 10x at $150, 25x at $250
D) 5x at $80, 10x at $160

**Q3.** Which of the following is included on the Claude Free plan?
A) Claude Code access
B) File creation and code execution
C) Research (deep research agent)
D) Priority access at high traffic

**Q4.** How is usage metered on the Enterprise plan, per Anthropic's official enterprise page (as of August 2026)?
A) Flat unlimited usage per seat
B) Per-seat fee plus usage billed as you go at API rates
C) Token bundles purchased per user
D) A single annual invoice with no usage component

**Q5.** How can a Pro subscriber access Claude Fable 5, according to the official pricing table?
A) Fable 5 is not available to Pro at any price
B) Via usage credits
C) At 50% of weekly limits
D) Only through the API with a separate key

**Q6.** Claude subscription usage limits operate through which mechanisms?
A) A single monthly token quota
B) A rolling 5-hour session window plus weekly caps
C) Per-day message counts only
D) Unlimited usage with throttling after 8 hours

**Q7.** Which feature does the Free plan NOT include?
A) Web search
B) Memory
C) Connectors / remote MCP
D) Claude Code

**Q8.** Your CFO asks why the Team plan price in last quarter's training deck doesn't match this quarter's procurement quote. What is the correct response?
A) Team pricing has been fixed globally since 2024
B) Team seat pricing and minimum-seat figures conflict across sources through 2026; always verify current claude.com/pricing before quoting
C) The quote must be fraudulent
D) Team plans are free for nonprofits

**Q9.** A 12-person startup wants SSO/SAML with domain capture, SCIM provisioning, audit logs, and a Compliance API. Which plan fits?
A) Pro
B) Max 20x
C) Team Premium
D) Enterprise

**Q10.** Which of the following can be purchased directly through AWS Marketplace and draw down an existing AWS commit?
A) Claude Pro
B) Claude Max
C) Claude Enterprise
D) Claude Free

---

### Section 2 — Models & Thinking

**Q11.** What is the correct latency/capability ordering of the current self-serve lineup, fastest to slowest?
A) Fable 5 → Opus 5 → Sonnet 5 → Haiku 4.5
B) Haiku 4.5 → Sonnet 5 → Opus 5 → Fable 5
C) Sonnet 5 → Haiku 4.5 → Fable 5 → Opus 5
D) Opus 5 → Fable 5 → Sonnet 5 → Haiku 4.5

**Q12.** Which statement about Claude Mythos 5 is accurate (as of August 2026)?
A) It is generally available on all paid plans
B) It is offered only in limited availability to approved customers in Project Glasswing
C) It is an open-weights model
D) It was retired in June 2026

**Q13.** What is the context window of Claude Opus 5?
A) 200k tokens
B) 500k tokens
C) 1M tokens, as both the default and the maximum
D) 2M tokens with a surcharge

**Q14.** What is the maximum output length for Sonnet 5, and for Haiku 4.5?
A) 64k for both
B) 128k for Sonnet 5, 64k for Haiku 4.5
C) 128k for both
D) 32k for Sonnet 5, 16k for Haiku 4.5

**Q15.** What happens if you send `thinking: {"type":"enabled", "budget_tokens": 4000}` to a Claude 4.7-or-later model?
A) It thinks up to 4,000 tokens
B) The request is rejected with a 400 error
C) The parameter is silently ignored
D) It falls back to effort "low"

**Q16.** What replaces manual `budget_tokens` thinking on the 4.7+/5-series models?
A) Chain-of-thought prompting
B) Adaptive thinking steered by `output_config.effort`
C) Prefilled assistant turns
D) The `temperature` parameter

**Q17.** What is the correct effort ladder and API default on Opus 5 / Sonnet 5?
A) low, medium, high, xhigh, max — default high
B) minimal, standard, deep — default standard
C) 1 through 10 — default 5
D) off, on — default on

**Q18.** On Opus 5, thinking is on by default. When can you disable it?
A) Never
B) Only at effort high or below; disabling at xhigh or max returns a 400 error
C) At any effort level
D) Only in the Batch API

**Q19.** A developer migrating code from Opus 4.5 to Opus 5 keeps `temperature: 0.3` and `budget_tokens` in the request. What will happen?
A) Both work unchanged
B) Both produce 400 errors on 4.7+/5-series models; non-default temperature/top_p/top_k and manual budget_tokens are rejected
C) Only temperature errors
D) The request succeeds but is billed double

**Q20.** Why can a "cheaper per-token" comparison between a Claude 4.5 model and a 4.7+ model mislead a cost model?
A) 4.7+ models use a newer tokenizer that produces ~30% more tokens for the same text
B) 4.7+ models bill per character
C) Output tokens are free on 4.5
D) The Batch API is unavailable on 4.7+

---

### Section 3 — Interface, Projects & Artifacts

**Q21.** What are the three main surfaces of the Claude desktop app?
A) Chat, Mail, Calendar
B) Chat, Cowork, Code
C) Chat, Files, Settings
D) Web, Mobile, API

**Q22.** What is the knowledge capacity model of Projects?
A) Hard cap of 20 files
B) 200K context window (500K on Enterprise), with RAG mode auto-expanding effective capacity up to ~10x when knowledge exceeds the window
C) Unlimited files with full-text loading always
D) 1M tokens on every plan

**Q23.** Which sharing/permission levels exist for project collaboration?
A) Public, Unlisted, Secret
B) Private, View access, Edit access
C) Read, Write, Admin, Owner
D) Viewer, Commenter, Editor

**Q24.** Which of the following is NOT a rendered Artifact type?
A) React (.jsx)
B) Mermaid diagrams
C) SVG
D) MP4 video

**Q25.** What does "Remix this Artifact" do?
A) Deletes the original artifact
B) Starts a new chat from someone else's published artifact so you can iterate on it
C) Converts the artifact to PDF
D) Publishes your copy to the directory

**Q26.** When did persistent memory reach all Claude users including Free, and what does it store?
A) March 2026; synthesized summaries of role, preferences, formatting — not full transcripts
B) January 2025; full transcripts of every chat
C) It is still Enterprise-only
D) July 2026; only custom instructions

**Q27.** What are the four preset Styles?
A) Brief, Long, Casual, Technical
B) Normal, Concise, Formal, Explanatory
C) Friendly, Professional, Academic, Creative
D) Default, Writer, Coder, Analyst

**Q28.** A user asks Claude in Cowork to "run the sales report every weekday at 8am." Which requirement must be true for Cowork Scheduled Tasks to fire?
A) Nothing — they run in Anthropic's cloud
B) The computer must be awake with the desktop app open; missed runs re-fire on reopen
C) The user must keep claude.ai open in a browser tab
D) Scheduled tasks only work on Enterprise

**Q29.** Which statement about voice mode (Beta) is accurate as of the July 2026 expansion?
A) Full-duplex real-time conversation on all plans
B) Turn-based spoken conversation across iOS/Android/desktop/web; free tier limited to Haiku and a single connected tool
C) Voice mode trains on your audio by default
D) Voice mode is Enterprise-only

**Q30.** What is the documented duration range for a Research (deep research) run, and what does it produce?
A) 5–45 minutes; a comprehensive report with citations
B) 30–60 seconds; a bulleted summary
C) Up to 3 seconds; a single answer
D) 2–3 hours; a downloadable dataset

---

### Section 4 — Files, Vision & Data

**Q31.** Which file type requires "code execution and file creation" to be enabled before uploading to claude.ai?
A) PDF
B) CSV
C) XLSX
D) DOCX

**Q32.** What are the current chat-upload limits on claude.ai (as of 2026 — recently raised)?
A) 30 MB per file, 5 files per chat
B) 500 MB per file, up to 20 files per chat
C) 100 MB per file, 10 files per chat
D) 1 GB per file, unlimited count

**Q33.** How does Claude process a 450-page PDF uploaded to chat?
A) Full text + visual analysis of every page
B) Text only — PDFs from 101 to 1000 pages are processed text-only
C) It is rejected
D) Only the first 100 pages are read

**Q34.** Which set of image formats is supported for upload?
A) JPEG, PNG, GIF, WebP
B) JPEG, PNG, TIFF, BMP
C) PNG, HEIC, RAW, WebP
D) Any format under 5 MB

**Q35.** Which vision task is documented as a limitation of Claude?
A) Reading charts in a PDF
B) Identifying or naming a person in an image
C) Describing a UI screenshot
D) Transcribing legible printed text

**Q36.** What applies to images analyzed by Claude 4.7-and-later models?
A) They are capped at 1568 px like older models
B) A high-resolution vision tier (max long edge 2576 px, up to 4784 visual tokens) applies automatically
C) Vision requires a separate paid add-on
D) Only the first frame of GIFs is unsupported

**Q37.** A user uploads a .pptx file expecting Claude to read the slides. What happens?
A) Claude reads text and images from the slides
B) PPTX is not a supported upload type; Claude can create .pptx via code execution, but cannot ingest it as a native upload
C) Claude converts it to PDF automatically
D) Only Enterprise plans can upload PPTX

**Q38.** In the claude.ai code-execution sandbox, what is the default network posture by plan?
A) Network fully open on all plans
B) On by default with an approved-domain list for Free/Pro/Max; off by default for Team/Enterprise
C) Off for all plans with no override
D) Network only for Enterprise

**Q39.** Can Claude generate a photorealistic image from a text prompt?
A) Yes, on Max plans
B) No — Claude does not generate or edit raster images; it produces SVG, Mermaid, charts, and interactive visuals via Artifacts/code
C) Yes, via the Files API
D) Only in Claude Design

**Q40.** A legal team must review a 90-page scanned contract with dense tables. Which approach fits documented behavior?
A) Upload it — PDFs of 100 pages or fewer get both text and visual (image/chart) analysis
B) Split it into 10-page chunks because the limit is 30 pages
C) Convert it to audio first
D) It cannot be processed because it is scanned

---

### Section 5 — Connectors & Integrations

**Q41.** Technically, what is a Claude connector?
A) A browser extension
B) A (usually remote) MCP server exposing tools/resources/prompts that Claude discovers dynamically
C) A Zapier-only webhook
D) A local plugin compiled into the app

**Q42.** From where does Claude reach remote connector servers?
A) The user's local machine
B) Anthropic's cloud infrastructure — endpoints behind VPNs, firewalls, or IP allowlists may fail
C) The user's browser only
D) A regional edge device

**Q43.** When did Anthropic launch the Connectors Directory, and which builders were among the first additions?
A) July 14, 2025 — including Notion, Canva, Figma, Socket, and Prisma
B) May 1, 2025 — including Jira and Zapier
C) January 26, 2026 — including Slack
D) April 2026 — including Spotify

**Q44.** What did the original "Integrations" launch (May 1, 2025) include?
A) 10 launch partners such as Atlassian (Jira/Confluence), Zapier, Intercom, Asana, Square, Sentry, PayPal, Linear, Plaid, and Cloudflare
B) Only Google Workspace
C) 800+ connectors
D) Local desktop extensions only

**Q45.** What can Claude do with a connected Gmail account?
A) Send email on your behalf
B) Search, read, and summarize threads and create drafts — but not send
C) Read attachments natively
D) Delete messages

**Q46.** A user's effective permission through a connector equals:
A) Whatever the MCP server allows
B) The intersection of the user's source-system permissions, granted OAuth scopes, the MCP tool design, and Claude-side admin/user controls
C) The org admin's permissions
D) Unrestricted access to the connected system

**Q47.** What are "MCP Apps" (launched January 26, 2026)?
A) Anthropic's mobile apps
B) Interactive tools — an open MCP extension rendering live UI inside Claude, with launch apps including Amplitude, Asana, Box, Canva, Figma, and Slack
C) A deprecated SSE transport
D) A billing tier

**Q48.** What is required before Claude can use the Microsoft 365 connector in a Team/Enterprise org?
A) Only the end user signs in
B) The org Owner enables the connector, an Entra Global Administrator grants tenant-wide admin consent, and users connect individually
C) A Microsoft Copilot license
D) Nothing — it is on by default

**Q49.** How many custom remote MCP connectors can a Free-plan user add (per 2026 documentation)?
A) Zero
B) One
C) Five
D) Unlimited

**Q50.** Is web search implemented as an MCP connector?
A) Yes, listed in the directory
B) No — web search is a built-in Anthropic-managed capability, not an MCP connector
C) Yes, but only on Enterprise
D) Only via the Brave connector

---

### Section 6 — MCP & API

**Q51.** Which three participants does MCP define?
A) Producer, consumer, broker
B) Host, client, server
C) Frontend, backend, database
D) User, model, tool

**Q52.** What are the two current standard MCP transports?
A) WebSocket and gRPC
B) stdio and Streamable HTTP
C) HTTP+SSE and WebSocket
D) TCP and UDP

**Q53.** Which headers does every Claude API request require?
A) `Authorization: Bearer` and `anthropic-version`
B) `x-api-key`, `anthropic-version`, and `Content-Type: application/json`
C) `x-api-key` only
D) `api-key` and `x-request-id`

**Q54.** Which parameter is required in every Messages API request body?
A) `temperature`
B) `max_tokens`
C) `system`
D) `stream`

**Q55.** In MCP, what distinguishes the three server primitives (tools, resources, prompts)?
A) Their latency
B) The control plane — tools are model-controlled, resources are host/application-controlled, prompts are user-controlled
C) Their transport
D) Their cost

**Q56.** What discount does the Batch API provide, and within what time are results delivered?
A) 25% off; 1 hour
B) 50% off input and output tokens; results within 24 hours (most under 1 hour)
C) 50% off input only; 48 hours
D) Free; 1 week

**Q57.** What are the prompt-caching TTL options and their price multipliers?
A) 1 minute (1x) or 1 day (3x)
B) 5-minute write at 1.25x base input, 1-hour write at 2x, cache reads at 0.1x
C) 5-minute only, at 0.5x
D) Unlimited TTL at 1x

**Q58.** A streaming API client checks only the HTTP status code for errors. What can it miss?
A) Nothing — status codes cover all errors
B) `overloaded_error` delivered as an in-stream error event after the connection opens with HTTP 200
C) 401 errors
D) Cache invalidation events

**Q59.** Your on-call runbook says "retry 429s immediately and treat 529s as client bugs." What correction is needed?
A) None — that is correct
B) 429 is your rate-limit problem (respect `retry-after`); 529 is Anthropic-wide overload — retry 529 with capped exponential backoff plus jitter
C) Swap them: 429 is Anthropic's fault
D) Neither is retryable

**Q60.** Which statement about the official MCP Registry is accurate (as of July 2026)?
A) It is a GA, fully vetted security guarantee for listed servers
B) It is still in Preview; a listing does not itself prove security, uptime, or quality — pin versions and verify publishers
C) It was shut down in 2026
D) It requires Enterprise membership to publish

---

### Section 7 — Claude Code

**Q61.** What is the recommended way to install Claude Code on macOS/Linux/WSL?
A) `pip install claude-code`
B) The native installer: `curl -fsSL https://claude.ai/install.sh | bash`, which auto-updates in the background
C) Downloading a .dmg from the App Store
D) `docker run anthropic/claude`

**Q62.** What does the npm package `@anthropic-ai/claude-code` actually install (as of v2.1.198+)?
A) A Node.js REPL wrapper
B) The same native binary as the standalone installer, via per-platform optional dependencies; requires Node.js 22+ but the binary does not invoke Node
C) A browser extension
D) The Agent SDK source code

**Q63.** At which four scopes can CLAUDE.md memory files exist?
A) Global, org, repo, branch
B) Managed policy, user (`~/.claude/CLAUDE.md`), project, local (`CLAUDE.local.md`)
C) System, user, session, ephemeral
D) Root, trunk, tag, fork

**Q64.** In Claude Code's permission rules, what is the evaluation order?
A) allow → ask → deny
B) deny → ask → allow
C) ask → allow → deny
D) First match wins alphabetically

**Q65.** Which permission mode "auto-approves tool calls with background safety checks"?
A) `default`
B) `plan`
C) `auto`
D) `dontAsk`

**Q66.** On which platforms does the built-in Bash sandbox run?
A) macOS (Seatbelt), Linux and WSL2 (bubblewrap+socat) — native Windows is not supported
B) All platforms including native Windows
C) macOS only
D) Linux only

**Q67.** What does a `PreToolUse` hook exiting with code 2 do?
A) Logs a warning only
B) Blocks the tool call as a blocking error
C) Retries the tool
D) Ends the session

**Q68.** Your team wants one Claude Code process to fix lint errors across 40 files in CI. Which documented pattern fits?
A) Open 40 interactive sessions
B) A `claude -p` fan-out loop in headless mode with `--output-format json` and `--allowedTools`
C) The `/voice` command
D) Cowork scheduled tasks

**Q69.** What triggers the Claude Code GitHub Action in a PR or issue?
A) A `/claude` slash command in Slack
B) An `@claude` mention; the GA action (`anthropics/claude-code-action@v1`) can analyze code, create PRs, and implement features
C) Merging to main
D) A commit signed with GPG

**Q70.** What is the average enterprise cost of Claude Code, per Anthropic's cost documentation?
A) ~$13 per developer per active day (below $30/active day for 90% of users)
B) ~$130 per developer per day
C) Free on all plans
D) $0.01 per commit

---

### Section 8 — Enterprise Admin & Security

**Q71.** Which SSO protocols and IdPs does Enterprise SSO support?
A) SAML 2.0 and OIDC with Okta, Microsoft Entra ID, and Google Workspace
B) Only Google sign-in
C) LDAP only
D) Only SAML 1.1

**Q72.** What does domain capture do?
A) Registers a DNS domain for Anthropic
B) Claims the corporate email domain (DNS TXT verification) so logins route through SSO and existing individual accounts are pulled into the managed workspace
C) Blocks email from the domain
D) Encrypts the domain's traffic

**Q73.** What is the prerequisite for SCIM provisioning, and what does it automate?
A) It requires SSO; it automates account creation, role updates, and deactivation from the IdP
B) It requires a Compliance API key
C) It requires HIPAA enablement
D) It has no prerequisites

**Q74.** What do Enterprise audit logs contain, and how far back?
A) Full chat content for 1 year
B) Metadata only (no chat/project titles or content — UUIDs only), covering the past 180 days
C) Only sign-in events for 30 days
D) Token counts for 7 days

**Q75.** Which key type and scope does the Compliance API use?
A) Standard `sk-ant-` API keys with `write:messages`
B) Admin API keys (`sk-ant-admin01-`) with the `read:compliance_activities` scope
C) OAuth user tokens
D) SCIM tokens

**Q76.** Which role hierarchy is correct?
A) User → Admin → Owner → Primary Owner (one per org)
B) Primary Owner → Owner → Admin → User
C) Admin → User → Guest → Auditor
D) There are no roles

**Q77.** An admin wants to know whether employee prompts train Anthropic's models on an Enterprise contract. The correct answer is:
A) Yes, with an opt-out toggle
B) No — prompts, data, and results are not used to train models by default on commercial products; contractual, with no opt-in/opt-out toggle
C) Only for the first 30 days
D) Only metadata is used

**Q78.** What is the default API data retention (post-September 2025) and the opt-in alternative?
A) 30 days default, 90-day opt-in
B) 7 days default; 30-day retention available by opting in via the DPA
C) Zero retention for everyone
D) 1 year default

**Q79.** Your security team proposes Zero Data Retention (ZDR) for all workloads including the Batch API, Files API, and code execution. What is wrong with this plan?
A) Nothing — ZDR covers everything
B) ZDR scope covers the Messages API and Token Counting API but excludes the Batch API, Files API, Skills API, code execution, and several other surfaces; Covered Models (Fable 5, Mythos 5) require 30-day retention and are incompatible with ZDR
C) ZDR is available only on Free plans
D) ZDR doubles the price

**Q80.** Which compliance certifications does Anthropic hold for commercial products (as of early 2026)?
A) SOC 2 Type I & II, ISO 27001:2022, and ISO/IEC 42001:2023
B) Only PCI-DSS
C) FedRAMP High for commercial products
D) None

---

### Section 9 — Prompt Engineering & Workflows

**Q81.** What is Anthropic's "golden rule" for testing whether a prompt is clear enough?
A) Run it through a linter
B) Show it to a colleague with minimal context; if they'd be confused following it, Claude will be too
C) Count the tokens
D) Ask Claude to rate it 1–10

**Q82.** How many few-shot examples does Anthropic recommend, and how should they be formatted?
A) Exactly one, in ALL CAPS
B) 3–5 diverse, canonical examples wrapped in `<example>`/`<examples>` tags
C) At least 20 edge cases
D) Examples are discouraged

**Q83.** For inputs over ~20k tokens, where should the long-form document go relative to your question, and why?
A) After the question — models read backwards
B) At the top, with the query at the end — this improved response quality by up to 30% in Anthropic's tests
C) In the system prompt only
D) Position does not matter

**Q84.** What replaced prefilled assistant responses starting with Claude 4.6?
A) Nothing changed
B) Prefill returns a 400 error; use Structured Outputs for forced JSON/YAML, system instructions to skip preamble, or move continuations into the user message
C) Prefill now requires a beta header
D) Prefill only works on Haiku

**Q85.** According to Anthropic, which instruction style produces better reasoning on current models?
A) Hand-written step-by-step plans
B) General instructions like "think thoroughly" — Claude's reasoning frequently exceeds what a human would prescribe
C) "Think step by step" appended to every prompt when thinking is enabled
D) ALL-CAPS emphasis

**Q86.** What is "context rot"?
A) Cache expiry after 5 minutes
B) The degradation of recall as the number of tokens in the context window increases — context is a finite attention budget
C) Corrupted CLAUDE.md files
D) Token price inflation

**Q87.** In Anthropic's "Building effective agents" framing, what distinguishes a workflow from an agent?
A) Workflows use LLMs; agents do not
B) Workflows orchestrate LLMs and tools through predefined code paths; agents have LLMs dynamically direct their own processes and tool usage
C) Agents are always cheaper
D) They are synonyms

**Q88.** Which pattern is described as "one LLM call generates a response while another provides evaluation and feedback in a loop"?
A) Routing
B) Parallelization
C) Evaluator-optimizer
D) Prompt chaining

**Q89.** A support team wants easy questions answered cheaply and hard questions answered by a premium model. Which pattern should they implement?
A) Routing — classify the input and direct it to specialized followup tasks or different models
B) Voting
C) Orchestrator-workers
D) Compaction

**Q90.** Which of these is an officially flagged prompt failure mode on current models?
A) Telling Claude what TO do instead of what not to do
B) Aggressive "CRITICAL: You MUST..." tool-trigger language causing overtriggering, and laundry lists of edge-case examples
C) Using XML tags
D) Giving a role in the system prompt

---

### Section 10 — Comparisons & Best Practices

**Q91.** On the vals.ai SWE-bench Verified tracker (July 31, 2026), which model led and at what score?
A) GPT-5.6 Sol at 96.2%
B) Claude Opus 5 at 97.0%
C) Claude Fable 5 at 95.0%
D) Gemini 3.1 Pro at 89%

**Q92.** Which competitor offers the largest advertised context window among current flagships?
A) Claude Opus 5 (1M)
B) GPT-5.6 Sol (~1.05M)
C) Gemini 3.1 Pro (2M, API)
D) Cursor (~200K advertised)

**Q93.** Which statement about Microsoft Copilot's relationship to Claude is accurate (2026)?
A) Copilot blocks all non-OpenAI models
B) Claude is available in mainline Copilot chat via the Frontier program, and Copilot Cowork (GA June 16, 2026) runs on Claude models by default
C) Microsoft acquired Anthropic
D) Copilot runs Claude only in Excel

**Q94.** How do Claude Code, Cursor, and GitHub Copilot differ philosophically?
A) They are identical products
B) Claude Code is a terminal-first autonomous agent; Cursor is an AI-native IDE for interactive, multi-model coding; Copilot is a plugin layer for existing IDEs with completions and a growing agent mode
C) Cursor is terminal-only; Claude Code is an IDE fork
D) Copilot is an agent; Claude Code is autocomplete-only

**Q95.** Per Anthropic's official cost-optimization guidance, how should you route workloads across model tiers?
A) Always use the most capable model
B) Haiku for simple tasks, Sonnet for most production workloads, Opus for the most complex reasoning — plus prompt caching and the Batch API
C) Use Fable 5 for everything
D) Route randomly to distribute load

**Q96.** Per the Menlo Ventures enterprise survey (December 2025 data), what was Anthropic's approximate share of enterprise LLM spend?
A) 10%
B) 21%
C) 27%
D) 40%

**Q97.** In the 2026 Pragmatic Engineer survey cited in comparisons research, how did Claude Code rank?
A) It was the most-loved developer tool at 46% (vs Cursor at 19%)
B) It ranked below all competitors
C) It tied with Notepad
D) It was not included

**Q98.** A newsroom team needs verifiable, cited current facts plus long-form synthesis. What hybrid pattern does the guide's comparison research suggest?
A) Claude for everything
B) Perplexity for gathering cited real-time facts, Claude for synthesis and long-form reasoning
C) Gemini for everything
D) ChatGPT's free tier only

**Q99.** Your team benchmarks Claude Opus 5 at 97% SWE-bench and declares victory in the company wiki. What caveat belongs in that wiki page?
A) None — benchmarks are absolute
B) Scores vary sharply by harness, scaffold, and tracker (vals.ai vs vendor-reported boards disagree), and leaderboards churn monthly — cite source and date
C) The benchmark only runs on Haiku
D) SWE-bench was retired in 2025

**Q100.** A workload needs the highest available capability regardless of cost (long-running agentic task). Per Anthropic's official model-selection guidance, which model should you start with?
A) Haiku 4.5
B) Sonnet 5
C) Opus 5 for complex agentic coding and enterprise work; Fable 5 when the workload needs the highest available capability
D) Mythos 5 via self-serve signup

---

---

> The answer key lives in the exam, not on this page. Sit the certification exam to see your score, the correct answers, and the reasoning behind each one.
