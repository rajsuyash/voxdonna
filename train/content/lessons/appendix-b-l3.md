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
