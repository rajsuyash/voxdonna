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
