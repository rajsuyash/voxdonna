# Part 20: Prompt Library — 100+ Production-Ready Prompts

**How to use this library.** Every prompt below is copy-paste-ready: replace the `[PLACEHOLDERS]` in square brackets with your own content and send. The templates follow Anthropic's recommended anatomy — a clear task, explicit context, XML tags to separate instructions from data, and a defined output format (Anthropic Docs, *Prompting best practices*, Jul 2026). Anthropic's golden rule applies before you use any of them: if a colleague with minimal context couldn't follow the prompt, Claude will struggle too. Pair heavier reasoning tasks with adaptive thinking (standard on 5-series models; Opus 5 thinks by default), attach source files via Projects, and route external lookups through the Research feature or connectors. Prompts marked **Pairs with** note the feature that improves results most. Model names and features are as of August 2026 — verify against current Anthropic documentation.

---

### 1. Research & Analysis

**1. Structured web research brief**
```
You are a research analyst. Research the following question thoroughly:

<question>[YOUR RESEARCH QUESTION]</question>
<context>[WHY YOU NEED THIS, WHO IT'S FOR, DECISION IT INFORMS]</context>

Instructions:
1. Start with broad searches, then narrow to specifics.
2. Develop at least two competing hypotheses and track your confidence in each.
3. Cross-check every key fact against at least two independent sources.
4. For every claim, cite the source and date.

Output format:
- Executive summary (5 bullets)
- Findings by hypothesis, with confidence level (High/Medium/Low)
- Contradictions or gaps in available evidence
- Recommended next research steps
```
*Pairs with: Research feature; extended thinking for synthesis.*

**2. Competitive landscape scan**
```
Analyze the competitive landscape for [PRODUCT/COMPANY] in [MARKET].

<context>[YOUR POSITION, TARGET SEGMENT, KNOWN COMPETITORS]</context>

Produce a comparison table covering: [COMPETITOR 1], [COMPETITOR 2], [COMPETITOR 3], and [COMPETITOR 4] across these dimensions:
- Pricing model and entry price
- Core differentiator
- Target customer
- Recent moves (last 12 months, with dates)
- Strengths and weaknesses vs. us

End with 3 strategic implications for [YOUR COMPANY]. Flag any claim you could not verify.
```
*Pairs with: Research; connectors (Salesforce/HubSpot for internal data).*

**3. Document deep-read with quote grounding**
```
<document>
[PASTE LONG DOCUMENT — contract, report, transcript, filing]
</document>

Answer this question about the document above:
<question>[YOUR QUESTION]</question>

Before answering, extract the 3–6 most relevant passages verbatim into
<quotes> tags. Base your answer only on those quotes. If the document
does not contain enough evidence, say so explicitly instead of inferring.

Output: <quotes> first, then <answer> (max 300 words), then <caveats>.
```
*Pairs with: 1M-token context on 5-series models; long-doc-before-query ordering.*

**4. Literature / source synthesis**
```
You are synthesizing research on [TOPIC].

<sources>
<source id="1">[PASTE ABSTRACT/EXCERPT 1]</source>
<source id="2">[PASTE ABSTRACT/EXCERPT 2]</source>
<source id="3">[PASTE ABSTRACT/EXCERPT 3]</source>
</sources>

Produce:
1. A synthesis of where the sources agree (cite by source id).
2. Where they disagree, and possible reasons why.
3. A joint findings table: Source | Method | Key claim | Evidence strength.
4. Open questions none of the sources answer.

Do not introduce facts beyond the sources provided.
```

**5. Interview / transcript analysis**
```
Analyze this [USER INTERVIEW / SALES CALL / FOCUS GROUP] transcript.

<transcript>[PASTE TRANSCRIPT]</transcript>

Extract:
- Top 5 themes, each supported by 1–2 verbatim quotes with speaker labels
- Pain points ranked by frequency and intensity
- Feature requests or unmet needs
- Notable emotional moments (frustration, delight)
- One-paragraph persona summary of the participant(s)

Format themes as a table: Theme | Quote | Implication for [PRODUCT/TEAM].
```
*Pairs with: Projects (keep a running transcript collection).*

**6. Meeting-notes-to-decisions extractor**
```
Here are notes from a [MEETING NAME] on [DATE]:

<notes>[PASTE NOTES]</notes>

Produce:
1. Decisions made (decision, owner, rationale in one line each)
2. Action items as a table: Action | Owner | Due date | Dependency
3. Open questions that were NOT resolved
4. Parking-lot items to revisit
5. A 3-sentence summary suitable for executives who missed the meeting

If owner or due date is missing, mark it [TBD] rather than guessing.
```

**7. Fact-check & claim verification**
```
Verify the following claims from [DOCUMENT/ARTICLE/PITCH]:

<claims>
1. [CLAIM 1]
2. [CLAIM 2]
3. [CLAIM 3]
</claims>

For each claim: search for corroborating and contradicting evidence.
Output a table: Claim | Verdict (Supported / Partially supported /
Unsupported / Unverifiable) | Best source(s) with date | Notes.
End with an overall credibility assessment of the source document.
```
*Pairs with: Research; web search.*

**8. Trend analysis from raw inputs**
```
Below are [N] data points/signals about [INDUSTRY/TOPIC] collected over [PERIOD]:

<signals>
[PASTE HEADLINES, METRICS, OR OBSERVATIONS]
</signals>

Identify:
1. 3–5 emerging trends, ranked by strength of evidence
2. Signals that contradict the mainstream narrative on [TOPIC]
3. What you would monitor over the next [PERIOD] to confirm or kill each trend
4. One contrarian hypothesis worth testing

Distinguish clearly between observed fact and your inference.
```

**9. Due-diligence question generator**
```
We are evaluating [COMPANY/VENDOR/ACQUISITION TARGET] for [PURPOSE].

<context>[WHAT WE KNOW SO FAR, DEAL SIZE, TIMELINE, RISK APPETITE]</context>

Generate a due-diligence checklist organized by:
- Financial (10 questions)
- Technical / product (10 questions)
- Legal & compliance (8 questions)
- Team & culture (6 questions)
- Customer & market (6 questions)

For each question add one line: what a red-flag answer looks like.
```

**10. Pre-mortem analysis**
```
It is [DATE 18 MONTHS FROM NOW] and [PROJECT/INITIATIVE] has failed badly.

<project>[BRIEF DESCRIPTION OF PLAN, GOALS, CONSTRAINTS]</project>

Write the post-mortem:
1. The 5 most likely causes of failure, ranked by probability
2. For each cause: the early warning sign we could have spotted
3. The mitigation we should put in place now for the top 3 causes
4. One sentence each: what we should NOT worry about (overestimated risks)

Be specific to this project, not generic.
```
*Pairs with: extended thinking for deeper causal reasoning.*

---

### 2. Writing & Editing

**11. Executive memo**
```
Write a one-page executive memo.

<topic>[DECISION/UPDATE TO COMMUNICATE]</topic>
<audience>[WHO READS IT — e.g., C-suite, board]</audience>
<background>[KEY FACTS, NUMBERS, CONTEXT]</background>
<stance>[YOUR RECOMMENDATION OR POSITION]</stance>

Structure:
1. Bottom line first (2 sentences)
2. Context (3 bullets max)
3. Options considered with trade-offs
4. Recommendation and requested action
Tone: direct, no jargon, active voice. Max 400 words.
```

**12. Long-form draft from outline**
```
Write a [ARTICLE/REPORT/BLOG POST] based on this outline.

<outline>[PASTE OUTLINE]</outline>
<audience>[AUDIENCE AND THEIR KNOWLEDGE LEVEL]</audience>
<source_material>[PASTE ANY NOTES/DATA TO DRAW FROM]</source_material>
<style>[e.g., conversational-expert, like The Economist / internal wiki]</style>

Rules:
- Length: ~[WORD COUNT] words
- Open with the implication for the reader, not background
- Use concrete examples; no filler transitions
- Do not copy source material word-for-word; synthesize
Output the draft in Markdown with H2 section headers.
```
*Pairs with: Artifacts for iteration; prompt-chaining outline → draft.*

**13. Edit for clarity (line edit)**
```
Edit this text for clarity, concision, and flow. Preserve the author's voice.

<text>[PASTE DRAFT]</text>

Deliver two parts:
1. The edited text (tracked-change style: show cuts in ~~strikethrough~~
   and additions in **bold**)
2. A bulleted list of the 5 most significant changes with one-line
   rationale for each.

Do not change meaning or remove technical content without flagging it.
```

**14. Tone rewriter**
```
Rewrite the following for a [AUDIENCE — e.g., frustrated customer /
regulator / skeptical engineer] audience.

<original>[PASTE TEXT]</original>

Target tone: [e.g., empathetic but firm / formal and precise / plain-spoken].
Keep: all facts, commitments, and deadlines unchanged.
Change: sentence length, vocabulary, level of formality.

Output only the rewritten text, then one line explaining the biggest tonal shift.
```

**15. Technical documentation**
```
Write user documentation for [FEATURE/PROCESS].

<context>[WHAT IT DOES, WHO USES IT, PREREQUISITES]</context>
<raw_notes>[PASTE ENGINEERING NOTES, SPECS, OR BULLETS]</raw_notes>

Structure:
1. Overview (2 sentences, non-technical)
2. Before you begin (prerequisites)
3. Numbered step-by-step procedure with expected result per step
4. Troubleshooting table: Symptom | Likely cause | Fix
5. FAQ (5 questions)

Define every technical term on first use. Audience: [SKILL LEVEL].
```

**16. Summary with tiered lengths**
```
Summarize the following document.

<document>[PASTE TEXT]</document>

Produce three summaries:
1. One sentence (max 25 words)
2. One paragraph (max 80 words)
3. Five bullets covering: purpose, key findings, decisions, risks, next steps

Preserve all numbers and proper nouns exactly. Do not add interpretation.
```

**17. Style-guide enforcer**
```
You are an editor enforcing our style guide.

<style_guide>
[PASTE STYLE RULES — e.g., voice, banned words, capitalization, formatting]
</style_guide>

<draft>[PASTE TEXT]</draft>

1. List every style violation: quote the offending text, name the rule, give the fix.
2. Provide the fully corrected version.
3. If a rule conflicts with clarity, note the conflict and choose clarity.
```

**18. Cold email / outreach**
```
Write a [COLD EMAIL / FOLLOW-UP] to [RECIPIENT ROLE] at [COMPANY TYPE].

<goal>[WHAT YOU WANT — meeting, reply, intro]</goal>
<value_prop>[WHAT'S IN IT FOR THEM, ONE LINE]</value_prop>
<proof>[CREDIBILITY: customer, metric, mutual connection]</proof>

Rules:
- Max 120 words
- Subject line under 7 words, no clickbait
- First line about them, not you
- One clear call to action with a specific, low-friction ask
- No buzzwords ("synergy", "revolutionary", "circle back")
Give 3 variants: formal, conversational, and brief.
```

**19. Speech / presentation script**
```
Write a [LENGTH]-minute talk for [EVENT/AUDIENCE].

<message>[THE ONE THING AUDIENCE SHOULD REMEMBER]</message>
<story_points>[ANECDOTES, DATA, OR EXAMPLES TO INCLUDE]</story_points>
<audience_state>[WHAT THEY KNOW, BELIEVE, AND CARE ABOUT]</audience_state>

Structure: hook (30 sec) → problem → turning point → evidence → call to action.
Write for the ear: short sentences, signposting phrases ("Here's the part
that matters"), and [PAUSE] / [SLIDE: description] cues inline.
```

**20. Headline & title generator**
```
Generate 12 title options for this [ARTICLE/REPORT/TALK].

<content>[PASTE ABSTRACT OR FULL TEXT]</content>
<audience>[WHO IT'S FOR]</audience>
<channel>[WHERE IT RUNS — blog, internal wiki, conference]</channel>

Produce 4 each of: (a) direct/benefit-led, (b) curiosity-driven,
(c) contrarian/question format. For each, one line on the intended effect.
Avoid clickbait that the content cannot pay off.
```

---

### 3. Coding & Debugging

**21. Feature implementation spec**
```
Implement [FEATURE] in this codebase.

<requirements>
- [REQUIREMENT 1]
- [REQUIREMENT 2]
- [EDGE CASES AND CONSTRAINTS]
</requirements>
<stack>[LANGUAGE, FRAMEWORK, VERSIONS]</stack>
<conventions>[STYLE GUIDE, PATTERNS TO FOLLOW, FILES TO MIRROR]</conventions>

Rules:
- Read the relevant files before proposing changes; never speculate about
  code you have not opened.
- Only make changes that are directly requested — no extra files, no
  refactors of surrounding code.
- Implement a solution correct for all valid inputs, not just test cases.
Deliver: plan (numbered), then diffs per file, then how to test.
```
*Pairs with: Claude Code with CLAUDE.md; effort `xhigh` for agentic coding (Anthropic Docs, Jul 2026).*

**22. Debug a failing test / stack trace**
```
Diagnose this failure.

<error>[PASTE FULL ERROR / STACK TRACE]</error>
<code>[PASTE RELEVANT CODE]</code>
<expected>[WHAT SHOULD HAPPEN]</expected>
<recent_changes>[WHAT CHANGED RECENTLY]</recent_changes>

Work through it:
1. Identify the most likely root cause (and 1–2 alternatives, ranked)
2. Point to the exact line(s) responsible
3. Provide the minimal fix
4. Suggest one regression test that would have caught this
Do not rewrite the surrounding code.
```
*Pairs with: Claude Code (reads the repo directly); extended thinking.*

**23. Code review**
```
Review this [PULL REQUEST / DIFF] as a senior engineer.

<diff>[PASTE DIFF]</diff>
<context>[WHAT THE CHANGE IS SUPPOSED TO DO]</context>

Review for, in priority order:
1. Correctness bugs and logic errors
2. Security issues (injection, authz, secrets, unsafe deserialization)
3. Error handling and edge cases
4. Performance concerns
5. Readability and maintainability

Output a table: Severity (Blocker/Major/Minor/Nit) | Location | Issue |
Suggested fix. End with an overall verdict: approve / approve with
comments / request changes.
```

**24. Explain unfamiliar code**
```
Explain this code to a [JUNIOR ENGINEER / NEW HIRE / NON-SPECIALIST].

<code>[PASTE CODE]</code>

Provide:
1. What it does in one plain sentence
2. A walkthrough of the key sections, referencing line numbers
3. The data flow: inputs → transformations → outputs
4. Non-obvious decisions and why they might exist
5. What would break if [SPECIFIC INPUT/CONDITION] changed
Use an analogy for the overall design if one fits.
```

**25. SQL query writer**
```
Write a SQL query for [DATABASE — Postgres/MySQL/Snowflake].

<schema>
[TABLE NAMES, COLUMNS, TYPES, RELATIONSHIPS]
</schema>
<question>[BUSINESS QUESTION IN PLAIN LANGUAGE]</question>
<sample_rows>[OPTIONAL: EXAMPLE DATA]</sample_rows>

Deliver:
1. The query, commented section by section
2. Plain-language explanation of the logic
3. Edge cases handled (NULLs, duplicates, time zones)
4. A cheaper alternative formulation if one exists
Assume read-only access; no DDL or DML.
```
*Pairs with: analysis tool / code execution to validate output.*

**26. Refactor for a target quality**
```
Refactor this code to improve [READABILITY / PERFORMANCE / TESTABILITY]
without changing behavior.

<code>[PASTE CODE]</code>
<constraints>[e.g., must stay in Python 3.11, no new dependencies]</constraints>

Steps:
1. List the specific smells you found (name each: long function,
   deep nesting, duplicated logic, etc.)
2. Show the refactored code
3. Provide a mapping: smell → technique applied (extract function,
   guard clause, etc.)
4. Confirm behavior is unchanged and suggest characterization tests
   to run before merging.
```

**27. Test generator**
```
Write tests for this [FUNCTION/MODULE/ENDPOINT].

<code>[PASTE CODE]</code>
<framework>[e.g., pytest, Jest, JUnit]</framework>

Cover:
- Happy path (2 cases)
- Boundary conditions (empty, zero, max, off-by-one)
- Error cases and invalid input
- [STATEFUL CASES / CONCURRENCY / MOCKS as relevant]

Rules: each test asserts one behavior; descriptive test names in
"should_X_when_Y" style; no testing of implementation details.
Implement tests that would fail for genuinely wrong behavior — do not
hardcode to the current output.
```

**28. API design reviewer**
```
Critique this API design.

<spec>[PASTE ENDPOINTS, SCHEMAS, OR OPENAPI FRAGMENT]</spec>
<use_cases>[TOP 3 CONSUMER USE CASES]</use_cases>

Evaluate:
1. Resource modeling and naming consistency
2. Versioning and backward-compatibility risks
3. Error format and status-code usage
4. Pagination, filtering, rate-limit story
5. Auth/authz model gaps

Output: findings table (Issue | Severity | Recommendation), then a
revised sketch of the two weakest endpoints.
```

**29. Incident postmortem drafter**
```
Draft a blameless postmortem for this incident.

<timeline>[PASTE TIMELINE / CHAT LOG EXCERPTS]</timeline>
<impact>[USERS/REVENUE/DURATION AFFECTED]</impact>
<root_cause>[WHAT WAS FOUND]</root_cause>
<resolution>[HOW IT WAS FIXED]</resolution>

Structure: Summary → Impact → Timeline (UTC) → Root cause (5-whys
compressed) → What went well / poorly → Action items table (Action |
Owner | Due). Tone: factual, blameless, no speculation beyond evidence.
```

**30. Migration plan**
```
Plan the migration from [OLD TECH/VERSION] to [NEW TECH/VERSION].

<codebase_context>[SIZE, CRITICAL MODULES, DEPENDENCIES, TEAM SIZE]</codebase_context>
<constraints>[DOWNTIME BUDGET, DEADLINE, RISK TOLERANCE]</constraints>

Deliver:
1. Phased plan with rollback criteria per phase
2. Dependency-ordered task list
3. Risk register: Risk | Likelihood | Impact | Mitigation
4. What to automate (codemods, tests) vs. manual
5. Definition of done for the migration overall
```
*Pairs with: Claude Code subagents for executing per-module migrations.*

---

### 4. Data Analysis & Excel

**31. Spreadsheet formula builder**
```
Write an [Excel / Google Sheets] formula for this task.

<goal>[WHAT YOU WANT TO COMPUTE, IN PLAIN LANGUAGE]</goal>
<layout>[WHERE THE DATA LIVES — e.g., names in A2:A500, dates in B, amounts in C]</layout>
<example>[ONE ROW OF SAMPLE DATA AND THE DESIRED RESULT]</example>

Provide: the formula, a plain explanation of each part, common errors
(#N/A, #DIV/0!) and how to guard them, and a dynamic-array alternative
if applicable.
```

**32. CSV / dataset profiler**
```
Profile this dataset.

<data>[PASTE CSV SAMPLE OR DESCRIBE SCHEMA + SAMPLE ROWS]</data>
<question>[WHAT YOU'RE TRYING TO LEARN]</question>

Deliver:
1. Column-by-column summary: type, missing %, distinct values, anomalies
2. Data-quality issues that would bias analysis
3. 3 hypotheses worth testing against the question
4. The cleaning steps to run first, in order
If you write code to analyze it, validate counts before drawing conclusions.
```
*Pairs with: code execution / analysis tool; XLSX inputs require code execution (Anthropic Docs, Jul 2026).*

**33. Analysis-plan generator**
```
Design an analysis to answer [BUSINESS QUESTION].

<available_data>[TABLES/FIELDS YOU HAVE]</available_data>
<decision>[WHAT DECISION THE ANSWER DRIVES]</decision>
<constraints>[TIME, TOOLS, SKILL LEVEL]</constraints>

Produce: the metric definition (exact formula), segmentation cuts,
required joins, statistical pitfalls (selection bias, survivorship,
seasonality) with mitigations, and the final deliverable format.
State what this data CANNOT answer.
```

**34. Chart & narrative recommender**
```
I need to present this data to [AUDIENCE].

<data_summary>[PASTE AGGREGATED TABLE OR DESCRIBE IT]</data_summary>
<message>[THE POINT YOU WANT THEM TO TAKE AWAY]</message>

Recommend: the single best chart type and why; axis/annotation choices;
the 2 charts to avoid and why; and a 3-sentence spoken narrative to
accompany the chart. Prioritize honesty — flag any axis truncation or
aggregation that could mislead.
```

**35. Anomaly investigator**
```
This metric moved unexpectedly: [METRIC] changed [X%] between [PERIOD A]
and [PERIOD B].

<context>[WHAT THE METRIC MEASURES, RECENT CHANGES/RELEASES]</context>
<breakdown_data>[PASTE SEGMENT BREAKDOWNS IF AVAILABLE]</breakdown_data>

Generate: 5 ranked hypotheses for the cause (mix shift, tracking change,
seasonality, real behavior change, one-off event); for each, the one
query or check that would confirm/refute it; and what you'd report to
leadership right now.
```
*Pairs with: extended thinking.*

**36. Excel-to-SQL translator**
```
Convert this spreadsheet logic into SQL.

<spreadsheet_logic>[DESCRIBE OR PASTE THE FORMULAS / PIVOT SETUP]</spreadsheet_logic>
<target_schema>[TABLE NAMES AND COLUMNS]</target_schema>
<dialect>[Postgres / BigQuery / Snowflake]</dialect>

Deliver the equivalent query, a mapping table (spreadsheet step → SQL
clause), and notes on any semantics that differ (blank cells vs NULL,
floating-point rounding, date handling).
```

**37. Data dictionary writer**
```
Create a data dictionary for [TABLE/DATASET].

<schema>[PASTE DDL OR COLUMN LIST WITH SAMPLES]</schema>
<domain_context>[WHAT THE BUSINESS DOES]</domain_context>

Output a table: Column | Type | Business definition | Allowed values /
range | Source system | Update frequency | Known quirks. Flag columns
whose meaning is ambiguous and propose a validation query for each.
```

**38. Experiment readout**
```
Interpret these A/B test results.

<setup>[HYPOTHESIS, VARIANTS, PRIMARY METRIC, GUARDRAILS, SAMPLE SIZE, DURATION]</setup>
<results>[PASTE NUMBERS]</results>

Provide: the plain-language verdict; whether the result supports
shipping; guardrail check; threats to validity (novelty effect, peeking,
SRM — run a sample-ratio-mismatch check); and the recommended next step
(ship, iterate, extend, abandon). State your confidence and why.
```

---

### 5. Product Management

**39. PRD first draft**
```
Draft a PRD for [FEATURE].

<problem>[USER PROBLEM + EVIDENCE]</problem>
<users>[TARGET SEGMENT]</users>
<constraints>[TECHNICAL, TIMELINE, RESOURCING]</constraints>
<success>[HOW WE'LL KNOW IT WORKED]</success>

Sections: Problem statement; Goals / non-goals; User stories (3–5, in
"As a [user] I want [X] so that [Y]" form); Proposed solution; UX flows;
Metrics (primary + guardrail); Open questions; Rollout plan.
Keep non-goals explicit and ruthless.
```

**40. Backlog prioritization (RICE)**
```
Score these initiatives with RICE.

<initiatives>
1. [NAME + one-line description]
2. ...
</initiatives>
<context>[TEAM SIZE, STRATEGY, QUARTER]</context>

For each: Reach, Impact (0.25–3), Confidence (%), Effort (person-weeks)
with one-line justification per factor; then the RICE score and ranked
table. Flag scores where a small confidence change would flip the
ranking, and recommend which 2 to cut entirely.
```

**41. User story + acceptance criteria**
```
Turn this feature idea into engineering-ready stories.

<idea>[DESCRIPTION]</idea>
<personas>[WHO USES IT]</personas>

Produce 4–6 stories, each with: story ("As a..."), 3–5 acceptance
criteria in Given/When/Then format, edge cases, and out-of-scope notes.
Order by dependency. Estimate relative size (S/M/L) with rationale.
```

**42. Roadmap narrative**
```
Write a one-page roadmap narrative for [QUARTER/HALF].

<themes>[TOP 3–4 THEMES AND WHAT'S IN THEM]</themes>
<audience>[EXECUTIVES / SALES / WHOLE COMPANY]</audience>
<constraints>[KNOWN DEPENDENCIES, STAFFING]</constraints>

Structure: where we're going (2 sentences) → the 3 bets and why now →
what we're explicitly NOT doing → key risks → how we'll measure success.
Now/Next/Later framing; no dates more precise than months.
```

**43. Churn / feedback theme analysis**
```
Analyze this batch of [CHURN SURVEYS / SUPPORT TICKETS / NPS COMMENTS].

<feedback>[PASTE RESPONSES]</feedback>

Cluster into 4–7 themes. For each: theme name, share of responses,
severity for the user, 2 representative verbatim quotes, and a candidate
product response. End with the single theme most likely driving churn
and the evidence for that claim.
```
*Pairs with: Projects for accumulating feedback over time.*

**44. Feature announcement**
```
Write the launch announcement for [FEATURE].

<feature>[WHAT IT DOES, WHO GETS IT, WHEN]</feature>
<audience>[EXISTING USERS / PROSPECTS / INTERNAL]</audience>
<channel>[BLOG / IN-APP / EMAIL]</channel>

Lead with the user benefit, not the technology. Structure: the problem
we heard → what we built → how it works (3 steps max) → who gets it and
when → what's next. 250 words for email, 600 for blog. Include one
suggested in-app tooltip (max 20 words).
```

**45. Stakeholder update**
```
Write a weekly product update for [STAKEHOLDER GROUP].

<progress>[SHIPPED, IN FLIGHT, METRICS MOVEMENT]</progress>
<blockers>[BLOCKERS AND WHAT YOU NEED]</blockers>
<next>[NEXT 2 WEEKS]</next>

Format: TL;DR (2 sentences) → Wins → Metrics table (metric, current,
target, trend) → Risks/blockers with asks in bold → Next. Max 300
words; scannable in 30 seconds.
```

**46. Bet sizing / opportunity assessment**
```
Assess this product opportunity before we commit.

<opportunity>[DESCRIPTION]</opportunity>
<market>[TAM ESTIMATE OR SEGMENT SIZE, IF KNOWN]</market>
<alternatives>[STATUS QUO + OTHER OPTIONS]</alternatives>

Deliver: the falsifiable bet ("We believe X will cause Y, measured by
Z, within T"); assumptions ranked by riskiness; the cheapest test for
the riskiest assumption; comparable precedents; and a recommendation:
full build / experiment / research / pass — with confidence level.
```
*Pairs with: extended thinking.*

---

### 6. Marketing & Sales

**47. Campaign brief**
```
Write a campaign brief for [PRODUCT/LAUNCH].

<objective>[AWARENESS / PIPELINE / RETENTION TARGET, WITH NUMBER]</objective>
<audience>[SEGMENT, PAIN, CURRENT BELIEF]</audience>
<assets>[BUDGET/CHANNELS AVAILABLE]</assets>

Include: single-minded proposition; key messages (3, ranked); proof
points; channel plan with rationale; timeline; KPIs and measurement
plan; risks. One page.
```

**48. Ad copy variants**
```
Generate ad copy for [PRODUCT] on [CHANNEL — Google/LinkedIn/Meta].

<offer>[WHAT + PRICE/CTA]</offer>
<audience>[TARGET AND THEIR PAIN]</audience>
<differentiator>[WHY US, PROOF]</differentiator>

Produce 5 variants per channel, respecting format limits (Google: 30-char
headlines, 90-char descriptions). Each variant leads with a different
psychological angle: pain, gain, social proof, curiosity, urgency.
Label each with its angle. No superlatives without proof.
```

**49. Landing page copy**
```
Write landing page copy for [PRODUCT/OFFER].

<audience>[WHO LANDS HERE AND FROM WHERE]</audience>
<value_prop>[CORE PROMISE]</value_prop>
<proof>[LOGOS, STATS, TESTIMONIALS]</proof>
<cta>[PRIMARY ACTION]</cta>

Sections with copy: H1 + subhead; 3 benefit blocks (benefit-led, not
feature-led); social proof band; objection-handling FAQ (5 items); CTA
block; and 2 alternate H1s for A/B testing. Reading level: grade 8.
```

**50. SEO content brief**
```
Create a content brief for the keyword "[TARGET KEYWORD]".

<intent>[WHAT THE SEARCHER WANTS]</intent>
<competitors>[URLS/ANGLES RANKING NOW, IF KNOWN]</competitors>
<our_angle>[OUR UNIQUE EXPERTISE/DATA]</our_angle>

Deliver: working title; search intent classification; recommended H2
outline; questions to answer (from "people also ask" style); word count
target; internal links to include; the differentiator that makes ours
worth ranking.
```

**51. Sales discovery call prep**
```
Prepare me for a discovery call with [COMPANY/CONTACT].

<account_research>[WHAT YOU KNOW — or ask me to paste it]</account_research>
<our_solution>[WHAT WE SELL, RELEVANT USE CASE]</our_solution>

Produce: hypothesis of their top 3 pains; 8 discovery questions ordered
rapport → situation → impact → decision process; 2 likely objections
with responses; one relevant customer story (template); and what a
successful next step looks like.
```
*Pairs with: Research for account intel; Salesforce/HubSpot connectors.*

**52. Objection handler**
```
A prospect said: "[EXACT OBJECTION — e.g., 'It's too expensive']".

<deal_context>[PRODUCT, THEIR SITUATION, STAGE]</deal_context>

Give: what the objection likely means beneath the surface; a 3-step
verbal response (acknowledge → reframe → question) in natural spoken
language; 2 proof points to deploy; and the follow-up question that
moves the deal forward. Avoid defensive or scripted-sounding language.
```

**53. Win/loss interview analysis**
```
Analyze these win/loss interview notes.

<notes>[PASTE INTERVIEW EXCERPTS FROM N DEALS]</notes>

Output: top 3 win drivers and top 3 loss drivers with verbatim quotes;
where our positioning vs. [COMPETITOR] lands; messaging that resonated
vs. fell flat; and 3 recommendations each for Sales and Product. Flag
patterns that appear in only one interview as anecdotal.
```

**54. Customer case study**
```
Write a case study from this interview/material.

<raw>[PASTE CUSTOMER QUOTES, METRICS, BACKGROUND]</raw>
<approval_constraints>[WHAT CUSTOMER ALLOWED US TO SAY]</approval_constraints>

Structure: customer + challenge (before state) → why they chose us →
implementation → results (lead with the hard numbers) → quote callouts
→ "what's next". 600–800 words. Never invent metrics; mark missing
numbers as [METRIC NEEDED].
```

**55. Nurture email sequence**
```
Write a 4-email nurture sequence for [SEGMENT] who [TRIGGER — downloaded
X, attended webinar].

<goal>[CONVERSION TARGET]</goal>
<content_assets>[WHAT WE CAN LINK TO]</content_assets>

For each email: send timing, subject line, preview text, body (max 150
words), CTA. Sequence logic: value → value → proof → ask. Each email
must be useful even if they never buy. No fake urgency.
```

**56. Social post repurposer**
```
Repurpose this [BLOG/REPORT/TALK] into social posts.

<source>[PASTE CONTENT]</source>
<brand_voice>[DESCRIBE OR PASTE EXAMPLES]</brand_voice>

Create: 3 LinkedIn posts (one insight, one story, one contrarian take —
150 words max each), 5 X/Twitter posts (hook-first), and 1 carousel
outline (8 slides, headline + one line per slide). Pull real substance
from the source; no empty engagement bait.
```

---

### 7. Legal & Compliance

> Caveat: prompts in this section support drafting and review by qualified professionals. Claude's output is not legal advice; route all final documents through counsel. (Medium-confidence/Conflict-zone items around data handling are flagged in Chapter on Enterprise controls — verify current terms as of August 2026.)

**57. Contract clause reviewer**
```
Review this contract clause from the perspective of [YOUR SIDE — buyer/vendor].

<clause>[PASTE CLAUSE]</clause>
<contract_context>[DEAL TYPE, VALUE, JURISDICTION]</contract_context>
<our_position>[WHAT WE WANT — e.g., cap liability at 12 months' fees]</our_position>

Deliver: plain-English summary of what the clause does; risks to us
(ranked); how it deviates from market standard; a redline suggestion;
and the fallback position if the counterparty refuses. Flag anything
requiring licensed counsel review.
```

**58. Policy gap analysis**
```
Compare our policy against [REGULATION/FRAMEWORK — e.g., SOC 2, ISO 27001,
internal standard].

<policy>[PASTE POLICY TEXT]</policy>
<requirements>[PASTE RELEVANT REQUIREMENT LIST]</requirements>

Output a coverage matrix: Requirement | Covered (Y/Partial/N) | Policy
section | Gap description | Recommended fix | Owner suggestion.
Do not interpret requirements beyond the text provided; mark ambiguous
mappings for compliance-team review.
```
*Pairs with: Projects holding the full policy library.*

**59. NDA first-pass check**
```
Screen this NDA before signature.

<nda>[PASTE TEXT]</nda>
<our_standard>[e.g., mutual, 3-year term, no residuals clause, Delaware law]</our_standard>

Check: mutuality; term length; definition of confidential information
(overly broad?); exclusions present (public, prior knowledge, independent
development); residuals clause; jurisdiction; non-solicit buried in the
NDA. Table: Item | Status (OK/Concern/Blocker) | Note | Suggested edit.
```

**60. Regulatory change digest**
```
Summarize this [REGULATION/GUIDANCE/ENFORCEMENT ACTION] for [BUSINESS FUNCTION].

<text>[PASTE TEXT OR LINKED EXCERPT]</text>

Produce: what changed in 3 bullets; who in our org is affected; effective
dates; required actions (if any) vs. monitoring items; penalties for
non-compliance as stated in the text; and open questions for counsel.
Quote the operative language for anything material.
```

**61. Meeting-minutes for audit trail**
```
Draft formal minutes for this [BOARD/COMMITTEE] meeting.

<notes>[PASTE ROUGH NOTES, ATTENDEES, MOTIONS]</notes>

Format: attendance & quorum; agenda items; for each — discussion summary
(neutral, 2–3 lines), motions with mover/seconder, vote counts,
resolutions adopted; conflicts declared; next meeting date. Formal
register, no adjectives, no attribution of informal remarks.
```

**62. Privacy notice drafter**
```
Draft a plain-language privacy notice section for [DATA PROCESSING ACTIVITY].

<data_flows>[WHAT DATA, FROM WHOM, WHY, WHERE STORED, WHO ACCESSES, RETENTION]</data_flows>
<jurisdictions>[e.g., EU/UK, California]</jurisdictions>

Write: what we collect; why (mapped to stated purposes); legal bases
(generic, flagged for counsel confirmation); sharing categories;
retention; user rights and how to exercise them; contact. Flag every
place legal counsel must verify before publication with [COUNSEL CHECK].
```

---

### 8. HR & Recruiting

**63. Job description**
```
Write a job description for [ROLE], [LEVEL], in [TEAM/FUNCTION].

<must_haves>[5-7 REAL REQUIREMENTS]</must_haves>
<day_one>[WHAT THEY'LL ACTUALLY DO — projects, not buzzwords]</day_one>
<comp_band>[RANGE + LOCATION POLICY]</comp_band>

Structure: what you'll own (3 bullets); what success looks like at 6
months; requirements (must-have only) vs. nice-to-haves; comp/benefits;
how to apply. Inclusive-language check: flag any coded or exclusionary
phrasing in my inputs before drafting.
```

**64. Resume screener (rubric-based)**
```
Screen this resume against the rubric below. Be consistent and evidence-based.

<rubric>
[REQUIREMENT → WHAT COUNTS AS EVIDENCE, e.g., "5 yrs backend" →
"explicit roles + dates"]
</rubric>
<resume>[PASTE RESUME]</resume>

Output: requirement-by-requirement table (Met/Partial/Not met + quoted
evidence); overall recommendation (advance/hold/decline) with rationale;
2 interview questions to probe gaps. Do not infer skills not evidenced;
do not consider name, school prestige, or gaps in employment.
```

**65. Interview question bank**
```
Design an interview loop for [ROLE/LEVEL].

<competencies>[4-6 COMPETENCIES TO ASSESS]</competencies>

For each competency: 2 behavioral questions ("Tell me about a time...")
with what strong/weak answers sound like; 1 work-sample or case exercise
with scoring rubric (1–4 anchors); and red flags. Include an interviewer
debrief template so scores stay independent before discussion.
```

**66. Offer & rejection communications**
```
Write two emails for candidate [NAME], [ROLE].

<context>[STAGE REACHED, SOMETHING SPECIFIC AND POSITIVE FROM THEIR PROCESS]</context>

1. Offer email: warm, specific, outlines comp/level/start date as
   [PLACEHOLDERS], next steps, who to contact with questions.
2. Rejection email: respectful, prompt, specific but not detailed feedback,
   door open for future roles, max 100 words.
Tone: human, not corporate. No ghosting language, no false hope.
```

**67. Performance review drafter**
```
Draft a performance review for [NAME/ROLE] covering [PERIOD].

<inputs>[PASTE: goals, shipped work, feedback excerpts, metrics]</inputs>
<rating_scale>[YOUR SCALE AND DEFINITIONS]</rating_scale>

Structure: summary (3 sentences); accomplishments mapped to goals with
evidence; growth areas (max 2, each with a specific example and a
development action); proposed rating with justification; goals draft for
next period (3, measurable). Separate observed fact from interpretation.
```

**68. Policy FAQ for employees**
```
Turn this policy into an employee-friendly FAQ.

<policy>[PASTE POLICY TEXT — e.g., PTO, expense, remote work]</policy>

Write 10–12 Q&As in plain language covering the most common real-world
situations, including edge cases (mid-year hire, carryover, manager
discretion). Each answer: 2–4 sentences, cites the policy section it
comes from. End with "Who to contact" block. Flag ambiguities in the
policy itself with [POLICY OWNER: CLARIFY].
```

---

### 9. Finance & Operations

**69. Budget variance commentary**
```
Write variance commentary for [DEPARTMENT/PERIOD].

<numbers>[PASTE: line item, budget, actual, variance $ and %]</numbers>
<context>[KNOWN EVENTS — hires, campaigns, one-offs]</context>

For each line > [THRESHOLD, e.g., ±5% or $10k]: driver explanation in
one sentence, one-time vs. recurring classification, full-year impact
estimate. End with 3-bullet executive summary and forecast risks.
Never invent explanations — mark unknowns as [CONFIRM WITH OWNER].
```
*Pairs with: code execution for the calculations.*

**70. Financial model explainer**
```
Explain this financial model to a [NON-FINANCE EXECUTIVE / NEW ANALYST].

<model_description>[PASTE STRUCTURE: tabs, drivers, formulas, outputs]</model_description>

Deliver: how money flows through the model (inputs → drivers → outputs);
the 3 assumptions the result is most sensitive to and why; what would
make the model wrong; and a 60-second spoken summary for a board
meeting. Flag circular references or hardcodes you spot.
```

**71. Vendor evaluation scorecard**
```
Build a vendor evaluation for [CATEGORY — e.g., CRM, payroll].

<requirements>[MUST-HAVES AND NICE-TO-HAVES]</requirements>
<vendors>[VENDOR NAMES + PASTE ANY PRICING/FEATURE NOTES]</vendors>
<weights>[e.g., functionality 40%, cost 25%, security 20%, support 15%]</weights>

Output: weighted scorecard table with per-criterion notes; TCO
comparison over 3 years including hidden costs; key contract
gotchas to probe; and a recommendation with sensitivity note (what
weight change would flip the result).
```
*Pairs with: connectors (pull quotes from email/Drive).*

**72. SOP writer**
```
Write a standard operating procedure for [PROCESS].

<current_practice>[DESCRIBE HOW IT'S DONE TODAY, ROLES INVOLVED]</current_practice>
<systems>[TOOLS USED]</systems>

Format: purpose; scope; roles & responsibilities (RACI); numbered steps
with expected outcome and time estimate per step; decision points as
"If X, then…" tables; escalation path; version/owner/review-date header.
Write so a new hire can execute on day one without asking questions.
```

**73. Invoice / expense audit**
```
Audit these [INVOICES / EXPENSE REPORTS] against policy.

<policy>[PASTE RELEVANT POLICY RULES]</policy>
<records>[PASTE LINE ITEMS]</records>

Flag: duplicates (fuzzy match on vendor+amount+date); out-of-policy
items citing the rule; missing documentation; unusual patterns (just
under approval thresholds, weekend dates, round numbers). Table:
Record | Flag | Rule cited | Recommended action. Do not accuse —
describe findings factually.
```

**74. Board financial summary**
```
Write the finance section of a board deck in prose.

<data>[PASTE: revenue, burn, runway, ARR metrics, headcount, forecast]</data>
<highlights>[WHAT MANAGEMENT WANTS EMPHASIZED]</highlights>

Structure: headline numbers (vs. plan and vs. prior period) → what's
driving the numbers → cash position and runway with sensitivity →
forecast and key assumptions → asks/decisions needed. 350 words, no
jargon, every number tied to a driver.
```

**75. Process bottleneck analysis**
```
Analyze this operational process for bottlenecks.

<process>[STEP-BY-STEP DESCRIPTION WITH CYCLE TIMES PER STEP]</process>
<volumes>[THROUGHPUT, ERROR/REWORK RATES]</volumes>

Deliver: the constraint step and evidence; queue-time vs. work-time
breakdown; top 3 improvement levers ranked by impact/effort; a quick
win achievable in 2 weeks; and the metric to track post-change.
```
*Pairs with: extended thinking.*

**76. Vendor negotiation prep**
```
Prepare me to negotiate renewal with [VENDOR].

<current_deal>[PRICE, TERMS, SEATS, RENEWAL DATE]</current_deal>
<usage>[ACTUAL USAGE/ADOPTION DATA]</usage>
<alternatives>[CREDIBLE ALTERNATIVES + SWITCHING COST]</alternatives>

Produce: our BATNA in one sentence; target price and walk-away; 3
anchoring arguments grounded in usage data; concessions we can offer
(term length, case study, payment terms) ranked by cost to us; likely
vendor counters and responses; and the opening line for the call.
```

---

### 10. Executives & Strategy

**77. Decision memo (one-pager)**
```
Write a decision memo for [DECISION].

<context>[BACKGROUND, WHY NOW, STAKEHOLDERS]</context>
<options>[OPTIONS ON THE TABLE, WITH KNOWN PROS/CONS]</options>

Structure: recommendation up front (2 sentences); the decision and its
reversibility (one-way vs. two-way door); options compared on 3–4
criteria in a table; risks of the recommended path and mitigations;
what we'd need to believe for each rejected option to be right; the
specific decision requested and by when. One page.
```
*Pairs with: extended thinking for trade-off analysis.*

**78. Strategy stress-test (red team)**
```
Red-team this strategy.

<strategy>[PASTE STRATEGY / PLAN SUMMARY]</strategy>

Attack it from four angles: (1) assumption failure — which load-bearing
assumption is least tested; (2) competitor response — what a smart
incumbent does in reaction; (3) execution risk — where the org lacks
capability; (4) macro/timing — what external shift breaks it. For each:
likelihood, impact, and an early indicator to monitor. End with the 2
changes that would most strengthen the plan.
```

**79. Board update writer**
```
Draft the CEO update for the board, [PERIOD].

<wins>[TOP 3 WINS WITH NUMBERS]</wins>
<misses>[WHAT MISSED AND WHY, HONESTLY]</misses>
<metrics>[PASTE KPI TABLE]</metrics>
<asks>[DECISIONS/INPUT NEEDED FROM BOARD]</asks>

Tone: candid, no spin — boards penalize surprises more than misses.
Structure: TL;DR → wins → misses + corrective action → metrics table →
market/team notes → asks. 500 words max.
```

**80. M&A / partnership screen**
```
Assess [TARGET/PARTNER] for [ACQUISITION / PARTNERSHIP / INVESTMENT].

<what_we_know>[PASTE FACTS + SOURCE OF EACH]</what_we_know>
<strategic_rationale>[WHY WE'RE INTERESTED]</strategic_rationale>

Deliver: strategic fit score (1–5) with justification; value-creation
hypothesis; top 5 diligence questions; integration risks; comparable
transactions (only if verified); and a recommendation: proceed to
diligence / watch / pass — with confidence level and what evidence
would change it.
```
*Pairs with: Research feature.*

**81. All-hands talking points**
```
Write talking points for an all-hands on [TOPIC — e.g., reorg, results,
new strategy].

<facts>[WHAT'S HAPPENING, WHEN, WHO'S AFFECTED]</facts>
<sentiment>[HOW PEOPLE LIKELY FEEL — anxious? skeptical?]</sentiment>

Deliver: opening (acknowledge reality, 30 seconds); 3 key messages with
supporting specifics; honest "what we don't know yet" section; 5
anticipated tough questions with suggested answers; closing commitment
with a concrete next update date. Plain language, no corporate euphemism.
```

**82. Scenario planning session**
```
Build a scenario plan for [BUSINESS/PRODUCT] over [HORIZON].

<uncertainties>[2 KEY UNCERTAINTIES — e.g., regulation, AI adoption rate]</uncertainties>
<current_position>[WHERE WE STAND]</current_position>

Create a 2×2 matrix from the two uncertainties; name and narrate each of
the 4 scenarios (5 lines each); for each: leading indicators, strategic
implications, and no-regret moves vs. contingent bets. End with which
scenario you'd plan around as the base case and why.
```
*Pairs with: extended thinking.*

---

### 11. Customer Support

**83. Empathetic response drafter**
```
Draft a support reply to this customer message.

<customer_message>[PASTE]</customer_message>
<account_context>[PLAN, HISTORY, KNOWN ISSUES]</account_context>
<resolution>[WHAT WE CAN OFFER — fix, refund, workaround, timeline]</resolution>

Structure: acknowledge the specific frustration (mirror their words,
not generic "sorry"); explain what happened in one plain sentence, no
blame-shifting; the resolution with exact next steps and timing; one
thing we're doing to prevent recurrence. Match their formality. Max
200 words. No "We value your feedback."
```

**84. Ticket triage classifier**
```
Classify this support ticket.

<ticket>[PASTE TEXT]</ticket>
<categories>[YOUR CATEGORY LIST — e.g., billing, bug, how-to, feature request]</categories>

Output: category; priority (P1–P4) based on [YOUR SEVERITY DEFINITIONS];
sentiment (frustrated/neutral/positive); whether escalation is needed
and to whom; suggested reply template name; and one-line summary for
the queue. If information is missing, list the single clarifying
question to ask first.
```
*Pairs with: routing workflow (Anthropic, "Building effective agents").*

**85. Help-center article**
```
Write a help-center article: "[TITLE — the task the user wants to do]".

<product_facts>[PASTE UI STEPS, CONSTRAINTS, ERROR MESSAGES]</product_facts>
<audience>[NEW USERS / ADMINS]</audience>

Structure: one-line answer up front; numbered steps with the exact
button/label names in **bold**; "If you see [ERROR]" troubleshooting
table; related articles (3, as [LINK] placeholders); last-reviewed date
placeholder. Every step verifiable — no "simply" or "just".
```

**86. Escalation summary**
```
Summarize this ticket thread for engineering escalation.

<thread>[PASTE FULL THREAD]</thread>

Produce: customer impact (who, how many, since when); reproduction steps
as reported; environment details mentioned; what support already tried
and the results; customer's explicit ask; urgency and SLA status; links
to [RELATED TICKETS]. Facts only — engineering needs signal, not
narrative.
```

**87. CSAT follow-up**
```
A customer gave us a [SCORE, e.g., 2/5] with this comment: "[COMMENT]".

<ticket_context>[WHAT HAPPENED]</ticket_context>

Write a follow-up from [ROLE — support lead]: own the specific failure
without groveling; state what we're changing (only if true); offer a
concrete make-good if policy allows [POLICY]; invite a 15-minute call.
Max 120 words. If the comment reveals a systemic issue, add an internal
escalation note separately.
```

**88. Macro / template library builder**
```
Create 5 reusable reply macros for our top support scenario: [SCENARIO].

<policy>[WHAT AGENTS CAN/CANNOT OFFER]</policy>
<voice>[BRAND VOICE NOTES OR EXAMPLES]</voice>

Variants: (1) quick fix confirmed; (2) fix + workaround pending; (3)
can't do it, with alternative; (4) need more info (asks exactly 3
questions); (5) escalation notice with timeline. Each: [CUSTOMER NAME]
and [DETAILS] placeholders, under 150 words, ends with a named human
signature block.
```

---

### 12. Admin & Governance

> Note: prompts here support — never replace — admin judgment. Audit-log interpretation and access decisions require human review. Enterprise features cited (SSO/SAML, SCIM, RBAC, audit logs, Compliance API) are as of August 2026 — verify current documentation.

**89. Access-review summarizer**
```
Help me run a quarterly access review.

<user_list>[PASTE: name, role, workspace role/permission, last active]</user_list>
<policy>[e.g., least-privilege, deactivate after 90 days inactive, admin only for X]</policy>

Output a table: User | Current access | Policy issue (if any) |
Recommended action (keep/downgrade/deactivate) | Manager to confirm.
Flag anomalies: role drift, dormant admins, mismatched titles. Never
auto-approve changes — this is a review aid only.
```
*Pairs with: Compliance API exports as input; audit logs (180-day, metadata-only) for activity checks.*

**90. Audit-log query helper**
```
Interpret this audit-log export / help me query it.

<logs>[PASTE SAMPLE ROWS OR SCHEMA]</logs>
<question>[e.g., "Who exported workspace data last week?"]</question>

Deliver: the filtering logic or query to answer the question; the
events most relevant and why; patterns that warrant follow-up; and the
limits of what these logs can prove (metadata-only — content is not
logged). Suggest the retention/reporting cadence to catch this earlier
next time.
```

**91. Acceptable-use policy explainer**
```
Turn our AI acceptable-use policy into guidance employees will actually read.

<policy>[PASTE POLICY — e.g., what data can/can't go into AI tools]</policy>

Create: a 1-page "Do / Don't" table with concrete examples per rule
(e.g., "Customer PII → don't paste into unapproved tools"); a 60-second
version for onboarding; 5 realistic gray-area scenarios with the correct
call and why; and where to ask questions. Plain language; no legalese.
```

**92. Onboarding checklist generator**
```
Build a Claude onboarding checklist for new [ROLE — e.g., analyst,
engineer, support rep].

<tool_setup>[OUR PLAN, SEATS, PROJECTS/CONNECTORS THEY NEED]</tool_setup>
<first_week_goals>[WHAT GOOD LOOKS LIKE IN WEEK 1]</first_week_goals>

Output: day-1 setup steps (account, SSO, browser/desktop apps); which
Projects and connectors to join and why; 3 role-specific first prompts
to try; guardrails to read; who to ask for help. Format as a checklist
a manager can paste into a ticket.
```

**93. Usage-report narrative**
```
Turn this usage export into an adoption report for leadership.

<usage_data>[PASTE: seats, active users, top use cases if visible,
spend]</usage_data>
<program_goals>[WHAT WE TOLD LEADERSHIP WE'D ACHIEVE]</program_goals>

Structure: adoption trend (activated vs. licensed seats); usage
highlights by team; estimated time saved (only if measurable — label
estimates clearly); spend vs. budget; 3 recommended actions to raise
adoption. Never present metadata as proof of productivity.
```
*Pairs with: spend controls / analytics exports; code execution for charts.*

**94. Incident comms (admin tooling)**
```
Draft internal comms for an AI-platform incident: [e.g., connector
outage, policy misconfiguration, unexpected spend spike].

<incident>[WHAT HAPPENED, WHEN DETECTED, WHO/WHAT AFFECTED, STATUS]</incident>

Two versions: (1) IT/security channel — technical detail, timeline,
workaround, next update time; (2) all-users — plain language, what to
do differently today, reassurance on data exposure status (state only
what is confirmed). Mark unconfirmed items as [VERIFYING].
```

---

### 13. Meta-Prompts (prompts that improve your prompts)

**95. Prompt generator**
```
You are an expert prompt engineer for Claude. Turn my rough task
description into a production-ready prompt.

<task_description>[DESCRIBE WHAT YOU WANT, MESSY IS FINE]</task_description>
<context>[WHO USES IT, HOW OFTEN, IN WHAT PRODUCT/WORKFLOW]</context>

Produce a structured prompt with: <background_information>,
<instructions> (numbered steps), <input> placeholders in [BRACKETS],
an ## Output description section, and 2–3 <example> blocks showing
ideal input/output. Then list 3 questions whose answers would improve
the prompt further.
```
*Pairs with: the Console "Generate a Prompt" tool, which does this interactively (Anthropic Console, Jul 2026).*

**96. Prompt critic**
```
Critique my prompt. Apply Anthropic's guidance: clarity ("would a new
colleague be confused?"), explicit output format, positive instructions
over negative ones, XML structure where content types mix, and no
contradictory or brittle rules.

<my_prompt>[PASTE YOUR PROMPT]</my_prompt>
<what_went_wrong>[PASTE BAD OUTPUT OR DESCRIBE THE FAILURE]</what_went_wrong>

Deliver: the top 3 weaknesses with quoted evidence from the prompt; a
revised version; and a test plan — 3 varied inputs to run before
trusting it.
```

**97. Role / system-prompt designer**
```
Design a system prompt for a Claude assistant with this job:

<job>[e.g., "legal intake triage for a 50-person startup"]</job>
<tone>[VOICE AND FORMALITY]</tone>
<boundaries>[WHAT IT MUST NEVER DO, STATED POSITIVELY WHERE POSSIBLE]</boundaries>
<tools>[FEATURES AVAILABLE — Projects, connectors, code execution]</tools>

Write the system prompt using sections: <background_information>,
<instructions>, ## Tool guidance, ## Output description. Aim for the
right altitude: heuristics and judgment guidance, not brittle if-else
rules. Keep it under 400 words; every sentence must earn its place.
```
*Based on Anthropic's recommended system-prompt anatomy (Anthropic Engineering, Sept 2025).*

**98. Few-shot example builder**
```
Create few-shot examples to steer this task.

<task>[DESCRIPTION + CURRENT PROMPT IF YOU HAVE ONE]</task>
<good_output_sample>[PASTE ONE EXAMPLE OF IDEAL OUTPUT]</good_output_sample>

Generate 3 additional diverse <example> blocks (different input types,
including one edge case) that together cover the output space without
becoming a laundry list. Wrap them in <examples> tags ready to paste.
Explain in 2 lines what each example teaches the model.
```

**99. Prompt-chain architect**
```
Design a prompt chain for this multi-step task: [TASK].

<constraints>[QUALITY BAR, LATENCY/COST BUDGET]</constraints>

Decompose into 2–4 sequential LLM calls. For each step: its prompt
(sketched), its input from the prior step, and a "gate" check a human
or program applies before continuing (e.g., "outline approved?").
Tell me which step is most likely to fail and how the gate catches it.
```
*Based on Anthropic's prompt-chaining pattern — fixed subtasks with programmatic gates (Anthropic Engineering, "Building effective agents").*

**100. Eval designer**
```
Design a lightweight evaluation for this prompt before we ship it.

<prompt>[PASTE PROMPT]</prompt>
<success_criteria>[WHAT GOOD OUTPUT LOOKS LIKE]</success_criteria>

Produce: 8 test cases (typical, boundary, adversarial, and one with
missing info); a 1–5 scoring rubric per success criterion with anchors;
and a pass threshold. Format test cases as a table I can paste into a
spreadsheet. Include one regression rule: what must stay true after
any prompt edit.
```

**101. Context curater (long-document setup)**
```
I'm about to give Claude a large body of material to work on: [TASK].

<materials>[LIST THE DOCUMENTS/DATA SOURCES]</materials>

Advise: which materials actually need to be in context (apply the
"smallest set of high-signal tokens" principle); how to order them
(long documents first, query last); what to summarize vs. paste raw;
what to tag with XML and how; and whether this belongs in a Project,
a Research run, or a prompt chain instead of one big prompt.
```
*Based on Anthropic's context-engineering guidance (Anthropic Engineering, Sept 2025).*

**102. Thinking / effort tuner**
```
Help me configure reasoning for this task: [TASK].

<observed_behavior>[e.g., shallow answers / slow responses / overthinking]</observed_behavior>

Recommend: the effort level (recall: `xhigh` for coding/agentic, minimum
`high` for intelligence-sensitive work, `max` may overthink); whether
thinking adds value here or whether direct answering is better; and the
one line to add to my prompt to steer thinking behavior (e.g., "After
receiving tool results, reflect on their quality before proceeding").
If the fix is raising effort rather than more prompting, say so plainly.
```
*Per Anthropic effort-parameter guidance (Anthropic Docs, Jul 2026) — as of August 2026, verify current model defaults.*

---

**Try it.** Pick one prompt from your daily-work category. Run it as-is on a real task, then run #96 (Prompt critic) against your result. Finally, save the improved version into a Project so your team shares one maintained copy rather than forking private variants.


---
