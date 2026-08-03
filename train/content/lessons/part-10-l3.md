#### 4. Product Management

**Recommended setup.** Team or Enterprise; Projects per product with PRDs and roadmaps in knowledge; connectors for Jira, Linear, Slack, Confluence (Connectors are remote MCP servers; Directory GA since Jul 2025); Research for market scans; Artifacts for one-pagers and roadmaps you can share and let colleagues remix.

**Example prompt.**

```
<context>Attached: Q3 roadmap, last 4 sprint retros, top 20 support tickets.</context>
<instructions>
1. Cluster the support tickets by theme with counts.
2. Map each cluster to roadmap items; flag roadmap items no ticket mentions.
3. Recommend three scope changes with a one-paragraph rationale each,
   citing ticket clusters by number.
</instructions>
Deliver as a Markdown artifact.
```

**Best practices.** Keep durable context in the Project rather than re-pasting it; use the analysis/code execution tool (GA, all plans) for ticket-volume math; share PRDs as published Artifacts for comment-driven iteration.

**Common mistakes.** Asking for prioritization without supplying the evidence base (Claude cannot invent your ticket data); skipping the quote-then-analyze grounding step on long backlogs; ignoring file limits — XLSX exports require code execution enabled, and PPTX cannot be *input* at all (Anthropic Docs — file support).

#### 5. Marketing

**Recommended setup.** Pro or Team; a Custom Style per brand voice; a Project with brand guidelines, persona docs, and 3–5 exemplar assets; Google Drive connector for asset libraries; Artifacts for drafts and Mermaid campaign diagrams.

**Example prompt.**

```
<task>Write 5 variants of a launch email for <product>.</task>
<persona>IT directors at 500–2,000-seat companies, skeptical of AI hype.</persona>
<constraints>Max 120 words each; one CTA; no superlatives without proof;
match the voice in <examples>.</constraints>
<examples>[2 approved past emails]</examples>
Then, as a separate step, translate the winning variant into German.
```

**Best practices.** The generate-then-translate chain above is Anthropic's own canonical prompt-chaining example (Anthropic Engineering, Dec 2024). Use evaluator-optimizer for high-stakes assets: define scoring criteria (clarity, on-brand, CTA strength) and loop generate → score → regenerate. Curate canonical examples rather than edge-case lists.

**Common mistakes.** One mega-prompt asking for all channels at once; style instructions phrased as prohibitions; A/B variants with no persona or constraints, which produces interchangeable mush.

#### 6. UX

**Recommended setup.** Figma connector (remote MCP) to pull design context; Artifacts (React/HTML, GA) for interactive prototypes you can publish; image uploads (≤8000px) for screenshot critique — put images *before* text in the prompt and label them (`Image 1:`) so you can reference them; consider a crop/zoom tool for detail inspection, which Anthropic reports gives consistent uplift on image evaluations (Anthropic Docs — Vision).

**Example prompt.**

```
Image 1: [checkout screenshot]  Image 2: [confirmation screenshot]
You are a senior UX reviewer. For each image, quote the specific UI text or
element you are critiquing, then give severity-ranked findings for the
checkout flow against WCAG-minded heuristics. End with the three highest-
impact fixes.
```

**Best practices.** Ground critique in quoted elements before generalizing; iterate on a single Live Artifact prototype rather than regenerating from scratch each round; keep prompts task-focused rather than prescribing a rigid heuristic checklist when the model's judgment suffices.

**Common mistakes.** Text-before-image ordering (weaker results); uploading tiny or blurry screenshots — images under ~200px and illegible text are documented error sources; expecting person identification or exact spatial coordinates, which are known vision limitations.

#### 7. Legal

**Recommended setup.** Team or Enterprise (no training on customer data by default; Enterprise adds data-retention controls, audit logs, and the Compliance API); Projects per matter with 500K Enterprise project context; long-document prompting discipline.

**Example prompt.**

```
<document><source>MSA-v4-final.pdf</source>
<document_content>[contract text]</document_content></document>
<instructions>
1. In <scratchpad>, quote every clause touching liability, indemnification,
   or termination, with section numbers.
2. Then compare quoted clauses against our standard positions (attached) and
   flag deviations in a table: clause, our position, deviation, risk level.
Do not summarize clauses you did not quote.
</instructions>
```

**Best practices.** Quote-first extraction is Anthropic's documented anti-hallucination technique for long documents: extract relevant quotes in `<scratchpad>`, then answer (Anthropic prompt-eng tutorial, Ch. 8). Put documents at the top of the prompt, questions at the end. Wrap multiple documents in `<document>` tags with `<source>` metadata.

**Common mistakes.** Asking for conclusions without the quote step; exceeding the PDF vision limit — PDFs up to 100 pages get vision+text, 101–1000 pages are text-only (as of Aug 2026 — verify); uploading PPTX or ZIP archives, which are not supported inputs; treating Claude's output as legal advice rather than attorney work product support.

#### 8. Sales

**Recommended setup.** Team; Salesforce and HubSpot connectors plus Slack; Projects per account or segment with call notes; memory (GA, all plans since Mar 2026) for your messaging preferences; voice mode (Beta) for talk-through prep.

**Example prompt.**

```
Using the attached call notes and the account record from Salesforce:
1. Summarize the customer's stated pain points in their own words (quote them).
2. Map each pain point to one product capability with a one-line proof point.
3. Draft a 150-word follow-up email: reference their words, one ask, no jargon.
```

**Best practices.** Ground personalization in quoted customer language; keep one Project per major account so context accumulates across touches; use Research for pre-call account briefs on public information.

**Common mistakes.** Generic outreach with no account context (fails the Golden Rule); pasting CRM exports as XLSX without enabling code execution; letting Claude fabricate proof points — supply them or forbid unverified claims explicitly.
