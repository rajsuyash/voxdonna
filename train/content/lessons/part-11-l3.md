### 9.8 Structured Output Techniques

**Prefilled assistant responses are no longer supported starting with Claude 4.6 models** — the last-turn prefill trick (seeding `{"` to force JSON) returns a 400 error on current models (Anthropic Docs — Prompting best practices). Migration paths:

| Old technique (≤4.5) | Current practice (4.6+) |
|---|---|
| Prefill `{` to force JSON/YAML | **Structured Outputs** (GA) — enforce schema server-side |
| Prefill to skip preamble | System instruction: "Respond directly without preamble..." |
| Prefill to continue a partial completion | Move the partial text into the user message and ask for continuation |

Older Anthropic pages and third-party guides describing prefill-based "JSON mode" are outdated for current models — treat them as historical.

For general format control, Anthropic's hierarchy (Docs — Prompting best practices):

1. **Tell Claude what TO do, not what not to do.** "Your response should be composed of smoothly flowing prose paragraphs" beats "Do not use markdown."
2. Use **XML format indicators** (`<report>`, `<summary>`) to mark output regions.
3. **Match your prompt style to the desired output style** — a prompt written in terse bullet points invites terse bulleted output.
4. Be detailed about formatting preferences rather than hoping for defaults.

---

### 9.9 Long-Context Prompting

For inputs of 20k+ tokens, Anthropic documents three techniques with measurable effects (Anthropic Docs — Prompting best practices):

1. **Documents first, query last.** Put longform data at the *top* of the prompt, above your query, instructions, and examples. "Queries at the end can improve response quality by up to 30 percent in tests." This is one of the few prompting changes with a published effect size — adopt it everywhere.
2. **Structure with XML tags** using the `<document>`/`<document_content>`/`<source>` pattern from §9.5.
3. **Quote-grounding.** Ask Claude to first quote the relevant parts of the documents (e.g., in `<scratchpad>` tags), then perform the task. Grounding the answer in extracted quotes reduces hallucination on long documents.

> **Caveat (Medium confidence):** An open GitHub issue on Anthropic's tutorial argues the anti-hallucination effect comes from the metacognitive instruction (consider whether the evidence answers the question) rather than evidence-gathering per se. Anthropic has not resolved the dispute; the combined quote-then-answer pattern remains the official recommendation.

For multi-window workflows (large agentic coding tasks): use the first window for framework setup (tests, init scripts), have the model write tests in structured formats, use git for state tracking, and provide verification tools (e.g., a browser-testing MCP server).

A worked long-context skeleton, combining all three techniques:

```xml
<documents>
  <document index="1">
    <source>vendor-contract-2026.pdf</source>
    <document_content>...</document_content>
  </document>
</documents>

<instructions>
  First, inside <scratchpad> tags, quote the exact passages relevant to the
  question below. Then answer based only on those quotes, citing the document
  index for each claim.
</instructions>

<question>What liability caps apply to data breaches under this contract?</question>
```

Note the ordering: documents at the top, the actual query at the very bottom — the single change associated with the up-to-30% quality gain.

---

### 9.10 The Prompt Generator and Metaprompt

You don't have to write structured prompts by hand. Anthropic's **prompt generator** in the Console Dashboard ("Generate a Prompt") converts a plain-language task description into a structured, XML-tagged prompt — typically producing a skeleton with `<scratchpad>` reasoning space, an `<outline>` stage, and a full draft section with explicit style rules for long-form writing. Treat the output as a first draft you edit, not a finished artifact.

For programmatic use, Anthropic maintains a **metaprompt notebook** (`misc/metaprompt.ipynb`) in the anthropic-cookbook GitHub repo, alongside `generate_test_cases.ipynb` and `prompt_caching.ipynb` — a "prompt that writes prompts" plus the eval scaffolding to test them.

> **Confidence note (Medium-High):** the cookbook notebook paths are indexed from repository documentation rather than fetched line-by-line; the Console prompt generator itself is High confidence. Verify exact notebook filenames against the current repo if you build a course exercise on them.

Two craft details from Anthropic's interactive tutorial are worth institutionalizing when you use generated prompts: scrub prompts for typos (small details matter — Claude is, in the tutorial's phrasing, "smarter when you sound smart"), and beware ordering bias — when you offer Claude two options in a prompt, it is more likely to pick the second. Audit generated prompts for accidental option-ordering before shipping them.

---

### 9.11 Prompt Libraries and Reusable Templates

Anthropic's Prompt Library (docs.anthropic.com/en/prompt-library/library) contains dozens of optimized prompts across work and play categories (Website Wizard, Excel Expert, Lesson Planner, and so on), each split into a **System** and **User** prompt — itself a lesson in template anatomy. A well-built reusable template has:

1. **A system prompt** holding role, stable instructions, and output contract.
2. **A user template** with clearly marked variable slots (`{{customer_message}}`) wrapped in XML tags.
3. **3–5 canonical few-shot examples** demonstrating the contract.
4. **An eval set** — the inputs and expected outputs that define "working."

Store templates in version control, treat changes like code changes, and re-run the eval set after any model upgrade — the 4.x → 5-series migration changed how several instructions behave (see §9.13).

:::exercise Try it #2
Pick one prompt from Anthropic's Prompt Library closest to your team's work. Run it as-is on three real inputs, then rewrite it as a reusable template with the four-part anatomy above. Where the library prompt conflicts with current 5-series guidance (e.g., prescriptive step-by-step reasoning), modernize it and note the difference in output.
:::

---

### 9.12 Vision Prompting

Claude's single most important vision rule (Anthropic Docs — Vision, fetched Aug 2026):

> Claude works best when images come before text.

Place the image(s) ahead of your question — the visual analogue of "documents first, query last." For multiple images in one request, label each (`Image 1:`, `Image 2:`) so you can reference them by name in the prompt and follow-ups.

Quality and limits (as of August 2026 — verify): images up to 8000×8000 px; ~28×28 px per visual token; up to 100 images per request on 200k-context models (600 on others). Ensure text in images is legible — automatic resizing and lossy JPEG/WebP compression can silently degrade it, so inspect the actual images sent. Known limitations: no person identification, approximate spatial coordinates and counting, errors on low-quality, rotated, or sub-200px images. For detail-heavy work, giving Claude a **crop tool** to zoom into regions shows "consistent uplift on image evaluations," with a published cookbook recipe.

---
