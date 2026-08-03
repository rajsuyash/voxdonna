### 9.13 The 12 Most Common Prompt Mistakes (and the 5-Series Myth Table)

Anthropic's documentation and engineering blog collectively flag a dozen recurring failure modes. Each below is stated with its fix.

1. **Vague, under-specified prompts.** Fails the Golden Rule. Fix: specificity about output, constraints, and audience.
2. **Negative instructions.** "Do not use markdown" → "Write smoothly flowing prose paragraphs." Tell Claude what *to* do.
3. **Bloated tool sets with ambiguous decision points.** "If a human engineer can't definitively say which tool should be used, an AI agent can't be expected to do better." Fix: prune tools, add explicit tool-choice heuristics.
4. **Laundry lists of edge-case examples.** Fix: 3–5 diverse canonical examples.
5. **Brittle hardcoded if-else logic in system prompts.** Fix: right-altitude heuristics.
6. **Overly vague system prompts.** The opposite altitude failure. Fix: concrete behavioral guidance.
7. **Contradictory instructions left unresolved.** Claude will try to follow both. Fix: audit for conflicts; state precedence explicitly.
8. **Aggressive trigger language.** "CRITICAL: You MUST ALWAYS use tool X..." causes over-triggering on newer models. Fix: calm, conditional heuristics.
9. **Legacy anti-laziness prompting.** Instructions written to stop 3.x/4.x models from under-triggering or under-thinking cause over-triggering and overthinking on 4.6+/5-series. Fix: delete them; raise effort instead.
10. **Overengineering (agentic coding).** Anthropic ships sample prompts against it: "Avoid over-engineering. Only make changes that are directly requested..." Fix: scope instructions explicitly.
11. **Test-gaming / hardcoding.** Fix: "Implement a solution that works correctly for all valid inputs, not just the test cases."
12. **Speculating about unseen code.** Fix: "Never speculate about code you have not opened" — require reading before editing.

#### Myth vs. current practice

Much pre-2026 prompting folklore is now counterproductive on 5-series models. Use this table when migrating old prompts or reviewing inherited ones:

| Pre-2026 folklore | Current practice (5-series, as of Aug 2026) |
|---|---|
| Hand-write a detailed step-by-step reasoning plan into the prompt | "Think thoroughly" — general instructions beat prescriptive steps; Claude's reasoning exceeds human scripts |
| Prefill the assistant turn (`{"`) to force JSON | Structured Outputs (GA); prefill returns 400 on 4.6+ |
| Tune `budget_tokens` for thinking, "start minimal and increase" | Adaptive thinking + `effort` ladder; `budget_tokens` returns 400 on 4.7+ |
| Add "double-check your answer" everywhere | Causes over-verification on Opus 5; remove when migrating |
| Use "CRITICAL/MUST/ALWAYS" to force tool use | Causes over-triggering; use conditional heuristics |
| Anti-laziness prompts ("don't be lazy, write the full file") | Causes overthinking on current models; raise effort instead |
| Disable thinking and prompt manual CoT for hard tasks | Keep adaptive thinking on at effort `high`/`xhigh`; manual CoT is the fallback, not the default |
| Elaborate prompt formatting is load-bearing | Formatting matters less as models improve; structure prompts for clarity and maintainability |

:::exercise Try it #3
Find a prompt in your organization written before 2026 (or write one using the folklore column above: step-by-step reasoning script, CRITICAL language, "double-check" instructions). Run it on five test inputs with a 5-series model at default effort. Then apply the migration table: delete legacy instructions, switch reasoning to "think thoroughly," and set effort to `high` or `xhigh`. Re-run and compare — most teams see the simplified prompt match or beat the original while being a third of the length.
:::

---

### 9.14 Chapter Summary

Prompt engineering for current Claude models reduces to a few durable disciplines: define success criteria and evals before tuning; write clear, right-altitude system prompts in clean sections; treat context as a finite budget and engineer it deliberately (compaction, note-taking, subagents, just-in-time retrieval); use roles, XML structure, 3–5 canonical examples, and quote-grounding; put documents and images before questions; and — above all — prompt for the adaptive-thinking era. General reasoning instructions, the effort ladder, and Structured Outputs replace the step-by-step scripts, budget tuning, and prefill tricks of the pre-2026 playbook. When in doubt, simplify the prompt and raise the effort.


---
