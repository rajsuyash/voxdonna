---
title: "Is Your Company Ready for AI? A 20-Point Readiness Assessment"
description: "Most companies start AI projects before they are ready for them. This 20-point assessment tells you exactly where your organization stands — and what to fix before you spend a dollar on AI."
date: "2026-07-18"
category: "AI Strategy"
readingTime: "9"
keywords: "AI readiness assessment, AI readiness checklist, company ready for AI, AI adoption checklist, AI implementation readiness, organizational AI readiness, enterprise AI readiness, AI strategy assessment"
---

# Is Your Company Ready for AI? A 20-Point Readiness Assessment

## Why Most AI Projects Start Too Early

Accenture's research on AI maturity found that only 12% of companies qualify as what they call "AI Achievers" — organizations that demonstrate advanced capabilities across both technical foundations and strategic execution. The remaining 88% are experimenting, building in isolation, or stuck somewhere between intent and deployment.

The reason most AI projects underperform is not that the technology fails. It is that organizations deploy AI into conditions that guarantee a difficult outcome: unclear processes, poor data quality, undefined success metrics, and no governance structure to catch problems before they compound. Fixing these conditions after deployment is far more expensive than addressing them before.

This assessment is designed to tell you, before you begin, whether your organization has the conditions in place that AI projects require to succeed.

---

## How to Use This Assessment

Work through the 20 checkpoints below. For each one, score your organization honestly:

- **2 points**: Yes — this is well established and documented
- **1 point**: Partial — this exists but inconsistently or informally
- **0 points**: No — this is absent or not yet started

Add your total. The scoring guide at the end tells you what the number means and where to focus remediation.

---

## Section 1: Data Foundation (8 points)

AI runs on data. Before any model can be trained, tuned, or deployed, the underlying data needs to be accessible, clean, and well-governed. Deloitte's survey of enterprise AI adopters found that "modernizing data infrastructure for AI" ranked as the top initiative for competitive advantage — and that fewer than 45% of organizations rated themselves as having strong capabilities in integrating AI into existing IT environments.

**1. Our primary business data is stored in structured, queryable systems — not locked in spreadsheets, PDFs, or email threads.**

*Why it matters:* AI systems need data they can read programmatically. If the information required for your target use case sits in formats that require manual extraction, that extraction becomes your first project — often larger than the AI work itself.

**2. We have a defined data owner for each major dataset we would use in an AI project.**

*Why it matters:* Data without ownership degrades. When no one is accountable for a dataset's accuracy and freshness, quality problems go undetected until they surface in production. Accenture found that AI leaders are far more likely to have formal data governance in place than laggards.

**3. We know the error rate in our most critical datasets and have a process to address data quality issues.**

*Why it matters:* AI models amplify whatever patterns exist in training data — including errors. If you do not know your current data quality baseline, you cannot predict how much of your AI project timeline will be consumed by data cleaning rather than model development.

**4. Customer and operational data from different systems can be linked to a common entity (customer ID, order ID, etc.) without manual reconciliation.**

*Why it matters:* Most valuable AI applications require joining data across systems — CRM, ERP, telephony, support tickets. If your systems do not share a common key, you are missing the joins that make AI outputs useful.

---

## Section 2: Process Clarity (4 points)

AI cannot automate a process that is not understood. Before deploying automation, you need to know what the current process actually is — not what the SOP says it is, but what people actually do.

**5. The process we want to automate is documented, with defined inputs, outputs, decision points, and exception handling.**

*Why it matters:* Undocumented processes mean that whoever built the automation is guessing at edge cases. Those guesses become bugs. PwC's analysis found that technology delivers only about 20% of an AI initiative's value — the other 80% comes from redesigning the underlying work. You cannot redesign what you have not mapped.

**6. We can measure the current performance of this process — volume, cycle time, error rate, and cost per unit.**

*Why it matters:* This is the baseline problem described in any serious AI ROI methodology. Without current-state metrics, you cannot set performance targets for the AI system, and you cannot demonstrate improvement after deployment. See our article on [calculating AI automation ROI](/blog-post.html?post=ai-automation-roi-calculation-guide&lang=en) for the full framework.

**7. The people who run this process today are involved in defining what the AI system should do.**

*Why it matters:* The team that runs a process holds the institutional knowledge of its edge cases, exceptions, and unstated rules. AI projects that exclude operators from design consistently encounter failure modes that frontline staff could have predicted.

---

## Section 3: Organizational Alignment (4 points)

Technical readiness is necessary but not sufficient. Accenture's research found that 83% of AI Achievers have formal senior sponsorship for their AI programs, versus 56% of organizations that struggle. Sponsorship is not enthusiasm — it is active budget authority, decision-making accountability, and willingness to intervene when the project hits obstacles.

**8. There is a named executive sponsor for this AI initiative with clear accountability for its business outcomes.**

*Why it matters:* AI projects that lack executive sponsorship get deprioritized when they compete for integration resources from IT, when procurement negotiations stall, and when change management becomes difficult. Projects with a sponsor who owns the business outcome do not wait in queue.

**9. We have defined what success looks like for this project — in measurable business terms, not technical metrics.**

*Why it matters:* "The model achieves 90% accuracy" is a technical metric. "Customer wait time drops from 4 minutes to under 30 seconds" is a business outcome. The latter is what justifies the investment and what determines whether the project gets expanded or cancelled.

**10. The budget for this project includes the full cost of deployment — not just software licensing, but implementation, integration, change management, and at least 12 months of operation.**

*Why it matters:* Most AI project cost overruns come from underestimating the non-licensing costs. If the budget only covers the vendor's fee, the project will need supplemental funding at the worst possible moment — mid-deployment. For a detailed breakdown of the 8-cost-component model, see our [AI ROI calculation guide](/blog-post.html?post=ai-automation-roi-calculation-guide&lang=en).

**11. Our leadership team has a shared, accurate understanding of what AI can and cannot do at our current scale and with our current data.**

*Why it matters:* AI projects fail when leadership expects capabilities the technology does not yet have, then loses confidence when the first deployment underperforms those expectations. Misaligned expectations destroy good projects faster than technical problems do. Our [AI adoption roadmap](/blog-post.html?post=ai-adoption-roadmap-midsize-business&lang=en) covers how to calibrate expectations across the leadership team.

---

## Section 4: Technical Infrastructure (2 points)

**12. Our existing systems have APIs or documented integration points that a new AI system could connect to.**

*Why it matters:* AI does not operate in isolation. It reads from and writes to your existing systems — your CRM, your scheduling software, your telephony platform, your ERP. If your systems are closed or undocumented, every integration becomes a custom engineering project. Build-vs-buy decisions for AI depend heavily on how integrable your existing stack is. See our [build vs. buy framework](/blog-post.html?post=build-vs-buy-ai-automation&lang=en) for a structured decision process.

**13. We have someone with technical authority — an internal IT lead or trusted external partner — who will own the technical implementation of this project.**

*Why it matters:* AI vendor deployments still require someone on your side who can evaluate vendor claims, manage integration work, and maintain the system post-deployment. Organizations that outsource technical judgment entirely to vendors consistently encounter scope creep, integration delays, and systems they cannot troubleshoot when problems emerge.

---

## Section 5: Risk and Governance (2 points)

Deloitte found that only 35% of organizations maintain formal inventories of their deployed AI models and systems. Only 28% have a single executive responsible for AI risks. These are not academic governance concerns — they are the conditions that allow AI failures to go undetected until they have caused real harm.

**14. We have a defined policy for how AI outputs will be reviewed before they affect customers or trigger business actions.**

*Why it matters:* Even high-performing AI systems make errors. The question is whether those errors are caught by a human review step before they become customer-facing problems. Organizations that skip human-in-the-loop design for new deployments are betting that the system will never produce a consequential error. That bet does not pay.

**15. We understand the regulatory and compliance requirements that apply to using AI in this use case and jurisdiction.**

*Why it matters:* Fifty-seven percent of AI adopters in Deloitte's survey worried about regulatory uncertainty's impact on AI initiatives. The regulatory environment for AI is evolving in the EU (AI Act), in the US (sector-specific guidance), and in sector-specific contexts like financial services and healthcare. Deploying without understanding compliance requirements creates remediation costs that dwarf initial deployment costs.

---

## Section 6: Change Management (4 points)

Accenture found that 78% of AI Achievers mandate AI training for most employees. This is not because AI requires everyone to become a data scientist — it is because AI changes how work gets done, and people who do not understand what AI is doing in their workflow cannot catch errors, cannot provide useful feedback, and often undermine adoption out of distrust.

**16. The team members whose work will change when this AI is deployed know about the project, understand the reasons for it, and have had the opportunity to ask questions.**

*Why it matters:* Surprise deployments — where teams learn about an AI system when it goes live — produce resistance, workarounds, and deliberate disengagement. Early, honest communication about what is changing and why is the single most cost-effective change management investment.

**17. We have a plan for what team members currently doing this work will do differently after the AI is deployed.**

*Why it matters:* If the AI automates a task that currently occupies 40% of a team member's time, what does that 40% become? If you do not have an answer, the people doing that work do not have one either — which creates anxiety, reduced morale, and passive resistance to adoption.

**18. We have a feedback mechanism for team members to report AI errors or edge cases they encounter.**

*Why it matters:* The people working alongside an AI system every day are its most valuable quality-monitoring resource. Organizations that build no feedback channel lose this signal and learn about systematic errors only when they have escalated to customer complaints or operational disruptions.

---

## Section 7: Build on Prior Learning (2 points)

**19. We have documented what we learned from previous technology or process change initiatives — what worked, what did not, and why.**

*Why it matters:* Organizations that cannot recall the lessons of their last ERP implementation, CRM deployment, or process redesign initiative will repeat the same mistakes in their first AI project. AI implementations share structural features with all large technology deployments. Prior learning compounds.

**20. We have identified two or three people in our organization who will serve as internal champions for this AI initiative — people who are respected by their peers and genuinely interested in the technology.**

*Why it matters:* Internal champions are more effective change management tools than any training program. When a skeptical colleague sees a peer they respect using an AI system effectively, that observation moves more than a company-wide mandate. Identifying and equipping champions before deployment is an investment that consistently outperforms post-deployment remediation.

---

## Scoring Guide

| Score | Readiness Level | Interpretation |
|---|---|---|
| **35–40** | Ready to proceed | You have the foundational conditions in place. Select a well-scoped first use case and begin. |
| **27–34** | Ready with remediation | You have most conditions in place. Address your 0-score items before committing to a full deployment timeline. |
| **19–26** | Partial readiness | Proceed only with a limited pilot in a low-stakes area. Use the pilot period to address gaps. |
| **11–18** | Pre-readiness | Invest in foundational work — data quality, process documentation, leadership alignment — before starting any AI project. |
| **0–10** | Not ready | Do not start. Organizational conditions for AI success are not present. Address the root causes first. |

---

## The Five Most Common Readiness Gaps

In practice, the checkpoints organizations most consistently score zero on are:

**Data ownership (Checkpoint 2).** Most organizations have data. Almost none have clearly assigned ownership of that data's quality and governance. This is remediable — it requires a decision, not a technology investment.

**Current-state process metrics (Checkpoint 6).** Organizations want AI to improve their processes but have not measured those processes. This creates an evaluation problem that surfaces at the worst moment — when someone asks whether the deployment was worth it.

**Realistic leadership expectations (Checkpoint 11).** Leadership teams that have absorbed AI marketing but not AI limitations will hold the deployment to standards the technology cannot yet meet. Calibrating expectations before the project starts is the responsibility of the person proposing the investment.

**Human review policy (Checkpoint 14).** New AI deployments almost universally benefit from a human review layer, at least initially. Organizations that skip this because they trust the vendor's accuracy claims consistently encounter errors that the review layer would have caught.

**Team communication (Checkpoint 16).** Of all the change management failures in AI deployment, the most preventable is the one where affected teams learn about the system when it goes live. It takes one conversation. Most organizations skip it.

---

## Using This Assessment Across Multiple Initiatives

If you are evaluating several potential AI use cases simultaneously, run this assessment for each one. The scores will differ — not because your organization changes, but because each use case sits in different process conditions, involves different data, and affects different teams.

A use case that scores 38 on this assessment is a better first AI project than one that scores 22, regardless of the theoretical business value of the second use case. The organization that builds one successful AI deployment before attempting a second one develops capabilities — in change management, technical integration, and data governance — that compound across subsequent projects. See our framework for [choosing your first AI project](/blog-post.html?post=ai-adoption-roadmap-midsize-business&lang=en) for a complementary decision-making model.

---

## FAQ

**What score should we aim for before starting?**
A score of 27 or above indicates sufficient readiness to proceed with appropriate care. A score of 35 or above indicates conditions that support a confident deployment. If you score below 27, the time spent addressing readiness gaps will be recovered many times over in reduced implementation friction.

**How long does it take to address readiness gaps?**
It depends on which gaps you have. Data ownership assignments and process documentation can be completed in weeks. Rebuilding data infrastructure or achieving leadership alignment on AI capabilities may take months. The assessment tells you what to fix; the timeline depends on your organizational pace.

**Should every department score separately?**
Yes, if you are deploying AI across multiple departments. The data conditions, process clarity, and change management readiness of your customer service team are not the same as those of your finance team. Treat each deployment area as a separate readiness assessment.

**What if we score highly but our first AI project still fails?**
Readiness reduces failure risk; it does not eliminate it. AI projects can still encounter vendor underperformance, integration problems, or market changes that alter the business case. High readiness scores improve the probability of success and reduce the severity of setbacks when they occur. They are not a guarantee.

**Does readiness assessment apply to off-the-shelf AI tools as well as custom deployments?**
Yes. The integration, governance, and change management questions are as relevant for a commercial AI product as for a custom-built system. The data quality and process clarity questions are equally critical — a well-designed vendor product will still underperform if the process it automates is undocumented or the underlying data is unreliable.

---

The organizations that deploy AI successfully are not necessarily the ones with the most sophisticated technology. They are the ones that spend time before the project understanding what conditions the technology requires — and building those conditions methodically. The 20 checkpoints above are not a bureaucratic checklist. They are the organizational prerequisites that separate AI deployments that deliver from ones that serve as cautionary tales.

Before you spend a dollar on AI, know your score.
