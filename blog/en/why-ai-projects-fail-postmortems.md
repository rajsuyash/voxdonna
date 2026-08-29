---
title: "Why AI Projects Fail: Patterns From Public Post-Mortems"
description: "The failures of Google Flu Trends, Amazon's recruiting AI, and IBM Watson for Oncology share the same underlying patterns. Here is what the documented post-mortems reveal — and the diagnostic framework that prevents repetition."
date: "2026-08-29"
category: "Common Mistakes"
readingTime: "9"
keywords: "why AI projects fail, AI project failure, AI post-mortem, AI implementation failure, AI failure case studies, Google Flu Trends failure, Amazon AI recruiting failure, IBM Watson failure, AI project risk, AI lessons learned"
---

# Why AI Projects Fail: Patterns From Public Post-Mortems

## The Advantage of Learning From Other People's Failures

Most organisations have access to the same research on AI project failure rates. They read it, nod, and proceed to replicate the same failure modes in their own deployments.

The reason is not ignorance. It is proximity. Abstract statistics about failure rates do not produce the same visceral recognition as reading what actually happened inside a specific project — what decisions were made, what signals were ignored, and what the cost was when things collapsed.

Public post-mortems are rare in technology. Companies are incentivised to suppress failure narratives. But enough has been reported — through journalism, litigation, academic analysis, and companies themselves — to identify the patterns that recur. These patterns are not unique to the organisations involved. They are structural, and they appear in organisations of every size and sector that are currently running AI projects.

This article documents the most instructive public failures and extracts what executives need to act on before the same patterns take root in their own initiatives.

---

## Pattern 1: Training Data That Does Not Represent Reality

**The case: Amazon's AI Recruiting Tool (2014–2017)**

In 2014, Amazon built an AI system to automate the screening of job applications. The objective was practical — the company received hundreds of thousands of CVs annually, and a system that could score candidates would reduce recruiter workload. The system was trained on CVs submitted to Amazon over the preceding decade.

The problem, reported by Reuters in October 2018 when the project was shut down, was that a decade of Amazon hiring had been dominated by male candidates — a reflection of the broader technology industry's gender imbalance. The system learned to replicate that pattern. It penalised CVs that contained the word "women's" (as in "women's chess club" or "women's leadership programme"). It downgraded graduates of two all-women's colleges. Amazon disbanded the team in 2017 after concluding the system could not be reliably corrected.

**What it means for your organisation**

Any AI system trained on historical data learns the decisions that produced that history — including the biased, suboptimal, and context-specific ones. Before deploying any model that uses historical decision data as training signal, ask: who made those historical decisions, under what constraints, and what patterns did they systematically favour or exclude?

This is not only a fairness concern. It is a reliability concern. A recruiting model that excludes high-quality candidates is a business problem. A credit-scoring model trained on historical approvals that reflected redlining will systematically misvalue current applicants. The same structural issue applies to any operational AI trained on past human decisions.

→ *See also: [Is Your Company Ready for AI? A 20-Point Readiness Assessment](/blog-post.html?post=ai-readiness-assessment-checklist&lang=en)*

---

## Pattern 2: Overfitting to a Proxy Signal

**The case: Google Flu Trends (2008–2015)**

Google Flu Trends launched in 2008 and generated significant attention — and genuine scientific interest — for its ability to track influenza outbreaks faster than the CDC's traditional surveillance systems. By analysing search query volumes, it appeared to track flu prevalence in near real time, weeks ahead of clinical data.

A 2014 analysis published in Science by Lazer et al. — "The Parable of Google Flu: Traps in Big Data Analysis" — documented the collapse of this performance. By 2013, Google Flu Trends was overestimating peak flu activity by more than 140 percent. The model had been optimised on a period when search behaviour and flu prevalence moved together. When Google changed its autocomplete algorithm in 2011 and 2012, search patterns shifted independently of actual flu rates. The model did not know this was happening.

The system had learned to predict a proxy of flu — search behaviour — rather than flu itself. When the proxy and the underlying phenomenon decoupled, the predictions became unreliable.

**What it means for your organisation**

Most AI models optimise on a measurable proxy of the outcome you actually care about. Customer churn scores predict cancellations, not the satisfaction that drives them. Fraud detection systems flag transaction patterns, not fraudulent intent. Demand forecasting models predict historical order patterns, not future demand.

When the proxy remains reliably correlated with the outcome, the model performs. When external conditions change the relationship — competitive shifts, economic disruption, regulatory changes, or even a UI redesign — the model's performance can degrade without any obvious signal that it is doing so.

Monitoring AI system performance against the actual business outcome, not just the training metric, is the only way to detect this category of failure before it becomes material.

→ *See also: [How to Calculate AI Automation ROI Before You Spend a Dollar](/blog-post.html?post=ai-automation-roi-calculation-guide&lang=en)*

---

## Pattern 3: Domain Complexity That Exceeds the Training Signal

**The case: IBM Watson for Oncology (2012–2022)**

IBM Watson for Oncology was one of the most prominent AI projects of the 2010s. Announced as a system that could recommend cancer treatment plans, it was sold to numerous hospitals globally and represented a significant public commitment to AI's potential in healthcare.

A 2017 investigation by STAT News, drawing on internal IBM documents, found that physicians at several major cancer centres had identified treatment recommendations that were "unsafe and incorrect." The underlying issue: the system had been trained predominantly on hypothetical patient cases generated by oncologists at Memorial Sloan Kettering Cancer Center, rather than on the complex, ambiguous, co-morbid real-world cases that physicians actually encounter.

A model trained on carefully constructed hypothetical scenarios performs well on carefully constructed hypothetical scenarios. Real patients have conflicting symptoms, unusual histories, and contraindications that do not fit clean patterns. Multiple hospital systems cancelled contracts through 2017 and 2018. IBM sold its Watson Health division to Francisco Partners in 2022.

**What it means for your organisation**

AI systems are calibrated to the complexity of their training data. If training data was curated, sanitised, or constructed to be representative of ideal scenarios, the system will perform well on ideal scenarios — which are not what it will encounter in production.

Before deployment, test AI systems against the messy, incomplete, and contradictory inputs that the operational environment actually produces. If performance degrades substantially on real data versus curated data, that gap is not a test environment problem. It is the model's actual performance ceiling.

→ *See also: [The AI Vendor Evaluation Scorecard: 25 Questions Before You Sign](/blog-post.html?post=ai-vendor-evaluation-scorecard&lang=en)*

---

## Pattern 4: Accountability Gaps That Become Legal Exposure

**The case: Air Canada's Chatbot (2022–2024)**

In 2024, the British Columbia Civil Resolution Tribunal ordered Air Canada to pay compensation to a customer who had been given incorrect information about bereavement fares by the airline's AI chatbot. The customer had purchased a full-price ticket in reliance on the chatbot's (erroneous) claim that a reduced bereavement rate could be applied retroactively within 90 days.

Air Canada argued in its defence that the chatbot was a "separate legal entity" responsible for its own statements, and that the airline bore no liability for its outputs. The tribunal rejected this argument. Air Canada was held responsible for the information its AI system provided to customers, regardless of whether the information was accurate.

**What it means for your organisation**

Customer-facing AI systems are not a separate legal category. When they provide incorrect information to customers — billing details, product specifications, policy terms, pricing — the organisation is responsible for the outcome. "The AI said it" is not a defence.

This does not mean customer-facing AI should not be deployed. It means the governance framework around it must address: what is the AI authorised to communicate on behalf of the organisation, what is outside scope, what escalation path exists when the AI is uncertain, and what review mechanism exists for updating the AI when policies change.

→ *See also: [The AI Governance Policy Every Mid-Size Company Needs (Template)](/blog-post.html?post=ai-governance-policy-template-smb&lang=en)*

---

## Pattern 5: Pilots That Cannot Scale

**The context: the production gap**

The cases above are visible because they involved major organisations and attracted journalistic attention. The more common failure is quieter: an AI pilot that demonstrates promising results in a controlled environment and then stalls at the boundary of production deployment.

McKinsey's 2026 Global Survey on the State of AI found that 80 percent of employees report productivity gains from AI, while only 37 percent of organisations report any EBIT impact. One consistent difference between organisations that close this gap and those that do not is whether they redesign workflows around AI or simply insert AI into existing processes. High performers — McKinsey's 6 percent with 5 percent or greater EBIT impact — are three times more likely to have fundamentally redesigned workflows.

Pilots succeed in controlled conditions because the control removes the complications that production environments contain: legacy system integrations that behave differently under load, edge-case data that was excluded from the pilot, users who are not the early adopters who tested the system, and organisational processes that were not redesigned to incorporate the AI's outputs.

The pilot-to-production failure rate is not primarily a technology problem. It is a scoping problem. Pilots that do not include a realistic sample of the production environment's complications are not actually testing whether the system will work at scale.

→ *See also: [From Pilot to Production: Why 70% of AI Pilots Never Scale](/blog-post.html?post=ai-pilot-to-production-playbook&lang=en)*

---

## The Post-Mortem Diagnostic

What the documented failures have in common is not complexity. They are failures of specific, identifiable decisions that were made before deployment. The table below maps each failure pattern to the decision point where it was preventable.

| Failure Pattern | Root Decision Point | Prevention |
|---|---|---|
| Training data bias | Data audit and labelling decisions | Audit training data for historical decision bias before modelling |
| Proxy signal drift | Metric selection during model design | Monitor against business outcome, not just training metric |
| Domain complexity gap | Evaluation design | Test against real, messy production data — not curated samples |
| Accountability gap | Governance and deployment scope | Define accountability before deployment; restrict scope to what governance covers |
| Pilot-to-production failure | Pilot design | Include production-representative complexity in pilot scope |

Each of these decisions happens upstream of the technology. They are not model tuning decisions or infrastructure decisions. They are project governance decisions — the kind that executives are positioned to require rather than delegate.

---

## Frequently Asked Questions

**What is a post-mortem in the context of AI projects?**
A post-mortem is a structured analysis of why a project failed, conducted after the fact. In AI, public post-mortems are rare — companies rarely publish their own failure analyses. The cases in this article were documented through journalism, academic research, and litigation.

**Are these failures unique to large companies?**
No. The patterns — training data that does not represent reality, proxy signals that drift, domain complexity that exceeds the training signal, accountability gaps, and pilot designs that do not reflect production conditions — appear in AI projects of all sizes. The specific companies are large because large projects attract more scrutiny.

**How do you detect proxy signal drift before it becomes material?**
Set up monitoring that tracks model performance against the actual business outcome — not the surrogate metric used during training. If churn prediction accuracy is stable but actual churn rate is rising, the model's proxy has decoupled from the underlying behaviour. Set alert thresholds on both.

**What governance structure prevents the accountability gap seen in the Air Canada case?**
Before any customer-facing AI goes live, document: what this system is authorised to communicate, what topics are out of scope and should escalate to a human, what the review cadence is for keeping system content current, and who is accountable when the system is wrong. One written page covers this for most mid-size deployments.

**Should organisations avoid AI because of these failure rates?**
No. The failures in this article are instructive precisely because they are preventable. The organisations that are generating material business outcomes from AI — McKinsey's 6 percent high performers — are not avoiding risk; they are designing processes to identify and manage it upstream. The lesson from the post-mortems is not caution. It is better project governance.

→ *See also: [The 9 AI Implementation Mistakes That Burn Executive Credibility](/blog-post.html?post=ai-implementation-mistakes-executives&lang=en)*
