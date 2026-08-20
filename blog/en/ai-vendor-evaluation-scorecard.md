---
title: "The AI Vendor Evaluation Scorecard: 25 Questions Before You Sign"
description: "Most AI vendor decisions are made on demos, not on the criteria that determine whether a deployment succeeds. This 25-question scorecard — across five dimensions — gives executives a structured framework for evaluating AI vendors before committing."
date: "2026-08-20"
category: "Practical Frameworks"
readingTime: "9"
keywords: "AI vendor evaluation, AI vendor selection framework, how to choose an AI vendor, AI procurement checklist, enterprise AI vendor scorecard, AI contract questions, AI RFP criteria"
---

# The AI Vendor Evaluation Scorecard: 25 Questions Before You Sign

## The Demo Is Not the Deployment

The AI vendor evaluation process at most organisations follows a predictable arc: a vendor books a discovery call, delivers a polished demo with a compelling use case, and then moves to proposal within two weeks. The demo works. It always works. The controlled environment, the pre-loaded data, the practiced flow — none of it reflects what happens when the system encounters your infrastructure, your data quality, your edge cases, and your compliance requirements.

The organisations that make poor AI vendor decisions are not making them because they failed to evaluate. They are making them because they evaluated the wrong things.

Gartner's analysis of enterprise software procurement consistently identifies technical fit and integration complexity as the leading causes of failed deployments — issues that are almost always visible in vendor evaluation, if you know what questions to ask. The problem is that most procurement processes are designed around capability demonstrations rather than deployment readiness.

This scorecard provides 25 specific questions across five evaluation dimensions. Score each question on a 0–2 scale: 0 for an unsatisfactory or missing answer, 1 for an acceptable answer with conditions, 2 for a strong, verifiable answer. Maximum score: 50. A vendor scoring below 30 should not progress to contract negotiation.

---

## How to Use This Scorecard

Before distributing this to vendors, assemble your evaluation panel: at minimum, a technical lead (CTO or head of engineering), a business owner from the primary deployment function, a legal or compliance representative, and your procurement lead. Each evaluator scores independently; compare and discuss before finalising.

Apply this scorecard to at least two vendors simultaneously. A single-vendor evaluation is a reference check, not a procurement process.

---

## Dimension 1: Technical Fit and Integration (Questions 1–5)

The majority of AI deployment timelines overrun because integration with existing systems — CRM, ERP, telephony, data warehouse — was underestimated during evaluation. These five questions reveal integration readiness before you commit.

**Q1. What does your standard API and integration architecture look like, and which specific systems have you integrated with in production deployments?**

A strong answer names specific systems (Salesforce, Workday, Epic, SAP, Genesys), describes the integration mechanism (REST API, webhooks, native connector, middleware), and includes a technical integration specification document. An answer that stays at the level of "we integrate with most major platforms" is a 0.

**Q2. How does your system handle data quality issues — missing fields, inconsistent formats, duplicate records — in production?**

The vendor's answer here reveals whether they have seen real data or only clean demo data. Strong vendors describe specific data validation layers, error handling logic, and how failures surface to the customer. Vague answers about "robust data pipelines" are not sufficient.

**Q3. What are the documented uptime SLAs, and how are SLA breaches measured, reported, and compensated?**

Your minimum threshold should be 99.5% monthly uptime for any production AI system in a customer-facing context. Strong vendors provide SLA documents with clearly defined measurement methodology and credit mechanisms for breach. If a vendor cannot provide a signed SLA document during evaluation, that is a risk signal.

**Q4. How is the system versioned, and how are breaking changes communicated and managed?**

AI systems are not static. Models update, APIs deprecate, and behaviour shifts. A strong vendor has a documented version policy: minimum 90-day advance notice of breaking changes, a migration guide, and the option to remain on a prior version for a defined window. A vendor that handles versioning informally is describing a future incident.

**Q5. What does your disaster recovery and business continuity architecture look like, and what is your documented RTO/RPO?**

Recovery Time Objective (how long to restore service) and Recovery Point Objective (how much data can be lost in an outage) should be defined in writing. A vendor without documented DR architecture has not had a production incident serious enough to force them to build one — which means you will be the incident.

---

## Dimension 2: Security, Privacy, and Compliance (Questions 6–10)

**Q6. What security certifications do you hold, and can you provide current audit reports?**

The baseline for enterprise AI vendors is SOC 2 Type II. ISO 27001 is a meaningful additional signal. Vendors without SOC 2 Type II certification are not enterprise-ready regardless of their product capabilities. "We're working toward SOC 2" means they do not have it.

**Q7. Where is customer data stored, processed, and retained, and what are the explicit data retention and deletion policies?**

For any organisation operating under GDPR, CCPA, or sector-specific regulations (HIPAA, PCI DSS), data residency and retention are legal requirements, not preferences. A strong answer names the specific geographic regions for data processing, the retention schedule, and the contractual mechanism for data deletion on termination.

**Q8. Is customer data used to train or fine-tune models shared with other customers or with the vendor's general model development?**

This is the question most vendors prefer not to answer clearly. A strong answer is explicit: customer data is not used for model training beyond the customer's own deployment without explicit opt-in. Any ambiguity in the contract on this point must be resolved in writing before signing.

**Q9. How do you handle a data breach or security incident involving customer data?**

Strong vendors have a documented incident response policy with defined notification timelines (under 72 hours for GDPR-reportable incidents), a named customer-facing point of contact for security events, and a post-incident review process. A vendor whose answer involves contacting the general support email is not prepared.

**Q10. Have you undergone any third-party penetration tests in the past 12 months, and can you share the executive summary?**

Reputable enterprise vendors conduct annual penetration tests and are willing to share sanitised results with prospective customers under NDA. A refusal to share any information about third-party security testing is a material negative signal.

---

## Dimension 3: Vendor Viability and Support (Questions 11–15)

**Q11. What is the company's current funding status, runway, and path to profitability?**

The AI vendor landscape in 2026 is dense with well-funded startups and thinly capitalised point solutions. A vendor with less than 18 months of runway at current burn represents a business continuity risk. Publicly traded vendors or those with substantial enterprise ARR are lower risk on this dimension; early-stage startups require explicit business continuity provisions in the contract.

**Q12. Who are your three largest customers by revenue, and can you provide references we can contact?**

References are a standard procurement mechanism that many AI vendors quietly resist. A vendor who is unwilling or unable to provide three current customer references in a segment comparable to yours is not demonstrating commercial track record. Reference conversations should happen before final vendor selection, not after.

**Q13. What is the average implementation timeline for a deployment of comparable scope, and what are the most common causes of timeline overrun?**

A vendor who cannot answer the second part of this question honestly has not conducted post-implementation reviews. The most common causes of delay — data access, internal stakeholder alignment, change management, integration complexity — are knowable and should be documented by any vendor with meaningful deployment history.

**Q14. What does your customer success and ongoing support model look like, including response SLAs for critical issues?**

Support SLAs should be contractually binding. A four-hour SLA for critical (production-impacting) issues is a reasonable benchmark. Support handled entirely through a ticketing system with no named contact for enterprise accounts is below the standard for a deployment that handles customer interactions.

**Q15. What is your product roadmap for the next 12 months, and how are customer requirements incorporated into development?**

A vendor without a credible answer to this question is not thinking about long-term customer success. A strong answer describes a formal product feedback mechanism, a customer advisory group or equivalent, and examples of features shipped in response to customer input.

---

## Dimension 4: Commercial Terms and Flexibility (Questions 16–20)

**Q16. What is the total cost of ownership, including implementation, integration, training, and ongoing licensing?**

The demo price and the deployment cost are rarely the same number. Strong vendors provide a total cost breakdown — not just licensing — that includes professional services, integration work, training, and the cost of internal resources required during implementation.

**Q17. How is pricing structured as usage scales, and are there volume discount provisions?**

Usage-based pricing models can produce significant cost surprises if call volume, API requests, or data volume exceeds initial estimates. Get the pricing model in writing with explicit tiers, overage rates, and volume commitment options before signing.

**Q18. What are the minimum contract terms, and what are the exit provisions?**

A vendor requiring a three-year minimum commitment for an unproven deployment is asking you to absorb their risk. A reasonable enterprise term for an initial deployment is 12 months with renewal options. Exit provisions should include data portability: you must be able to extract your data in a standard format on termination.

**Q19. Who owns the models, fine-tuning, and outputs generated from our data?**

Intellectual property provisions in AI contracts are often insufficiently specific. Ensure the contract explicitly states that models fine-tuned on your data, prompts developed by your team, and outputs generated from your data are your intellectual property.

**Q20. What provisions exist for SLA breach remedies beyond credit — including contract exit rights?**

Credit for downtime is the minimum. In a customer-facing AI deployment where SLA breach causes measurable business harm, the contract should include exit rights triggered by repeated SLA failures. Vendors who resist this provision are not confident in their own reliability.

---

## Dimension 5: Implementation and Change Management (Questions 21–25)

**Q21. Who is the named implementation lead on your side, and what is their relevant experience?**

A vendor who assigns implementation to a junior project coordinator while the sales engineer moves to the next deal is a pattern worth identifying before it happens. The named implementation lead should have direct experience with deployments of comparable complexity and should be named in the contract as a deliverable.

**Q22. What does the knowledge transfer process look like, and what internal capability will we have to manage the system post-implementation?**

The goal is operational independence: your team should be able to configure, monitor, and troubleshoot the system without vendor intervention for routine operations. Vendors who design systems requiring ongoing professional services for basic management are not building customer success.

**Q23. How do you handle end-user training, and do you have documented resources for adoption?**

AI deployments fail as often from adoption failure as from technical failure. A strong vendor has documented training resources, a structured onboarding programme, and experience supporting organisations through the change management process — not just the technical implementation.

**Q24. What metrics do you track and report during implementation, and how is success defined?**

Success metrics should be agreed in writing before implementation begins. Strong vendors propose specific, measurable outcomes (call deflection rate, average handling time, CSAT score) and commit to a reporting cadence that makes progress visible throughout implementation.

**Q25. What does your escalation path look like if the implementation is not on track — including your commitment to remediation?**

A vendor who cannot describe a clear escalation path and remediation commitment for a troubled implementation is one who has not had to rescue one yet. Ask for a specific example of an implementation that encountered significant difficulties and how it was resolved.

---

## Scoring Summary

| Score | Interpretation |
|---|---|
| 45–50 | Strong vendor — proceed to contract with standard diligence |
| 35–44 | Acceptable — negotiate specific gaps before signing |
| 25–34 | Significant gaps — negotiate hard or shortlist an alternative |
| Below 25 | Walk away |

A vendor who scores well on Dimensions 1 and 2 but poorly on Dimension 3 is technically capable but commercially fragile. A vendor who scores well on Dimensions 3 and 4 but poorly on Dimensions 1 and 2 has a strong sales operation and a weak product. Both profiles are traps.

The 25 questions above will not fit into a 30-minute discovery call. That is intentional. A vendor who pushes back on the depth of your evaluation process is showing you something about how they will respond when a deployment runs into difficulty. The vendors worth signing with will welcome the rigor.

---

## FAQ

**How long should AI vendor evaluation take?**

For a deployment that will touch customer interactions or core business processes, a rigorous evaluation should take 4–8 weeks from first vendor meeting to contract signature. Evaluations compressed below four weeks typically cut the reference check and the security review — the two steps most likely to surface material risks.

**What if the vendor refuses to answer specific questions?**

A refusal to answer — as opposed to a nuanced or conditional answer — is informative. Vendors who refuse to share SOC 2 documentation, provide customer references, or clarify data ownership provisions are not comfortable with what you would find. That discomfort belongs in your evaluation, not your production environment.

**Should we run a pilot before signing a full contract?**

Yes, where commercially feasible. A paid pilot on a limited scope (one department, one workflow) with defined success criteria and a clear mechanism to convert to a full contract — or exit — is a reasonable ask. Vendors who resist any pilot mechanism before a multi-year contract are asking for more trust than the evaluation process has earned.

**How do we evaluate vendors who are pre-revenue or early-stage?**

Apply Dimension 3 (Viability and Support) with higher scrutiny: require escrow provisions for source code, seek explicit business continuity clauses, and limit initial contract scope and term. An early-stage vendor with outstanding technology is a valid choice if the contract architecture manages the business continuity risk.

**What is the most commonly overlooked question in AI vendor evaluation?**

Q8 — whether customer data is used for model training. Most buyers assume their data is private by default; many vendor contracts include training rights in broad language that buyers do not catch on first read. Have legal review every data usage clause before signing.

---

*Further reading:*
- [Is Your Company Ready for AI? A 20-Point Readiness Assessment](/blog-post.html?post=ai-readiness-assessment-checklist&lang=en)
- [Build vs Buy AI Automation: The Decision Framework CTOs Actually Use](/blog-post.html?post=build-vs-buy-ai-automation&lang=en)
- [How to Calculate AI Automation ROI Before You Spend a Dollar](/blog-post.html?post=ai-automation-roi-calculation-guide&lang=en)
- [From Pilot to Production: Why 70% of AI Pilots Never Scale](/blog-post.html?post=ai-pilot-to-production-playbook&lang=en)
- [Your First AI Project: Why Most Companies Pick the Wrong One](/blog-post.html?post=first-ai-project-how-to-choose&lang=en)
