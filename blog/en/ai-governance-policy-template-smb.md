---
title: "The AI Governance Policy Every Mid-Size Company Needs (Template)"
description: "Most mid-size companies are deploying AI without a governance policy. Here is the framework — and a template you can adapt — to manage AI risk, assign accountability, and build the board-level confidence your AI investments require."
date: "2026-08-25"
category: "Practical Frameworks"
readingTime: "9"
keywords: "AI governance policy, AI governance framework mid-size business, responsible AI policy template, AI risk management SMB, AI policy template, NIST AI RMF, AI governance checklist, enterprise AI governance"
---

# The AI Governance Policy Every Mid-Size Company Needs (Template)

## The Accountability Gap

Most mid-size companies now use AI. Very few have written down who is responsible when something goes wrong.

That gap matters more than it used to. When AI was a spreadsheet tool or a spam filter, the consequences of failure were contained. Today, AI systems make credit decisions, handle customer calls, draft contracts, screen job applications, and access live financial data. The failure modes — biased outputs, data leaks, regulatory non-compliance, reputational damage — are executive-level problems.

PwC's 2025 Responsible AI survey found that 18% of organisations are still building foundational AI policies and frameworks. In a mid-size company without a dedicated AI governance team, that 18% is almost certainly an undercount. The organisations that have caught up are seeing measurable returns: nearly 58% of executives with mature governance programmes report that Responsible AI improves ROI and operational efficiency, and 55% report improvements in customer experience and innovation.

An AI governance policy does not require a team of compliance specialists or a year of consulting engagement. It requires four things: a clear scope, accountability assignments, a risk classification system, and a review cadence. This article gives you a template structure for each.

---

## Why Mid-Size Companies Can't Wait for Enterprise Precedent

Large enterprises have compliance teams, legal departments, and dedicated AI ethics boards. Their governance frameworks are comprehensive — and largely inaccessible as models for a 200-person company.

Mid-size companies face a different risk profile. They typically:

- Deploy AI faster than their policies can keep up with, often through individual departmental decisions rather than centralised procurement
- Have less capacity to absorb the reputational or regulatory consequences of a public AI failure
- Operate under the same regulations as large enterprises, particularly in regulated industries

The EU AI Act, fully applicable as of August 2026, assigns obligations to any organisation deploying AI systems — regardless of company size. Those obligations include transparency requirements, conformity assessments for high-risk systems, and post-market monitoring for systems that affect individuals' rights. Non-compliance carries penalties up to 3% of global annual turnover.

NIST's AI Risk Management Framework (AI RMF 1.0), published January 2023, provides a voluntary but widely adopted structure. Its four core functions — Govern, Map, Measure, and Manage — form the basis of most credible AI governance frameworks. The template below maps to these functions.

---

## The Template Structure

An AI governance policy for a mid-size company needs six sections. Below is each section with the key decisions it must document.

---

### Section 1: Scope and Definitions

This section defines what the policy covers and what it excludes. Without it, the policy will be applied inconsistently.

**What to include:**

- **Definition of an "AI system" for your organisation.** A workable definition: any system that uses machine learning, generative AI, or rules-based automation to produce outputs (predictions, decisions, recommendations, or content) that affect business operations, customers, or employees.
- **Systems in scope.** Name specific tools and system categories: your CRM's AI features, any generative AI tools used by staff, customer-facing AI applications, automated decision systems in HR or finance.
- **Systems excluded.** Standard rule-based automation, search functions, and analytics dashboards without predictive or generative components typically sit outside the scope of most AI governance frameworks. Be explicit.
- **Effective date and review schedule.** AI changes fast. The policy should be reviewed at minimum annually, or whenever a material new AI system is deployed.

---

### Section 2: Accountability Structure

AI governance fails when nobody owns it. The most common failure pattern is a policy that lists principles without assigning names.

**The minimum viable accountability structure:**

| Role | Responsibility |
|---|---|
| **AI Governance Lead** (often CTO, CIO, or a named senior) | Owns the policy; chairs the governance review; approves new AI systems |
| **Business Process Owners** (one per department) | Responsible for AI systems within their domain; submit risk assessments before deployment |
| **Legal / Compliance** | Reviews regulatory obligations; monitors regulatory change |
| **HR** | Oversees AI systems that affect employees (recruitment, performance, scheduling) |
| **Data Privacy Officer** (where required) | Reviews AI systems for data protection obligations |

In a company without a dedicated CISO or data privacy officer, these roles are often held by the same two or three people. The principle is the same: every AI system must have a named human owner who is accountable for its performance, its risks, and its compliance.

One thing that consistently goes wrong at this stage: the AI Governance Lead is given responsibility but not authority. If that person cannot pause an AI deployment pending a risk review, the accountability structure is decorative.

---

### Section 3: AI Risk Classification

Not all AI systems carry the same risk. A scheduling tool and a customer credit assessment system should not be governed identically.

A practical three-tier classification:

| Tier | Description | Examples | Governance Requirements |
|---|---|---|---|
| **Tier 1 — High Risk** | Affects individual rights, legal status, or significant financial outcomes | Credit decisions, recruitment screening, disciplinary processes, medical triage | Full risk assessment; legal review; ongoing monitoring; human override required |
| **Tier 2 — Medium Risk** | Affects business operations materially; customer-facing with significant interaction | AI phone agents, content moderation, demand forecasting, pricing recommendations | Risk assessment; owner review quarterly; disclosure to affected parties |
| **Tier 3 — Low Risk** | Internal productivity tools; staff-facing with human review of outputs | Meeting summarisers, drafting assistants, internal search tools | Register only; basic training for users |

For any system that could qualify as high-risk under the EU AI Act — which includes systems used in employment, education, credit, essential services, or law enforcement — a conformity assessment is required regardless of your internal tier classification.

The classification framework has one rule that matters more than the tiers themselves: **every AI system must be classified before it is deployed, not after a problem occurs.**

---

### Section 4: Procurement and Deployment Standards

Most AI governance failures in mid-size companies happen at the procurement stage. A department head signs a vendor contract for an AI tool, the IT team configures it, and the legal and compliance implications are discovered later.

**Before any new AI system is deployed, document:**

1. **The use case.** What decision or output does this system produce? What happens if the output is wrong?
2. **The data inputs.** What data feeds the system? Is any of it personal data? Is it subject to geographic data restrictions?
3. **The vendor's transparency obligations.** Does the vendor disclose the model type, training data provenance, known limitations, and accuracy benchmarks? If not, the system is harder to govern.
4. **The human override mechanism.** For any Tier 1 or Tier 2 system, there must be a defined process for a human to review and override the AI's output. This is both a governance requirement and, for high-risk EU AI Act systems, a legal obligation.
5. **The training and change management plan.** Who in the organisation will use this system? What training do they need to use it responsibly? What happens when the model is updated?

A useful procurement question that most vendors resist but credible ones can answer: **what does the system do when it encounters a case it has not seen before?** The answer tells you how the system handles uncertainty, which is often where governance failures occur.

---

### Section 5: Transparency and Disclosure

Transparency requirements have two audiences: your customers, and your regulators.

**Customer transparency.** If your customers interact with an AI system — an AI phone agent, an AI chat assistant, a personalised recommendation engine — they should be told. This is required under the EU AI Act for conversational AI systems, and increasingly expected by customers regardless of regulation. The disclosure does not need to be elaborate: "This call may be handled by an AI assistant. You can request a human agent at any time."

**Internal transparency.** Employees affected by AI systems — particularly in HR, performance management, or scheduling — must be informed that AI is involved in decisions affecting them, and must have access to a process for contesting those decisions.

**Regulatory transparency.** For high-risk systems under the EU AI Act, post-market monitoring and incident reporting obligations apply. This means logging system performance, documenting material failures, and in some cases reporting to national AI authorities.

---

### Section 6: Ongoing Monitoring and Review

A governance policy written once and filed is not a governance policy. It is a document.

**The minimum viable monitoring cadence:**

- **Monthly:** AI Governance Lead reviews any flagged incidents or complaints related to AI systems in the prior 30 days.
- **Quarterly:** Business Process Owners review Tier 1 and Tier 2 systems against their performance benchmarks and risk assessments. Flag drift in model accuracy or unexpected output patterns.
- **Annual:** Full policy review against regulatory developments, new AI deployments, and any incidents that occurred in the year.
- **Triggered reviews:** Any material failure, regulatory change, or significant new AI deployment triggers an immediate review regardless of the scheduled cadence.

PwC's 2025 Responsible AI survey found that organisations at the strategic governance stage are roughly 1.5 to 2 times more likely to describe their AI programme capabilities as effective compared with those still building foundational frameworks. The difference is almost always whether governance is embedded into operating rhythm or treated as a compliance exercise done once.

---

## The Readiness Checklist

Before filing your AI governance policy, check each of these:

| Item | Done? |
|---|---|
| Scope defined with specific systems named or excluded | |
| Named AI Governance Lead with sign-off authority | |
| Named Business Process Owner for every active AI system | |
| All active AI systems classified (Tier 1 / 2 / 3) | |
| Procurement checklist in place for new deployments | |
| Customer-facing AI disclosure language drafted and reviewed | |
| High-risk systems reviewed against EU AI Act obligations (if applicable) | |
| Monitoring cadence documented and owned | |
| Policy review date set | |

A checklist that returns more than three gaps identifies where to start, not how far behind you are. Closing the accountability and classification gaps — Sections 2 and 3 above — reduces the majority of AI governance risk in practice.

---

## What Happens Without a Policy

The question organisations sometimes ask is whether a mid-size company that doesn't operate in the EU, doesn't use high-risk AI, and isn't publicly traded really needs a formal AI governance policy.

The answer is less about regulation than about what governance actually does.

Without a risk classification system, high-risk AI deployments move at the same pace as low-risk ones. Without accountability assignments, incidents become ownership disputes. Without procurement standards, vendor AI decisions are made by whoever signs the contract. Without a monitoring cadence, model drift is discovered by a customer complaint rather than an internal audit.

None of these are hypothetical failure modes. They are the patterns that produce the public AI incidents that damage brands and trigger regulatory investigations.

The organisations that avoid them do not wait for a failure to build the framework. They build the framework before it is needed, because the cost of doing so is predictable and manageable — and the cost of the alternative is not.

---

## Frequently Asked Questions

**How long does it take to write an AI governance policy?**
For a mid-size company with a clear scope, four to six weeks of internal effort is typical. The drafting is not the hard part. The hard part is inventorying all active AI systems — most organisations discover several they had not formally acknowledged — and getting the accountability assignments confirmed at the leadership level.

**Does the EU AI Act apply to my company?**
The EU AI Act applies to any organisation deploying AI systems that affect individuals in the EU, regardless of where the organisation is headquartered. If you have EU customers, employees, or operations, you are likely in scope. High-risk system obligations, transparency requirements for conversational AI, and post-market monitoring apply from August 2026.

**Do we need a dedicated AI ethics board?**
For most mid-size companies, a designated AI Governance Lead with quarterly reviews and clear escalation paths is sufficient. A formal board is appropriate at the scale where AI deployment decisions are too numerous or complex for a single point of accountability. The governance structure should match the scale of your AI footprint, not the scale of your ambitions.

**How do we handle AI tools that employees bring in themselves?**
Shadow AI — employees using AI tools not approved or procured by the company — is a material risk in most organisations. A governance policy should include a clear statement that any AI system used for company purposes, regardless of whether it was procured by IT, falls under the policy. This is enforced through employee training and HR policy, not purely through technical controls.

**What if our AI vendor changes the model without telling us?**
This is a known risk with SaaS AI tools. Your procurement standards should require vendors to notify you of material model updates and provide documentation of what changed. For Tier 1 and Tier 2 systems, model updates should trigger a re-review against your risk assessment. If a vendor cannot commit to this, that is a material governance consideration at the procurement stage.

---

## Starting Point, Not End State

An AI governance policy is not a compliance artefact. It is the operating document that determines whether your AI investments deliver value consistently or create liability unpredictably.

The template structure above — scope, accountability, risk classification, procurement standards, transparency, and monitoring — covers the decisions that most governance failures trace back to when they are reconstructed after the fact.

Start with what is already deployed. Classify it. Assign an owner. Set a review cadence. The sophistication can follow; the accountability cannot.

For the vendor evaluation criteria you should apply before any new AI system reaches the deployment stage, the [AI Vendor Evaluation Scorecard](/blog-post.html?post=ai-vendor-evaluation-scorecard&lang=en) covers 25 questions that should be answered before you sign. For understanding where your organisation sits on the broader AI readiness spectrum, the [AI Readiness Assessment Checklist](/blog-post.html?post=ai-readiness-assessment-checklist&lang=en) provides a structured evaluation across the dimensions that governance failures most commonly trace back to.

If you are building your AI strategy from the ground up, the [AI Adoption Roadmap for Mid-Size Businesses](/blog-post.html?post=ai-adoption-roadmap-midsize-business&lang=en) provides a 90-day framework that places governance as a foundational layer rather than a late-stage addition. And for understanding the hidden costs that governance frameworks are designed to contain, the [Hidden Costs of AI Automation](/blog-post.html?post=hidden-costs-ai-automation&lang=en) covers the budget lines that most AI proposals omit.
