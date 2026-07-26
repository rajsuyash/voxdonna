---
title: "Buy Now or Wait: The Weekly Question Manufacturers Answer With a Spreadsheet"
description: "Copper set records in 2025 and again in January 2026. Materials are the largest line in most manufacturers' cost base. And the buy-or-wait call is still made on last month's average price and a supplier's phone call. Here is how procurement decision intelligence works: demand forecasts, honest price bands, five buying plays, and why a human must still approve every one."
date: "2026-07-26"
category: "Manufacturing"
readingTime: "14"
keywords: "procurement decision intelligence, manufacturing procurement AI, demand forecasting materials, price band forecasting P10 P50 P90, raw material price volatility, buying strategy manufacturing, procurement analytics, supplier split, inventory cover days, CPO technology"
---

# Buy Now or Wait: The Weekly Question Manufacturers Answer With a Spreadsheet

## The question nobody has a system for

Every Monday, in every manufacturing business, a buyer sits down with a material code and asks a question worth more than most of the projects on the IT roadmap:

**Do I buy this week, or do I wait?**

The answer usually comes from three inputs: last month's average price, whatever the supplier said on Friday, and the buyer's own memory of what happened the last time the market looked like this. Then it gets typed into a purchase requisition and becomes fact.

That process is not stupid. It is often carried out by people with twenty years of instinct, and instinct is real information. But it has three properties that make it fragile in a volatile market: it cannot state its own uncertainty, it cannot be audited a year later, and it does not scale past the handful of materials the most experienced buyer personally watches.

This article is about what a better process looks like — not "AI buys your steel", which is neither achievable nor desirable, but a decision system that turns your own history into a weekly recommendation your buyer can approve, override, or defend in an audit.

---

## Part 1: Why This Got Harder

### Prices stopped behaving

2025 and early 2026 were not calm years for industrial metals.

Copper spent March 2025 setting a then-record on COMEX at $5.374 per pound, then **fell about 25% to $4.03 by 7 April** — a quarter of the value, in roughly four weeks. ([CQG](https://news.cqg.com/blogs/commentary/2025/04/copper-volatility-march-and-april-2025)) By October, the LME three-month price punched through an all-time nominal high above **$11,200 per tonne** ([Reuters](https://www.reuters.com/markets/commodities/lme-copper-hits-record-highs-funds-fundamentals-align-2025-10-30)), New York copper ended the year **up more than 40%** ([CNBC](https://www.cnbc.com/amp/2025/12/30/copper-prices-what-next-for-the-red-metal-as-lme-prices-hit-record.html)), the LME three-month contract added a further **21% in Q4 alone**, and on 29 January 2026 it hit **$14,527.50 per tonne**. ([Benchmark Mineral Intelligence](https://source.benchmarkminerals.com/article/copper-hits-another-all-time-high-but-gains-fail-to-hold))

A buyer who waited four weeks in one part of that period saved a quarter of their cost. A buyer who waited four weeks in another part paid a fifth more. Both used the same instinct.

That is the definition of a market where a point estimate is worthless and a *range* is the only honest output.

### Materials are the biggest number you control

Academic surveys of Western manufacturing put raw material costs at roughly **35–40% of total costs**, the single largest category. ([Share of raw material costs in total production costs](https://www.researchgate.net/publication/268791925_Share_of_raw_material_costs_in_total_production_costs)) Research on large enterprises puts total external supplier spend even higher — Proxima's analysis of Fortune 500 firms found supplier costs averaging around **75% of total spending and 65% of revenue**. ([Proxima](https://proximagroup.com/reports-and-research/the-state-of-spend-report-and-supplier-cost-reductions))

Here is the arithmetic that makes procurement decisions disproportionately valuable, and it is worth doing on your own P&L before you read further.

Take a manufacturer with:
- Revenue: **₹500 crore** (or $60M — the ratio is what matters)
- Direct material spend: **40% of revenue** = ₹200 crore
- Net margin: **6%** = ₹30 crore

Now cut material cost by **2%** — not through renegotiation, just through better timing and mix on purchases you were going to make anyway.

- Saving: ₹200 crore × 2% = **₹4 crore**
- That drops to the bottom line: net profit goes ₹30 crore → **₹34 crore**
- **A 13.3% increase in net profit**

To get the same ₹4 crore of profit through sales, at a 6% margin, you would need **₹66.7 crore of additional revenue** — a 13.3% increase in top line, requiring more capacity, more people, more working capital, and more risk.

That is the trade every manufacturer is implicitly making when procurement gets a spreadsheet and sales gets a CRM.

For context on what is achievable: BearingPoint reports that well-executed direct material sourcing programmes typically deliver **5–15% of annual spend** ([BearingPoint](https://www.bearingpoint.com/en-africa/insights-events/insights/how-manufacturing-companies-can-leverage-sourcing-to-break-negative-profit-margin-trend)), and McKinsey's October 2025 work on AI-driven procurement cites around **20% savings potential** from deploying analytics across the function ([McKinsey](https://www.mckinsey.com/capabilities/operations/our-insights/transforming-procurement-functions-for-an-ai-driven-world)). Those are ceilings from mature programmes across all levers, not a promise from any single tool. The 2% used above is deliberately modest, and it still reprices the business.

### The people who run procurement already know

Deloitte's 2025 Global Chief Procurement Officer Survey — its twelfth edition, covering **more than 250 CPOs across 40 countries** — found the top quartile of procurement organisations ("Digital Masters") now allocating **up to 24% of their budgets to technology**, close to double their 2023 level, and projecting 26% next year. Those organisations report an average **3.2x return on generative AI investment**, against roughly 1.5x for followers. ([Deloitte](https://www.deloitte.com/us/en/about/press-room/2025-chief-procurement-officer-survey.html))

The same survey names the barriers, and they are not technical: siloed ways of working (**57%**), competing priorities (**46%**), organisational or technology capability (**40%**), and the talent gap (**34%**). Their most effective risk strategies are equally unglamorous: maintaining active alternative sources (**74%**), supply chain visibility (**64%**), and supplier collaboration (**61%**).

Note what that implies. The constraint is rarely the model. It is whether the output lands in a workflow someone owns.

---

## Part 2: From Forecast to Decision

Most "procurement AI" projects stop one step short of usefulness. They produce a forecast. A forecast is not a decision.

A decision system needs four layers, in order.

### Layer 1 — Demand: what will we actually consume?

Weekly consumption per material, per plant. Not annual budget divided by 52. Real consumption, with its seasonality, its production plan, and its scrap rate.

Be careful with the accuracy claims in this area. Vendor material widely cites 30–50% forecast error reduction from machine learning, usually attributed to McKinsey ([ToolsGroup summary](https://www.toolsgroup.com/blog/machine-learning-in-demand-planning-how-to-boost-forecasting)). Peer-reviewed work is more conservative: a study in the *International Journal of Logistics Research and Applications* found ML-based models delivered on average about a **5% improvement in forecast accuracy** over the benchmarks tested, while noting that even that translated into real supply chain gains. ([Feizabadi, 2022](https://www.tandfonline.com/doi/full/10.1080/13675567.2020.1803246))

Both can be true — the large numbers usually come from replacing badly-run manual processes, the small numbers from beating an already-tuned statistical baseline. The practical guidance: **measure your current forecast error first.** If nobody in your business can tell you your MAPE by material, that is the project, and it costs nothing but attention.

### Layer 2 — Price: a band, not a number

This is the layer most spreadsheets get wrong, and the one that changes how people think.

A single forecast price ("steel will be ₹61,400 next month") is a claim nobody believes and everybody plans around anyway. The honest output is a **distribution**, usually expressed as three points:

- **P10** — the price you'd beat only 10% of the time. Your realistic best case.
- **P50** — the median. Half the outcomes land above, half below.
- **P90** — the price you'd exceed only 10% of the time. Your planning downside.

A band does three things a point estimate cannot. It **shows the asymmetry** — when P90 is far above P50 but P10 is close below it, waiting is a bad bet even if the median is flat. It **makes uncertainty a number**, so a widening band automatically argues for shorter commitments. And it **gives you a language for hedging** without anyone having to be a market forecaster.

### Layer 3 — Constraints: what are you actually allowed to do?

Reality is not an unconstrained optimisation. Every real buying decision sits inside policy:

- **Minimum cover** — never fall below N days of stock for this material at this plant
- **Supplier share cap** — no supplier above X% of trailing 90-day volume (this is the "alternative sources" strategy 74% of CPOs named, expressed as a number)
- **Working capital cap** — a ceiling on cash tied up in inventory this month
- **Lead times and MOQs** — the physical constraints that make timing decisions lumpy
- **Storage and shelf life** — for materials where buying ahead has a physical cost

Inventory carrying cost is the discipline that stops "buy now" being the answer to everything. APQC benchmarking puts carrying cost at roughly **20–30% of inventory value annually** ([APQC](https://www.apqc.org/what-we-do/benchmarking/open-standards-benchmarking/measures/inventory-carrying-cost-percentage)) — so buying three months early to save 3% is a losing trade before you count the risk of obsolescence.

### Layer 4 — The play: one recommendation, with its reasoning

Layers 1–3 produce inputs. The decision layer resolves them into exactly one action per material, per week.

Five plays cover the real decision space:

| Play | When it wins | What it commits |
|---|---|---|
| **Buy now** | Cover below floor, or band trending up with a wide upside tail | Full volume, this window |
| **Wait** | Cover holds, band flat or softening, no supply risk flagged | Nothing — deliberately |
| **Partial buy** | Cover tight but band uncertain in both directions | Part of the volume now, rest exposed |
| **Split suppliers** | Volume is fine, concentration is not | Same quantity, rebalanced across sources |
| **Hedge / lock** | Long horizon where a fixed price beats spot exposure | A commitment beyond the normal window |

The value is not in the taxonomy. It is in the discipline that **every material gets exactly one of these every week**, including the ones nobody has looked at in six months. Ambiguity is what your buyers already have.

Two design rules matter here. **The reasoning must be structured, not narrated** — drivers recorded as data (`COVER_BELOW_FLOOR`, `BAND_TRENDING_UP`, `SHARE_CAP_BREACH`) rather than a paragraph of prose, so that identical inputs produce identical recommendations and disagreements can be traced to a specific driver. And **the same inputs must always produce the same output**. If your system gives a different answer on Tuesday than it gave on Monday from the same data, no buyer will ever trust it, and they will be right not to.

---

## Part 3: The Approval Question

Here is the position worth arguing for plainly: **a procurement system should recommend, and a human should decide.**

Not because the machine is unreliable. Because of what a purchase order is. It is a financial commitment, often with legal terms, made on behalf of a company, in a market with counterparties who behave strategically. The value of a named human approving it is not that they catch every error — it is that accountability stays where it can act.

What this looks like in practice:

- **Every recommendation waits.** Nothing transmits to a supplier without a buyer or approver on the record.
- **Overrides are first-class.** When a buyer disagrees, they record the reason. That reason is data — it tells you what the system does not know.
- **The record is immutable.** Inputs, drivers, recommendation, decision, approver, timestamp. Twelve months later you can answer "why did we buy 420 tonnes in week 32" with a record instead of a story.
- **Roles are enforced server-side.** Viewer, buyer, approver, admin. Not by hiding a button in the UI.

The override log is the most underrated artefact in the whole system. After two quarters you can ask the only question that matters: **when buyers overrode, were they right?** If they were consistently right on one material family, the model is missing a variable that lives in their head — go find it. If they were consistently wrong, you have a coaching conversation grounded in evidence rather than seniority.

---

## Part 4: What You Need Before You Start

A short, honest data checklist. Most manufacturers have all of this; almost none have it in one place.

**Required:**
- Purchase history: material, plant, supplier, date, quantity, unit price, currency — 24 months minimum, 36 preferred
- Consumption or issue history at the same grain
- Current inventory and open purchase orders
- Supplier lead times, MOQs, and current contracts
- A market price series for each material family (index, exchange, or your own observed prices)

**Needed to make it operational:**
- Minimum cover days per material × plant
- Maximum supplier share policy
- Who approves what, at what value

**The problems you will find** — and finding them is part of the value, whatever you build:

- Material master duplicates (the same grade under four codes, so nothing aggregates)
- Unit-of-measure drift (tonnes and kilograms in the same column)
- Prices that include freight in some rows and not others
- Consumption booked to the wrong plant
- Lead times last updated in a different decade

None of that is a reason to delay. It is a reason to start with **one category** — the one with the highest spend and the most volatility — rather than the whole material master.

---

## Part 5: Running a Pilot That Proves Something

The most common failure of procurement analytics pilots is not that they produce bad recommendations. It is that nobody can say afterwards whether they were good.

**Design the measurement before the model.**

**Step 1 — Backtest, honestly.** Run the system over the last 12 months of your own history and compare what it *would* have recommended against what your team actually did. Price the difference at real market prices. This costs nothing and takes days. Be strict: no lookahead, no using information that would not have been available in that week.

**Step 2 — Shadow mode, 6–8 weeks.** The system publishes recommendations. Buyers make decisions the way they always have. Nobody is bound by anything. You are measuring two things: **agreement rate** (how often the system and the buyer reached the same call) and **disagreement quality** (when they differed, who turned out to be right).

**Step 3 — Live on one category, with approval.** Recommendations become the default proposal; the buyer approves or overrides with a reason. Track realised cost versus the P50 band and versus the counterfactual "what we would have done".

**Step 4 — Report in money, with the assumptions visible.** Recommended versus actual, priced. Cover days maintained. Supplier concentration before and after. Working capital tied up. And the number that keeps everyone honest: **how many recommendations were overridden, and what happened next.**

Three metrics tell you whether it is working. **Realised price versus band** — are you landing below P50 more often than above it? **Cover breaches** — did the floor ever get violated? **Override outcome ratio** — of overridden recommendations, what share proved better than the system's call?

---

## What This Will Not Do

Where the ceiling sits, plainly.

It will not predict shocks. A tariff announcement, an export ban, a mine failure, a war — none of these are in your purchase history. What a band-based system *does* do is stop pretending it can: when the band widens because recent volatility spiked, the recommendation shortens commitments automatically. That is not prediction, it is humility encoded as policy.

It will not renegotiate your contracts. It will not fix a material master nobody has cleaned in nine years, though it will make the mess impossible to ignore. It will not replace a good buyer's knowledge of which supplier actually delivers in monsoon season. And it should never place an order.

What it does is answer the same question, every week, for every material, with the reasoning attached and a human's name on the decision. That is not glamorous. But when materials are 40% of your cost base and copper can move 25% in a month, being systematically slightly better at the buy-or-wait call — across hundreds of materials, every week, for years — is worth more than most of what is on the transformation roadmap.

---

## Sources

- Deloitte — [2025 Global Chief Procurement Officer Survey](https://www.deloitte.com/us/en/about/press-room/2025-chief-procurement-officer-survey.html) (12th edition; 250+ CPOs across 40 countries)
- McKinsey — [Transforming procurement functions for an AI-driven world](https://www.mckinsey.com/capabilities/operations/our-insights/transforming-procurement-functions-for-an-ai-driven-world) (October 2025)
- Reuters — [LME copper hits record highs as funds and fundamentals align](https://www.reuters.com/markets/commodities/lme-copper-hits-record-highs-funds-fundamentals-align-2025-10-30)
- CNBC — [Copper prices: what next for the red metal as LME prices hit record](https://www.cnbc.com/amp/2025/12/30/copper-prices-what-next-for-the-red-metal-as-lme-prices-hit-record.html)
- Benchmark Mineral Intelligence — [Copper hits another all-time high](https://source.benchmarkminerals.com/article/copper-hits-another-all-time-high-but-gains-fail-to-hold) (29 January 2026)
- CQG — [Copper volatility in March and April 2025](https://news.cqg.com/blogs/commentary/2025/04/copper-volatility-march-and-april-2025)
- APQC — [Inventory carrying cost as a percentage of inventory value](https://www.apqc.org/what-we-do/benchmarking/open-standards-benchmarking/measures/inventory-carrying-cost-percentage)
- BearingPoint — [Sourcing as a lever to improve manufacturing margins](https://www.bearingpoint.com/en-africa/insights-events/insights/how-manufacturing-companies-can-leverage-sourcing-to-break-negative-profit-margin-trend)
- Proxima — [The State of Spend report](https://proximagroup.com/reports-and-research/the-state-of-spend-report-and-supplier-cost-reductions)
- Feizabadi, J. (2022) — [Machine learning demand forecasting and supply chain performance](https://www.tandfonline.com/doi/full/10.1080/13675567.2020.1803246), *International Journal of Logistics Research and Applications*

---

*Voxdonna builds [Procurement Intelligence](https://voxdonna.com/procurement-intelligence.html) for manufacturers: weekly demand forecasts, P10/P50/P90 price bands, and one recommended buying play per material — with the drivers recorded as data and a named buyer approving every decision. It recommends. It never transacts.*
