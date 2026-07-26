---
title: "The Customer Who Defaults Was in the News First"
description: "Around 43% of US B2B credit sales are overdue and 5% of long-overdue invoices get written off, while global insolvencies are rising for a fifth straight year. Almost every default is preceded by public signals nobody on the credit desk had time to read. Here is how to build an early-warning system that catches them without drowning your team in alerts."
date: "2026-07-26"
category: "Risk"
readingTime: "13"
keywords: "B2B credit risk, customer risk intelligence, adverse media monitoring, early warning system credit, bad debt prevention, days sales outstanding, trade credit risk, portfolio monitoring, entity resolution, credit desk automation"
---

# The Customer Who Defaults Was in the News First

## The postmortem always looks the same

A customer stops paying. Ninety days pass. Collections escalates. Legal gets involved. Eventually somebody writes off the balance and the account gets a line in the bad-debt schedule.

Then somebody does a postmortem, types the company name into a search engine, and finds it: a regulatory investigation opened eleven months ago. Two supplier recovery suits filed the quarter after that. A ratings action. An auditor resignation. All public. All free. All published while your team was still shipping to them on 90-day terms.

Nobody was negligent. The information existed in a form nobody had time to consume — spread across trade press, court filings, and regional outlets, mixed in with a hundred harmless mentions of the same company name and a few dozen mentions of a completely different company with a similar one.

This article is about closing that gap, and about the reason most attempts fail: not the finding, but the filtering.

---

## Part 1: The Numbers Behind the Anxiety

### Overdue is normal now, and write-offs are not rare

Atradius runs one of the more useful recurring surveys in this area, the Payment Practices Barometer. Its **2025 North America edition** (published September 2025) reports:

- **United States:** 43% of credit-based B2B sales are overdue; bad debts now affect **5% of long-overdue invoices**; 35% of firms report payment behaviour worsening
- **Canada:** overdue invoices at 44% of B2B credit sales; bad debts around **6%** of long-outstanding invoices; **50% of companies expect the insolvency picture to deteriorate**
- **Mexico:** overdue at 41% of credit-based sales; bad debts around 4%

([Atradius, B2B payment practices trends in North America 2025](https://group.atradius.com/knowledge-and-research/reports/b2b-payment-practices-trends-in-north-america-2025))

The same survey series for **Western Europe 2025** puts bad debts at an average of **6% of B2B invoices**. ([Atradius Western Europe 2025](https://group.atradius.com/knowledge-and-research/reports/b2b-payment-practices-trends-western-europe-2025))

### The macro trend is not helping

Allianz Trade's Global Insolvency Outlook expects global business insolvencies to rise **+6% in 2025 and a further +5% in 2026**, before a modest –1% in 2027 — making 2026 the **fifth consecutive year of increases**, with the firm estimating **2.2 million jobs directly at risk globally** in 2026. ([Allianz Research](https://www.allianz.com/en/economic_research/insights/publications/specials_fmo/251021-insolvency-outlook.html))

You do not need to believe any specific forecast to take the point. You are extending credit into a market where counterparty failure is trending up, not down, and where roughly two in five of your invoices are already late.

### What one write-off actually costs

Credit teams are usually good at this arithmetic and the rest of the business is usually not, so it is worth putting on the table.

A write-off is not a cost of the amount written off. It is a cost of **the sales needed to replace it**.

Take a business with a **7% net margin** that writes off **$250,000**:

- Replacement sales required = $250,000 ÷ 0.07 = **$3.57 million**

At the win rates from the first article in this series — call it 21% on qualified opportunities, $85K average deal — that is roughly **42 new deals**, from about **200 qualified opportunities**, which is most of a year for a mid-sized sales team. To stand still.

Run this with your own margin and average deal size. It reframes the credit desk from a cost centre that slows down sales into the function with the highest revenue-equivalent output in the building.

And note where the leverage sits in time. Collection effectiveness decays fast — one industry compilation of receivables data reports success rates falling from roughly 65% when contact happens within 24 hours of a missed payment, to about 45% at three days, 30% at a week, and 15% beyond two weeks ([CreditPulse](https://www.creditpulse.com/blog/days-sales-outstanding-dso-by-industry-2025-benchmarks-data-analysis) — a vendor compilation, so treat the exact figures as directional). If two weeks of delay costs that much recovery, the value of knowing *months* earlier is not marginal.

---

## Part 2: Why Your Existing Setup Misses It

Most companies already do something. That something usually has one of four failure modes.

### Failure 1 — Diligence that expires

Credit assessment happens at onboarding. The file was accurate the week it was written. Then the customer trades with you for four years, the exposure grows, and nothing re-checks the assumption. The riskiest accounts are frequently the oldest ones, because that is where limits crept up quietly on the strength of a long relationship.

### Failure 2 — Alerts that are 95% noise

Someone sets up keyword alerts on the top 50 customers. Within a month the team is receiving product launches, hiring news, conference sponsorships, and stories about a company in another country that happens to share the name. The real signal is in there. Nobody reads it, because the last forty were junk.

**This is the core problem, and it is worth stating precisely: the job is not finding mentions. The job is discarding the 95% that do not change your exposure, and being right about the 5% that do.** A system that surfaces more is worse, not better.

### Failure 3 — Name collisions

"Acme Industrial" is a company in Ohio, a company in Gujarat, and a dormant shell in Cyprus. Your ledger holds one of them. Adverse news about the other two is not a warning — it is a false alarm that trains your team to ignore the channel.

This is why serious systems do **entity resolution first**: resolving each ledger row to a canonical legal entity with a verified domain, country, and legal name before any monitoring runs. Rows that cannot be resolved confidently should be flagged for human review, not guessed at. A guess here poisons everything downstream.

### Failure 4 — Financial data that arrives late by design

Bureau reports and filed accounts are genuinely valuable, and nothing here suggests replacing them. But they share a structural limitation: they describe a period that has ended. Annual accounts can be six to eighteen months behind reality. Payment-behaviour data is faster but still lags the underlying event.

A regulatory investigation, a supplier suit, an executive departure, a plant shutdown — these are public within days. The gap between "something has gone wrong" and "the numbers show something went wrong" is exactly the window an early-warning system is built to occupy. It is also the framing used by banking supervisors: Moody's describes early-warning systems as tools to identify potential material credit deterioration **at an early stage**, before it shows up in performance data. ([Moody's](https://www.moodys.com/web/en/us/insights/resources/banking-resiliency-adaptation.pdf))

---

## Part 3: Scoring That Survives Contact With a Credit Committee

Once you have confirmed entities and a stream of candidate news, you need to turn text into something a credit committee can act on. Four principles.

### 1. Score across separate vectors

A single "risk score" hides what kind of risk it is, and different kinds demand different responses. Four vectors cover most of what matters to a trade creditor:

| Vector | What it captures | Why a creditor cares |
|---|---|---|
| **Legal / regulatory** | Investigations, fines, sanctions, litigation, consent orders | Most predictive of sudden, severe deterioration |
| **Financial** | Insolvency filings, defaults, distressed refinancing, auditor resignations | Direct read on ability to pay |
| **Reputational** | Fraud allegations, executive misconduct, boycotts | Predicts counterparties leaving, which becomes financial |
| **Operational** | Shutdowns, recalls, strikes, breaches, supply failures | Predicts short-term inability to pay on time |

Separate vectors also let different people filter differently. A credit manager and a supply chain manager care about opposite ends of that table, from the same feed.

### 2. Aggregate with a maximum, not an average

This is the most consequential design decision in the whole system, and the easiest to get wrong.

If an article scores 90 on legal/regulatory and 10 on the other three, the average is 30 — comfortably below any sane alert threshold. **A regulatory action that could end the company gets buried by three quiet scores.**

Aggregate with a weighted maximum instead. Severity in one dimension must survive to the top. The purpose of an early-warning system is to be woken by the one thing that matters, not to compute a tidy composite.

### 3. Weight by source authority

A regulator's own filing, a national business daily, and an aggregator repost of a repost are not equal evidence. Multiply the score by a source-authority factor. This is also your main defence against coordinated or manipulated coverage.

### 4. Require entity confirmation as a hard gate

Even after entity resolution, each article needs a binary check: **is this actually about our entity?** Not the parent, not the similarly-named subsidiary, not the founder's other venture. An article that fails this gate is discarded before scoring, not scored and shown with a caveat. Caveats do not survive a busy Tuesday.

---

## Part 4: Building the Monitoring Loop

A system that watches everything equally will bankrupt your attention. Tier it.

### Step 1 — Segment the portfolio by exposure, not by revenue

Rank customers by **credit exposure × payment terms × concentration**, not by sales. Your largest customer may be your safest; the risk is often a mid-sized account on long terms in a stressed sector.

A workable starting split:

| Tier | Typical share of accounts | Monitoring frequency |
|---|---|---|
| **Tier 1** — top exposure, long terms, stressed sectors | 5–10% | Daily |
| **Tier 2** — material exposure | 20–30% | Weekly |
| **Tier 3** — long tail | Remainder | Monthly |

Attention costs money. Spend it deliberately.

### Step 2 — Set a threshold you will actually honour

Pick the score above which a human is interrupted, and be honest about capacity. If your credit team can act on five alerts a week, set the threshold that produces five — not the one that produces forty and gets muted in a fortnight.

Then **tune it with feedback**. Every alert should be markable as useful or not, and that judgement should move the threshold. A system without a feedback loop degrades into the keyword alerts you already ignore.

### Step 3 — Write the action playbook before the first alert

An alert with no defined response is anxiety, not risk management. Decide in advance, in writing:

- **Score 40–59:** note on file, review at next scheduled credit review
- **Score 60–74:** credit manager reviews within 5 working days; consider limit reduction or shortened terms
- **Score 75–89:** limit frozen pending review; account manager makes contact; consider security or prepayment
- **Score 90+:** stop-ship decision escalated same day; legal and finance notified

The numbers are yours to set. What matters is that they exist before the alert, so the response is policy rather than a judgement call made under pressure by whoever happened to open the email.

### Step 4 — Keep the evidence

Capture the article as it appeared, not just a link. Pages get taken down, edited, or paywalled; your credit file needs to hold six months later, in front of an insurer, an auditor, or a court.

This matters commercially too. If you carry credit insurance, documented monitoring and a documented response strengthen your position at claim time. "We didn't know" is a weaker file than "we knew on 14 July, we reduced the limit on 16 July, here is the evidence and the decision record."

### Step 5 — Close the loop with your own ledger

The strongest early-warning signal is not news at all. It is a customer who has silently drifted from paying at 42 days to paying at 61 over two quarters. Adverse media tells you something happened in the world; payment behaviour tells you it reached their treasury. **Together they are far better than either alone**, and one of the two is already in your ERP.

---

## Part 5: A 30-Day Start

You do not need a platform decision to begin. You need a list.

**Week 1 — Build the exposure map.** Export every customer with an open credit line. Add current balance, terms, and any concentration flags. Rank by exposure. Take the top 50. This alone surfaces surprises in most companies — accounts nobody has reviewed in years sitting near the top.

**Week 2 — Resolve the entities.** For those 50, confirm the exact legal name, the registered country, and the primary domain. Note the parent and any subsidiaries you actually trade with. This is unglamorous and it determines everything downstream.

**Week 3 — Run a manual backtest.** For each of the 50, search adverse-media terms — investigation, lawsuit, insolvency, default, sanctions, recall, strike, breach — and record what you find. Two questions matter: **how many findings were material**, and **how many did your team already know about?** In most portfolios the answer to the second is "fewer than we assumed", and that gap is the business case.

**Week 4 — Write the policy.** Thresholds, owners, response actions, evidence retention. One page. Circulate it to sales as well as finance, because the first real alert will land on an account somebody has a relationship with, and that argument is much easier to have before it happens than during.

If, at the end of the month, the manual process found things worth acting on, automate it. If it found nothing across 50 accounts and two years of history, you have learned something valuable for the price of four weeks of attention, and you should spend your budget elsewhere.

---

## What This Does Not Replace

The boundary matters, both for expectations and for credibility.

This is not a credit bureau, and it does not parse financial statements. It will not tell you a company's current ratio or its covenant headroom. If you have bureau data, keep it; if you have credit insurance, keep that too.

It will not predict a fraud that nobody has written about. It will not catch the private distress of a family-owned firm with no press coverage — which is precisely why the payment-behaviour signal from your own ledger belongs alongside it.

And it will produce false positives. An investigation gets dropped. A lawsuit is meritless. A recall turns out to be trivial. The measure of the system is not zero false positives — it is whether the flags a human reviews are worth the ten minutes it takes to review them.

What it does is remove a specific, expensive excuse: that the information was not available. With around **43% of US B2B credit sales overdue**, **5–6% of long-overdue invoices written off**, and insolvencies climbing for a fifth straight year, the signals are public, they are cheap, and they are almost always earlier than the ledger.

The customer who defaults was in the news first. The only question is whether anyone on your side was reading.

---

## Sources

- Atradius — [B2B payment practices trends in North America 2025](https://group.atradius.com/knowledge-and-research/reports/b2b-payment-practices-trends-in-north-america-2025) (September 2025)
- Atradius — [B2B payment practices trends in Western Europe 2025](https://group.atradius.com/knowledge-and-research/reports/b2b-payment-practices-trends-western-europe-2025)
- Allianz Research — [Global Insolvency Outlook 2026–27](https://www.allianz.com/en/economic_research/insights/publications/specials_fmo/251021-insolvency-outlook.html) (October 2025)
- Moody's — [Banking resiliency and adaptation: early warning systems](https://www.moodys.com/web/en/us/insights/resources/banking-resiliency-adaptation.pdf)
- Thomson Reuters — [Using adverse media screening](https://www.thomsonreuters.com/en-us/posts/investigation-fraud-and-risk/adverse-media-screening)
- Tanaka, K. et al. (2025) — [A multi-stage financial distress early warning system](https://www.mdpi.com/1911-8074/18/4/195), *Journal of Risk and Financial Management*
- CreditPulse — [DSO by industry: 2025 benchmarks](https://www.creditpulse.com/blog/days-sales-outstanding-dso-by-industry-2025-benchmarks-data-analysis) (vendor compilation; collection-decay figures are directional)

---

*Voxdonna builds [Customer Risk Intelligence](https://voxdonna.com/customer-intelligence.html): upload the portfolio once, every entity gets resolved and watched, every finding gets scored across four risk vectors, and only the material ones reach your credit desk — with the evidence attached.*
