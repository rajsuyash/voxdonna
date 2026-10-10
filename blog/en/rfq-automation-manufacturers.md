---
title: "RFQ Automation: Quoting Before the Buyer Calls a Rival"
description: "How an AI agent turns emailed RFQs into priced draft quotes in your ERP and CRM, which requests it may send itself, and which stay with sales ops."
date: "2026-10-10"
category: "Business Task Automation"
readingTime: "8"
keywords: "rfq automation, rfq automation manufacturers, quote request automation, automated quoting from email, ai rfq response, rfq to quote erp"
noBrandSuffix: "true"
---

# RFQ Automation: Quoting Before the Buyer Calls a Rival

## The Short Answer

RFQ automation means an AI agent reads each emailed request for quote, matches every line to your catalog, pulls price and availability from your ERP, and prepares a quotation. For a narrow class of requests it sends the quote itself. For everything else it hands your sales ops team a prepared draft with the doubtful lines flagged. The work lands in two places: a quotation document in the ERP and an opportunity record in the CRM.

The agent removes the lookup and retyping between "request arrives" and "quote is ready". It does not remove the decisions that carry margin risk. Those stay with a person until your own data shows they can safely move.

This post describes a design pattern, not a measured result. VoxDonna's published order-intake agent handles purchase orders, and its acceptance cases are synthetic. We have not published RFQ outcomes, and no number below is a VoxDonna result.

## Why the First Reply Matters, and What Is Actually Known

Most advice on RFQs repeats one idea: the supplier who answers first wins. The evidence behind it is thinner than the repetition suggests.

The best-known source is the March 2011 *Harvard Business Review* paper "The Short Life of Online Sales Leads" by Oldroyd, McElheran and Elkington. In an audit of 2,241 U.S. companies sent a web-generated test lead, 37% responded within an hour, 24% took more than 24 hours, and 23% never responded. In a separate study of 1.25 million leads across 29 B2C and 13 B2B companies, firms that contacted a lead within an hour were nearly seven times as likely to qualify it as firms that waited even one hour longer.

Two caveats apply before you carry that into quoting. The leads were web enquiries, not RFQs, and the underlying data came from the InsideSales platform, whose CEO is a co-author. We traced every figure in that literature in our [lead response time study](/blog/en/lead-response-time-study.html).

We found no independent, published benchmark for RFQ-to-quote turnaround. Vendor pages quote speed-up multiples and win-rate gains, but those are vendor marketing, so do not build a business case on them.

Build it on your own data instead. Pull the last 90 days of the shared quoting inbox and compute two numbers: the median time from the request arriving to the first reply, and the share of requests that never got a quote. Those numbers are the baseline any pilot is measured against.

## How an RFQ Differs From a Purchase Order

An order agent and a quoting agent share most of their plumbing, but the failure mode is different. A wrong order is booked and caught at acknowledgement. A wrong quote is a price or a date you have promised in writing.

| Dimension | Purchase order | RFQ |
|---|---|---|
| Buyer commitment | Already decided; wants confirmation | Comparing suppliers; no commitment |
| Output document | Sales order plus acknowledgement | Quotation with price, lead time and validity date |
| Input quality | Usually your part numbers or a contract reference | Often a description, a drawing or a competitor's part number |
| Price | Checked against an agreed price | Must be determined: list, contract, volume break, margin floor |
| Cost of a wrong answer | A bad order booked | A price promise you must honor or retract |
| Sensible default action | Post when every check passes | Draft for approval unless explicit rules allow sending |

The reading, matching, deterministic checks and audit trail from [purchase order intake](/blog/en/purchase-order-intake-automation.html) carry over. The last step is what changes: instead of posting a sales order, the agent decides between sending, drafting or holding.

## The Pipeline, Stage by Stage

An RFQ agent that a Head of Sales Ops can trust runs the same path on every email.

1. **Intake.** It watches the shared quoting mailbox, accepts known buyer domains, and sends unknown senders to a review queue. A durable ledger claims each message before work starts, so a restart mid-run cannot produce two replies.
2. **Extraction.** It reads the body and any PDF or spreadsheet attachment into a fixed schema: buyer, requested lines (description, buyer part number, quantity, unit), required-by date, ship-to and response deadline. An email that is not an RFQ is logged and left alone.
3. **Matching.** Each line is matched against your catalog and the customer's cross-reference table. The result per line is exact match, probable match or no match, and a probable match is never priced as if it were exact.
4. **Price and availability.** It reads customer-specific price, volume breaks, stock and standard lead time from the ERP. This step is read-only, and no model generates a price.
5. **Rules.** Plain code checks the margin floor, customer credit or blocked status, minimum order quantity, quote validity and any item that needs engineering review. Each result is recorded.
6. **Disposition.** The agent chooses to send, draft or hold, as described in the next section.
7. **Record.** The quotation is written to the ERP, an opportunity or activity is logged in the CRM with the thread attached, and the reply goes out in the original email thread.

## Three Outcomes: Send, Draft, Hold

| Outcome | When it applies | What the buyer gets | What sales ops sees |
|---|---|---|---|
| Send | Every line is an exact match, price comes straight from contract or list, stock covers the quantity, margin is above the floor, the customer is in good standing, and the total is under a ceiling you set | A quotation in the original thread within minutes | A log entry |
| Draft | Any probable match, a discount outside the rules, or a lead time that misses the required-by date | A holding note naming what is being confirmed and when to expect the quote | A prepared quotation with the flagged lines highlighted |
| Hold | Blocked customer, no match, a drawing needed, conflicting quantities, an unreadable attachment, or an ERP lookup that failed | A holding note naming what is missing | An escalation with the reason attached |

Start with sending switched off. Run every RFQ as a draft for several weeks and compare each draft with the quote your team would have written. Enable sending only for the customer group and value ceiling where the drafts matched, and widen it from there.

## A Worked Example (Illustrative)

This is a constructed scenario, not customer data. A U.S. manufacturer of industrial fasteners and fittings gets an email from a distributor's buyer at 8:40 pm on a Friday. A PDF attached to the email lists five lines.

| Line | What the buyer asked for | What the agent does | Outcome |
|---|---|---|---|
| 1 | 5,000 pieces under the buyer's own part number | Cross-reference gives one exact material; contract price applies; stock covers it | Priced |
| 2 | 2,000 pieces, "zinc plated", with two zinc finishes in the catalog | Probable match only; will not pick a finish | Flagged for sales ops |
| 3 | 500 pieces of an item with a 1,000-piece minimum | Will not change the quantity on its own | Flagged for sales ops |
| 4 | 3,000 pieces with no stock | Quotes the ERP's standard lead time, which misses the required-by date | Flagged for sales ops |
| 5 | "Custom bracket per attached drawing" | No catalog match; needs engineering | Held |

Four of five lines need a person, so the whole request is a draft. The buyer still receives a reply that night: five lines received, line 1 priced, lines 2 to 5 being confirmed, and the time by which the company has committed to answer. Whether to send a partial quote or wait for a complete one is a business policy, and the agent applies whichever one you choose.

On Monday, sales ops opens one prepared draft with the open questions listed, rather than a PDF to retype. The gain is in the first hours and in the retyping. The review step is still there.

## What Lands in the ERP and CRM

The agent writes a quotation document to the ERP carrying the matched materials, the price and its source, the lead time and the validity date. In the CRM it creates or updates an opportunity or activity, links the email thread and assigns an owner.

Because it writes into customer systems, the permissions are narrow: it creates quotations and logs activity, and it never edits price lists, customer records or material master data. The same email arriving twice produces one quotation. A failed check creates nothing.

For the order side of the same mailbox, see how [sales and purchase order intake](/sap-email-agent.html) works in the published pilot.

## How to Test Before It Writes Anything

Run these cases against a copy of the quoting mailbox and a sandbox ERP, and read the run log rather than the reply. These are acceptance criteria to run, not results we have measured.

1. **Clean RFQ from a known buyer, every line an exact match.** Expected: a draft, or a send if your rules allow it.
2. **A buyer part number missing from the cross-reference.** Expected: that line is held and nothing is invented.
3. **The same RFQ delivered twice, with a restart mid-run.** Expected: one reply in total.
4. **A quantity in the email body that contradicts the PDF.** Expected: held, with both readings attached.
5. **A customer on credit hold.** Expected: no quote, and an escalation.
6. **An ERP price lookup that times out.** Expected: no price is guessed and the request is held.

The agent that quotes the clean case is easy to build. What matters is the five it must refuse to guess on.

## Where to Start

1. **Measure the baseline.** Take the median time to first reply and the share of requests with no quote from the last 90 days.
2. **Find your exact-match ceiling.** Estimate what share of RFQs come from repeat buyers asking for catalog items. That share bounds how much could ever be sent without review.
3. **Fix the cross-reference table first.** Buyer part numbers mapped to your materials are usually the real bottleneck, not the model.
4. **Pilot in draft mode.** Measure how often the draft matches what your team would have sent.

If you are weighing this against scripted automation, [AI employee vs. RPA](/blog/en/ai-employee-vs-rpa.html) covers where each one fits. The wider set of manufacturing workflows is on our page for [AI agents for manufacturers](/ai-for-manufacturers.html).

## FAQ

### Can an AI agent send quotes without a human approving them?
For a narrow class, yes. Exact-match lines at contract or list price, with stock available, margin above the floor and a customer in good standing, can be sent automatically below a value ceiling you set. Everything outside that class goes to a person as a draft.

### How is this different from CPQ software?
CPQ configures and prices products from structured input inside your own system. An RFQ agent works upstream of that: it reads the emailed request, with its mixed formats and buyer part numbers, into the structured input a pricing engine or ERP can use. Many teams will want both.

### Which ERPs does it work with?
VoxDonna's order-intake page is written for SAP, Oracle and Dynamics, but its published acceptance cases run against a pilot backend with synthetic inputs, not a customer's production ERP. An RFQ project is scoped against the quotation and price-lookup interfaces of your specific ERP, and we do not publish a supported-connector list for quoting.

### Does VoxDonna have published RFQ results?
No. This post is a design pattern built on our published order-intake pipeline. Any measured result will come from a scoped project with a stated baseline, period and method.
