---
title: "Order Change Requests by Email: Apply, Review or Refuse"
description: "How an AI agent handles emailed purchase order changes and cancellations: find the right order, read its status in the ERP, then apply, review or refuse."
date: "2026-10-31"
category: "Business Task Automation"
readingTime: "9"
keywords: "purchase order change request, purchase order cancellation email, order change request automation, sales order change management, order amendment automation, ai order desk"
noBrandSuffix: "true"
---

# Order Change Requests by Email: Apply, Review or Refuse

## The Short Answer

An emailed change to an existing order is a different job from an emailed new order. The agent must find the one order the customer means, read what has already happened to it in the ERP, and only then decide whether the change can be applied, needs a person, or must be refused. The deciding input is the order's status, not the wording of the email.

For a Customer Service Director, the result is that routine changes to untouched orders are confirmed in minutes, and everything that touches stock, credit or a shipment arrives on the order desk as a prepared decision rather than a thread to untangle.

This post describes a design pattern, not a measured result. VoxDonna's published order agent creates sales orders from purchase orders, and its acceptance cases use synthetic inputs. We have not published results for order changes, and no number below is a VoxDonna result.

## Why Changes Are Harder Than New Orders

A new order refers to nothing that exists yet. A change refers to something that does, and that something keeps moving after the customer sends the email.

Three things make the work different:

- **The email points at an order, often vaguely.** "Push the Ohio order out a week" leaves the agent to find which order, which lines, and whether the customer has two similar ones open.
- **The right answer depends on state.** The same cancellation is harmless on an order nobody has touched and costly after a delivery has been created.
- **The state can change between reading and writing.** An order that looked untouched at 3:00 pm can have a delivery by 3:02 pm.

A wrong change can quietly alter a commitment that production or the warehouse is already working to.

## A Precedent: Status Decides, Not the Request

Order systems already encode this. Oracle's documentation for the vendor portal of Oracle Retail Order Broker Cloud Service (documentation version 22.2.401.0) describes how a supplier handles retailer requests to change a delivery address or cancel a purchase order line. The outcome depends on the line's status:

| Line status | What happens to a cancellation request |
|---|---|
| New Order | Applied automatically |
| In Process or Held | Goes to the supplier to accept or decline |
| Shipped or Canceled | Rejected automatically |

The same page records three details worth copying. Cancellation requests are per line, so cancelling a whole order takes a request for each line. A second address change submitted before the first is decided automatically rejects the first. And when a request is rejected automatically because the line has already shipped or been canceled, no history record is created. That last gap is the one to avoid: a refusal that leaves no trace is the hardest kind to explain to a customer a week later. Source: [Oracle Retail Order Broker Cloud Service, Purchase Order Change Requests](https://docs.oracle.com/en/industries/retail/retail-order-broker-cloud/22.2.401.0/robvh/VendPOChanges.htm).

Caveat on scope: that is a retail drop-ship flow with its own statuses, not a manufacturer's order desk. It is evidence for the shape of the rule, not for your ERP's behavior.

## What the ERP Lets an Agent Read Before It Writes

For SAP S/4HANA, the sales order OData service `API_SALES_ORDER_SRV` returns status fields alongside the order itself. The connector reference for that service lists, on the order header, a delivery status for all items, an order-related billing status for all items, a rejection status for all items, an overall status of credit checks, a delivery block and a billing block. On each item it lists a delivery status and a reason for rejection. It also exposes operations to update an order and to update an order item. Source: [Ballerina connector reference for `API_SALES_ORDER_SRV`, version 2.1.0](https://central.ballerina.io/ballerinax/sap.s4hana.api_sales_order_srv/2.1.0).

Two notes on using that. This is a third-party connector page generated from SAP's service definition, so check field availability against your own release and configuration. And SAP's own checks stay the authority: if SAP refuses a change, the agent must catch the refusal, hold the request with its context, and not retry blind.

The practical rule that follows is simple. The agent reads status first, applies your written rules to it, and writes only when a rule says yes. It should have no right to delete an order.

## The Pipeline, Stage by Stage

An agent that a Customer Service Director can trust runs the same path on every email.

1. **Intake.** It watches the order mailbox, accepts only known customer domains, and claims each message in a durable ledger before work starts, so a restart cannot produce two replies.
2. **Extraction.** It reads the body and any attachment into a fixed schema: customer, the customer's PO number, the change type (quantity, delivery date, ship-to, line cancellation, order cancellation), the lines affected and the new values. An email that is not a change request is logged and left alone.
3. **Locate.** It matches the request to exactly one open order using the customer, the customer's PO number and the line. Zero matches or more than one means the request is held. It never picks the likeliest order.
4. **Read status.** It reads delivery, billing, block and credit status for that order and, where the change affects lines, for the lines.
5. **Rules.** Plain code compares the requested change with your policy: what may move, by how much, below what value, for which customers. Each result is recorded. No model gets a vote on whether a rule applies.
6. **Disposition.** The agent chooses apply, review or refuse, described next.
7. **Record.** An applied change is written to the ERP, a note is logged against the order or in the CRM with the thread attached, and the reply goes out in the original thread. A refusal is recorded too.

## Three Outcomes: Apply, Review, Refuse

| Outcome | When it applies | What the customer gets | What the order desk sees |
|---|---|---|---|
| Apply | One exact order match, nothing downstream of the order, no blocks, a change type your policy allows, the value inside a ceiling you set | Confirmation of the new quantity or date in the original thread | A log entry with the before and after |
| Review | A quantity increase, a ship-to change, a date pulled earlier, a new line, a partly delivered order, anything that reopens stock or credit | A note saying what was received and when to expect an answer | A prepared change with the reason it needs a person |
| Refuse | No match or several matches, an order already delivered or billed, conflicting instructions, a status that could not be read | A note naming what cannot be done and what the customer can do next | An escalation with the full thread |

Treat quantity increases and date pull-ins as review by default: they ask the company for something new, such as stock, capacity or credit. Reductions and later dates are the usual candidates for automatic handling, and only where your own history says they are routine.

Start with applying switched off. Run every change as a prepared draft for several weeks, compare each with what your team did, and enable applying only for the customer group and change type where the drafts matched.

## A Worked Example (Illustrative)

This is a constructed scenario, not customer data. A U.S. manufacturer of industrial valves and fittings receives an email from a distributor's buyer at 6:10 pm on a Thursday, quoting the distributor's PO number. It asks for four changes.

| Request | What the agent finds | Outcome |
|---|---|---|
| Move the delivery date on line 10 out by five days | Order untouched, no delivery created, no blocks | Applied; confirmation with the new date |
| Reduce line 20 from 500 to 400 pieces | Untouched, 400 is above the minimum lot | Applied; confirmation with the new quantity |
| Increase line 30 from 200 to 300 pieces | Stock and credit must be rechecked | Review; prepared change with stock and credit figures attached |
| Cancel line 40 | A delivery was created on Tuesday | Refused; escalated to the desk and warehouse |

The buyer gets a reply that evening: lines 10 and 20 are changed, line 30 is being confirmed, and line 40 cannot be cancelled automatically because it is already in delivery, with a named contact. On Friday morning the desk opens two prepared items rather than a thread. Whether to pull back the line 40 delivery is a business decision for people, with the warehouse's position in front of them.

## What Lands in the ERP and CRM

An applied change is written to the specific order lines, with the source email referenced. A note on the customer account in the CRM records what changed and who confirmed it.

Permissions are narrow. The agent updates quantity and date fields on orders that pass the rules, and logs. It does not delete orders, release blocks, edit prices or change customer master data.

The intake side of this mailbox is described in [purchase order intake](/blog/en/purchase-order-intake-automation.html) and on the [order agent page](/sap-email-agent.html). Quotes are the earlier step, covered in [RFQ automation](/blog/en/rfq-automation-manufacturers.html).

## How to Test Before It Writes Anything

Run these cases against a copy of the order mailbox and a sandbox ERP, and read the run log rather than the reply. These are acceptance criteria to run, not results we have measured.

1. **Change to an untouched order, exact match.** Expected: applied once, with a before-and-after record.
2. **Two open orders for the same customer with similar lines.** Expected: held, nothing changed, both candidates attached.
3. **Cancellation of a line whose delivery already exists.** Expected: refused and escalated, not applied.
4. **The same change email delivered twice, with a restart mid-run.** Expected: one change and one reply.
5. **A delivery created between the status read and the write.** Expected: the ERP's refusal is caught, the request is held, and the customer is not told it was applied.
6. **A quantity increase that pushes the customer over its credit limit.** Expected: review, not apply.

An agent that applies the clean change is easy to build. What matters is that it declines the other five.

## Where to Start

1. **Measure the baseline.** From the last 90 days of the order mailbox, count change requests per week, the share that arrived after a delivery existed, and the median time to confirm.
2. **Sort them by type.** Date moves, reductions, increases, cancellations. The mix tells you how much could ever be handled without review.
3. **Write the policy down.** What may move, by how much, for whom. If your desk cannot state it, an agent cannot follow it.
4. **Pilot in draft mode.** Measure how often the prepared change matches what your team would have done.

If you are weighing this against scripted automation, [AI employee vs. RPA](/blog/en/ai-employee-vs-rpa.html) covers where each fits. The wider set of manufacturing workflows is on our page for [AI agents for manufacturers](/ai-for-manufacturers.html).

## FAQ

### Can an AI agent cancel a purchase order?

For a narrow class, yes. An exact order match with nothing downstream, no blocks and a value under a ceiling you set can be handled automatically. Once a delivery or invoice exists, the agent should refuse and escalate, because the decision involves the warehouse and finance, not only the order.

### How does it avoid changing the wrong order?

It matches on the customer, the customer's PO number and the line. If that yields zero or several orders, it changes nothing and holds the request with the candidates attached.

### What about changes that arrive by WhatsApp or phone?

The pipeline is the same: extract, locate, read status, apply rules. VoxDonna's published order agent reads email, and we have not published a change-request flow on other channels, so any other channel would be scoped as a project.

### Does VoxDonna have published results for order changes?

No. This post is a design pattern built on our published order-intake pipeline. Any measured result will come from a scoped project with a stated baseline, period and method.
