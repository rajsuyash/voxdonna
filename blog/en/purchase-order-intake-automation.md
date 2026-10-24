---
title: "Purchase Order Intake Without Re-Typing It"
description: "Purchase order intake automation: an agent reads PO emails, checks each line against ERP data, books only clean orders and escalates the rest."
date: "2026-10-24"
category: "Business Task Automation"
readingTime: "9"
keywords: "purchase order intake automation, automated po processing, erp order entry automation, sap purchase order automation, po intake ai agent, purchase order processing manufacturing, po exception handling"
noBrandSuffix: "true"
---

# Purchase Order Intake Without Re-Typing It

Purchase order intake automation means an agent reads each customer PO that arrives by email, matches every line to your ERP master data, runs your validation rules, and creates the sales order only when every check passes. Anything that fails a check is held and sent to a named person with the reason attached. The part worth testing before you buy is not how well it reads the PDF but what it refuses to book. [VoxDonna's order-intake agent](/sap-email-agent.html) is built around that refusal rule; this article shows how to test it.

---

## The Monday Morning PO Stack

An illustrative scenario, not a customer account: a sales administrator at a precision components manufacturer in Germany arrives at 08:30 and opens the order mailbox. Thirty-one purchase orders arrived over the weekend, from automotive suppliers, aerospace maintenance shops and industrial distributors. Every one has to be keyed into SAP SD.

The orders are simple in content: these parts, these quantities, this delivery date. The difficulty is in the intake.

One customer sends a PDF with its own part numbers, and none match the SAP materials catalogue. A translation table covers most of them; the rest need a manual lookup. An aerospace shop quotes lengths in feet while the SAP material is priced per metre. A distributor writes the order in the email body with no attachment, which breaks any tool that only reads PDFs.

Assume eight to fifteen minutes per clean order. That assumption is ours, for the scenario. At that rate, 31 orders take roughly four to eight hours (31 × 8 = 248 minutes; 31 × 15 = 465 minutes). That is most of Monday morning.

EDI works for customers who can send structured messages. The orders that still get re-typed come mostly from customers who will not, who email a PO in their own format.

---

## Three Layers of PO Intake Complexity

**Format variation.** Every buyer has its own template: ERP-generated PDFs, forms printed to file, Excel attachments, plain email text. A tool tuned for one layout produces noise on the others.

**Code translation.** The buyer's item code is its internal reference and the seller's SAP material number is another. There is no universal cross-reference, so a manufacturer with hundreds of customers either maintains hundreds of translation tables or relies on someone remembering. An out-of-date table puts the wrong material on the order.

**Validation.** Before SAP SD will take a sales order, several questions need answers that are not on the PO: does the price match the agreed contract or price list, is the quantity above the minimum lot, is the ship-to a known address, is the customer inside its credit limit, is the customer blocked. Each is a lookup in a different place.

A human administrator does all of this from experience. It is slow and error-prone at volume, not hard.

---

## Why OCR Stops Halfway

OCR turns a document into text and fields. On a consistent layout it extracts customer name, order number, line items, quantities and dates well. It does not translate the buyer's code to your material number without a current mapping, and it has no connection to the ERP where validation happens. A new layout from a customer also breaks a template-based setup until someone builds another template.

The usual result is a hybrid: OCR handles tidy documents from a few large customers and people handle the rest. The workload shrinks but the typing job stays.

| Step | Manual entry | OCR alone | Order-intake agent |
|---|---|---|---|
| Read the order | Human reads and types | Field extraction; a new layout needs a new template | Reads body text or a PDF into a schema-validated order |
| Match lines to master data | Human looks up customer, material and ship-to | Returns the raw buyer code | Matches against customer, material and ship-to data; unmatched lines are held |
| Check price, minimum quantity, credit limit | Human checks several screens | Not applicable | Deterministic rules with a recorded result per check |
| Create the order | Human enters it | Not applicable | Creates it only if every check passed |
| Handle exceptions | Human resolves them | Flags document-level errors | Holds the order, replies to the sender that it is held, escalates to a named person |

Two of those cells carry the design. The checks are plain code, not a model's judgement, so the same PO gets the same decision every time and the run log can show which rule fired. And a failed check stops the order. A guessed order costs more than the typing it saved.

---

## Six Cases an Order Agent Must Pass Before It Writes to Your ERP

The acceptance pack on the order-intake page defines six cases. Run them against a copy of your mailbox and your master data, and read the run log rather than the reply. A correct acknowledgement on a clean order proves little; the risk sits in the other five.

| Case | What arrives | Correct behaviour |
|---|---|---|
| 01 Clean order | Allowlisted buyer, PDF PO, known materials, quantities above the minimum lot, inside credit limit | Order created; acknowledgement carries the real order number |
| 02 Unknown party or material | Ship-to not in master data, one line with free text and no material code | Nothing created; holding reply names what is missing; escalation to the order desk |
| 03 Duplicate and retry | The case 01 email delivered twice, agent restarted mid-run | One order and one reply, not two |
| 04 Unreadable attachment | Half-legible scan; body quantity contradicts the PDF quantity | Nothing guessed; holding reply asks for a readable order; escalation with both readings |
| 05 ERP failure | A timeout, and an error returned after the write may have landed | No success assumed; run held for reconciliation; customer is not told an order exists |
| 06 Approval boundary | Valid order above the value your rules reserve for a human | Held until a named approver releases it; acknowledgement of receipt only |

Status of this evidence, stated plainly: the expected outcomes above are the acceptance criteria, run against a simulated pilot backend with synthetic inputs. They are not measured results from a customer's production ERP. Connector-tested and production outcomes are recorded separately per deployment and VoxDonna has not published them. The [Usha Martin case study](/case-studies/usha-martin.html) covers complaint intake, not order processing, so it is not evidence for this workflow.

Use the same six cases to test any vendor, including us.

---

## What SAP Integration Needs: Least Privilege

Connecting an agent to SAP SD is not the same as giving it read access to a report. Order creation needs write access, and write access should be scoped the way you would scope a junior sales administrator. This is the scope we would ask for, as a design recommendation:

- Read access to customer master (XD03), material master (MM03) and pricing conditions (VK13)
- Write access to sales order creation (VA01), restricted to the relevant sales organisation and distribution channels
- No access to billing (VF01), financial postings or credit master maintenance

SAP's own checks stay the authority. If SAP rejects an order for a credit block, a missing mandatory field or a plant-to-customer combination that is not permitted, the agent must catch the rejection, hold the order with full context, and not retry blind. A silent retry after a rejection can create duplicate records or hide a credit situation that needed a person. That is case 05 above in practice.

The order-intake page states that the last step has been built for SAP, Oracle and Microsoft Dynamics and that pilots run against a simulated backend first, so the first connection to your own sandbox ERP is a separate test.

---

## What Changes for the Sales Administration Team

Automating the structured part of intake changes what the team does; it is not a headcount argument. Take a hypothetical manufacturer receiving 150 POs a week where 80 percent are well-formed and fully mappable. Those figures are an assumption, not a benchmark. On that assumption 120 orders go straight through and 30 still need a person: new customers with no code mapping, pricing disputes, credit holds. The team handles 30 decisions instead of 150 keying tasks, and spends the time extending code mappings and reading pricing exceptions that signal a customer testing a rate renegotiation. The same intake logic applies to [spare parts and consumables orders](/blog/en/voice-agent-spare-parts-ordering.html) that run alongside standard POs.

The honest measure for your site is the exception rate and error rate against your current manual baseline, taken from your own orders. A pilot on one mailbox with a small sender allowlist is how to get that number.

---

## The EU Backdrop: E-Invoicing Covers the Invoice, Not the Order

For manufacturers selling in the EU, e-invoicing mandates are changing the invoice side of the order-to-cash cycle. They do not change how a purchase order reaches your ERP. Dates as published by the sources below:

- **Italy:** B2B and B2C e-invoicing has been mandatory since January 2019, through the Sistema di Interscambio ([European Commission country sheet](https://ec.europa.eu/digital-building-blocks/sites/spaces/einvoicingCFS/pages/658735784/Italy+2023+eInvoicing+Country+Sheet)).
- **Germany:** companies had to be able to receive structured e-invoices from 1 January 2025; issuing becomes mandatory for large businesses from 2027 and for all businesses by 2028 ([European Commission](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467108886/eInvoicing+in+Germany)).
- **France:** from 1 September 2026 every business must be able to receive e-invoices and large and mid-sized companies must issue them; smaller businesses must issue from 1 September 2027 ([AIFE, French state agency](https://aife.economie.gouv.fr/nos-applications/facturation-electronique-b2b/)).
- **EU level:** the ViDA package was adopted on 11 March 2025 and entered into force on 14 April 2025. It lets Member States introduce mandatory e-invoicing under specific conditions, with digital reporting for cross-border B2B transactions from 1 July 2030 ([European Commission](https://taxation-customs.ec.europa.eu/taxation/vat/vat-digital-age-vida_en)). Directive 2014/55/EU, with a transposition deadline of 27 November 2018, concerns e-invoicing in public procurement ([EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32014L0055)).

A customer who emails a PO today will most likely keep emailing it. An order agent complements e-invoicing; it does not replace it. The comparison of manual entry, EDI and AI agents is on the [sales order automation page](/sales-order-automation.html).

---

## FAQ

**What happens when a buyer changes the PO template?**

The agent reads the document's content and does not depend on fixed field positions. Extraction is validated against a schema, so a half-read PO fails loudly and is held instead of booking part of an order. Expect more orders to go to a person for a while, and review the exception log after a major customer changes its template.

**Can it handle partial deliveries and blanket releases?**

Not as a given. A blanket order releases quantities against an agreed total, which in SAP means scheduling agreements (VA31/VA32) rather than a standard sales order, and the integration scope needs write access to them. Neither is in the six published acceptance cases, so treat it as scoping work to agree before a pilot.

**What accuracy should we expect?**

We have not published a production straight-through rate for order intake, and a number without a denominator or method is not useful. Ask instead how the exception rate and the wrong-order rate compare with your manual process, measured on a sample of your own POs.

**How does it interact with credit management?**

Credit limit is one of the deterministic checks the agent runs, and SAP's own credit control remains the authority. An order from a customer over its limit is not booked: it is held, the sender receives a holding note, and the escalation goes to your order desk.

**How long does a deployment take?**

There is no published timeline. Cost and effort follow order volume and the number of rule sets and plants behind the mailbox, and the scope is sized with you before anything is signed. A pilot runs on one mailbox with a small allowlist.

---

*Further reading:*
- [Sales Order Automation: AI vs EDI vs Manual](/sales-order-automation.html)
- [RFQ Automation: Answering Quote Requests Before the Buyer Asks a Competitor](/blog/en/rfq-automation-manufacturers.html)
- [Complaint Handling Automation for B2B Manufacturers](/blog/en/voice-ai-b2b-complaint-handling.html)
- [Spare Parts Ordering on WhatsApp: Automating the Repeat Request](/blog/en/voice-agent-spare-parts-ordering.html)
