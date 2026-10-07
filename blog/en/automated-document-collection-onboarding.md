---
title: "Chasing Documents: Automating Onboarding Follow-Up"
description: "A buyer pays the booking amount, then the paperwork stalls. How an AI agent chases KYC and loan documents on WhatsApp and updates the CRM checklist."
date: "2026-10-03"
category: "Business Task Automation"
readingTime: "8"
keywords: "automated document collection, document collection automation, customer onboarding document chasing, whatsapp document collection, real estate kyc document collection, ai agent crm checklist update"
noBrandSuffix: "true"
---

# Chasing Documents: Automating Onboarding Follow-Up

## Booking Day Is Not the Finish Line

A relationship manager at a residential developer in Pune closes a booking on Saturday. The buyer pays the booking amount, shakes hands, and leaves happy. By Wednesday the file is stuck.

The bank needs salary slips and three months of statements. The developer's compliance team needs identity and address proof for every co-applicant. The allotment paperwork needs a signed copy. The buyer, who has a day job, sends a blurry photo of one PAN card to the relationship manager's personal WhatsApp at 11pm and considers the matter handled.

Nobody here is careless. The task is built to fail by hand: one person owns forty open files, each missing a different two or three items, and the chasing happens whenever there are ten free minutes.

This post covers that one task: collecting the documents a buyer owes after booking, and keeping the CRM checklist accurate while it happens. The example is an Indian residential developer; the pattern applies wherever onboarding stalls on paperwork the customer supplies.

## What the Task Actually Is

"Document collection" sounds like one job. It is four.

1. **Knowing what is owed.** The list differs by buyer type. A salaried resident, a self-employed buyer, an NRI and a joint application each trigger a different set, and the bank financing the purchase may add its own items on top of the developer's.
2. **Asking, and asking again.** Each missing item needs a request, then a reminder, then a different reminder when the first one is ignored.
3. **Checking what arrives.** A file that is the wrong document, belongs to the wrong person, is cropped, or has expired is worse than no file, because the checklist now says "received".
4. **Recording it.** The CRM should show, per buyer and per document, what was asked, what came back and who accepted it.

Most teams manage all four from a spreadsheet and memory. The usual first automation covers only the second, a scheduled reminder blast, and it fails.

## Why Reminder Blasts Do Not Work

A generic reminder ("Please send your pending documents") makes the buyer do the work of figuring out which ones. A request with unclear effort is easy to defer, and a deferred request on a busy weekday often stays deferred.

A useful request is specific and small: "We still need your latest salary slip. A photo is fine; please make sure all four corners are visible." One item, one instruction, one reply.

There is a second failure in the blast model. It does not know what has already arrived. If a document came in at 2pm and the reminder goes out at 5pm, the buyer is chased for something they sent. The buyer's next message to a human is an annoyed one.

The reminder has to read the checklist before it speaks. That is the point at which this stops being a scheduler and becomes [an AI employee with a defined job](/blog/en/ai-employee-vs-rpa.html).

## What the AI Employee Does, Step by Step

The agent works on [WhatsApp](/whatsapp-donna-agents.html), where Indian buyers already are, and writes to the CRM the sales operations team already uses. The comparison with the manual process looks like this:

| Step | Manual | AI employee |
|---|---|---|
| Build the checklist | RM remembers or copies from last file | Generates it from buyer type, financing route and co-applicants recorded in the CRM |
| Request | Ad hoc message from RM's phone | Sends one request per item, in the buyer's language, from the company's number |
| Receive | Photo lands in a personal chat | Image or PDF lands in the company's document store, linked to the buyer record |
| Check | Accepted if it looks roughly right | Checks type, legibility, that the name matches the buyer, and that dates are current |
| Correct | RM notices later, often at the loan stage | Replies at once: "This looks like page 2 only; can you send page 1?" |
| Record | Spreadsheet, if updated | CRM checklist status changes per document, with received date and file reference |
| Escalate | RM remembers eventually | After a set number of tries, flags the file to the RM with the reason and stops |

Two boundaries matter. First, the agent checks whether a document is usable. Whether an identity document is genuine, and whether the buyer passes the developer's KYC rules, stays with a named human on the compliance team. The agent's job is to make sure that person receives a complete, readable file, not to make the compliance decision. Second, it never improvises the checklist. If the buyer type does not map to a defined list, it asks the RM rather than guessing.

For the upstream step, how the enquiry became a qualified buyer in the first place, see [what an AI lead qualifier actually asks](/blog/en/ai-lead-qualification-what-it-asks.html). Document collection starts where qualification ends.

## Four Channel Facts That Shape the Design

These are properties of WhatsApp and of Indian data rules that change how the workflow has to be built. Each is checked against the platform or government source.

The first fact is the 24-hour window. When a buyer messages your business number, a 24-hour customer service window opens, and you can send free-form replies inside it. Outside the window, Meta requires a pre-approved template message ([Meta for Developers, WhatsApp Business Platform documentation](https://developers.facebook.com/documentation/business-messaging/whatsapp/messages/send-messages/)). For document chasing, the first request after a quiet week must go out as an approved template, so it should ask for the single most useful item; the buyer's reply reopens the window.

The second is file size. The Cloud API accepts images up to 5 MB and PDFs up to 100 MB ([Meta media reference](https://developers.facebook.com/docs/whatsapp/cloud-api/reference/media/)). A single-page document photographed on a phone can exceed 5 MB, and a multi-page bank statement is better requested as a PDF. The agent should say which format it wants.

The third is that media does not stay on WhatsApp. Meta states that media files sent through the API persist for 30 days unless deleted earlier. A developer that treats WhatsApp as the filing cabinet will lose documents. The agent has to download each file on receipt and write it to the company's own document store, with the CRM holding the reference.

The fourth is consent and purpose. India notified the Digital Personal Data Protection Rules, 2025, which operationalise the DPDP Act, 2023, with an 18-month phased compliance timeline. The rules require standalone, clear consent notices that explain the specific purpose for which data is collected ([Press Information Bureau announcement](https://www.pib.gov.in/PressReleasePage.aspx?PRID=2190014)). For document collection, the practical consequence is that the first message should say what is being collected and why, the agent should request only what the checklist needs, and the retention rule should be defined before the first file arrives. Legal counsel should confirm how the rules apply to your processing.

## Designing the Follow-Up Cadence

A reasonable starting design, to be tuned against your own file-closure data:

- **Request.** Sent within a day of booking, naming the one or two most urgent items, with the reason ("the bank needs this to start sanction").
- **First nudge.** Two days later, only for items still missing, naming the specific item.
- **Format help.** If an item arrives rejected, the correction goes out at once, with an example of what is needed.
- **Second nudge, different angle.** Offers help: "Would a call be easier? I can arrange one with your relationship manager."
- **Stop and hand off.** After the agreed number of attempts, the agent stops messaging and flags the RM with the file, the item and the history. It does not keep going.

The stop rule is as important as the reminders. A buyer who has paid a booking amount and is being messaged daily by an automated system feels watched, not served. The same restraint applies in other chasing tasks: the [gold savings scheme instalment reminders](/blog/en/gold-scheme-installment-reminders-ai.html) post covers how a jeweller automates instalment follow-up without damaging the relationship.

## What the CRM Record Should Hold

The CRM turns a stack of chats into a status the sales head can read at a glance. Each buyer record should carry, per document:

| Field | Example |
|---|---|
| Document type | Salary slip, month 1 |
| Required for | Bank sanction |
| Status | Requested / Received / Needs correction / Accepted |
| Received at | Timestamp from the chat |
| File reference | Link to the company document store |
| Accepted by | Agent (readability) or named compliance reviewer (verification) |
| Reason code | Cropped, wrong person, expired, wrong type |

Separating "received" from "accepted", and splitting readability checks from compliance verification, is what lets the head of sales operations trust the dashboard. A file marked complete means a person on the compliance team looked at it.

If the agent cannot write to the CRM cleanly, the whole exercise degrades into another chat tool. The [real estate AI chatbot](/industries/real-estate-ai-chatbot.html) page shows how the front end of this workflow, qualification on WhatsApp with the brief written into the CRM, is set up. Document collection extends the same integration to the weeks after booking.

## What to Measure

Measure task completion, not message volume.

- **Days from booking to a complete file.** The headline number. Record the baseline before the agent goes live.
- **Files complete without RM involvement.** The share the agent closes alone.
- **Second requests per document.** A high figure means the first request is unclear or the checklist is wrong.
- **Rejected on arrival versus rejected at the bank.** The second number should fall towards zero.
- **Hand-offs and their reasons.** Patterns here show where the process, not the agent, is broken.

Fix the measurement method and date range before launch; a before-and-after claim without a baseline is not evidence.

## Where This Goes Wrong

A buyer sends a photograph of a photograph, taken off another screen, and the check passes a file the bank later rejects. The fix is a stricter legibility check and an example image in the request.

A co-applicant's document arrives in the primary buyer's chat, so the agent asks whom it belongs to before filing it.

A buyer replies in Hindi or Marathi to an English request. The agent must reply in the language the buyer uses, and the checklist names need to exist in each language. This is also where [multilingual handling](/blog/en/multilingual-ai-jewellery-india.html) pays for itself in a non-English market.

A buyer ignores text entirely and would rather talk. A voice follow-up, handed off through the same CRM record, picks up where the chat stopped. Channel is a property of the buyer, not of the system.

## FAQ

### Does the agent verify KYC documents?

No. It checks that a document is the expected type, readable, current and in the buyer's name, then routes it to a named compliance reviewer who decides. Verification is a compliance responsibility, and the CRM should record who performed it.

### Which documents does it chase?

The ones on the checklist defined for that buyer type and financing route, and nothing else. The checklist is configured with your sales operations and compliance teams, not inferred. Collecting less is part of the design.

### What happens when a buyer stops replying?

After the agreed number of attempts, the agent stops and flags the relationship manager with the file history. The RM decides whether to call, visit or hold the file.

### Does it replace the relationship manager?

It removes the chasing, which is the part of the job nobody values. The relationship manager keeps the relationship, the negotiation and every exception the agent hands over.
