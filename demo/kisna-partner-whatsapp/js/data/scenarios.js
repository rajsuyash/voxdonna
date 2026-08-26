/*
 * Scenario scripts that drive the interactive B2B WhatsApp demo.
 * Each scenario is a small node-graph. A node has:
 *   user    : (optional) simulated inbound message from the retail partner
 *   bot     : array of message specs (see the RENDER map in app.js for `t` types)
 *   choices : quick-reply chips { label, goto }  (goto = node key, or 'END')
 * Free-typed text is handled in app.js (intent parsing + RAG) and then returns
 * to the current node's choices.
 *
 * Two agents appear on purpose:
 *   Riya   — the conversational layer the partner talks to.
 *   Voxdonna — the back-office orchestrator. It never talks to the partner; it acts,
 *            and the demo surfaces those actions as a separate chip so a buyer can
 *            see where the automation actually sits.
 */
window.SCENARIOS = {

  /* 1 ─────────────────────── ORDER & CATALOGUE CONCIERGE ─────────────────── */
  catalog: {
    title: 'Catalogue & Ordering', emoji: '📖', persona: 'Shree Balaji Jewellers · Nagpur',
    blurb: 'Browse by purity and price point, check margin, place the order — inside chat.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Need to restock the gifting counter before Diwali. What do you have under ₹25,000 wholesale?',
        bot: [
          { t:'text', text:'Good morning, Mr. Deshpande 🙏 Riya here from the *Kisna Partner Desk*. Pulling your counter mix and this year’s festive movers now.' },
          { t:'text', text:'Under ₹25,000 wholesale, these three are doing the heaviest volume for partners your size — margin and lead time on each card:' },
          { t:'reco', query:{ ticket:25000, tags:['gifting','fast-moving'], ready:true }, n:3 },
        ],
        choices: [
          { label:'14K only', goto:'purity' },
          { label:'Show bridal instead', goto:'bridal' },
          { label:'Build me an order', goto:'build' },
        ],
      },
      purity: {
        user: 'Only 14K — my counter moves the lighter pieces',
        bot: [
          { t:'text', text:'Understood. 14K, ready stock, all inside your price point:' },
          { t:'reco', query:{ ticket:25000, purity:'14K', ready:true }, n:3 },
          { t:'text', text:'The *Nose Pin* is the one I’d push hardest — MOQ 20, but it has the highest units-per-invoice in the whole catalogue. It walks out at the counter.' },
        ],
        choices: [
          { label:'Build me an order', goto:'build' },
          { label:'What margin do I make?', goto:'margin' },
          { label:'Show bridal instead', goto:'bridal' },
        ],
      },
      bridal: {
        user: 'Also show me bridal — wedding bookings are picking up',
        bot: [
          { t:'text', text:'Wedding season stock, ordered by how fast it turns at partner counters:' },
          { t:'reco', query:{ tags:['bridal'], ticket:120000 }, n:3 },
          { t:'text', text:'One thing worth knowing: the *Diamond Mangalsutra* (KSN-MS-3310) has never sat on a partner shelf longer than 40 days this year. Three on the counter year-round is the norm.' },
        ],
        choices: [
          { label:'Add 3 mangalsutra', goto:'build' },
          { label:'What margin do I make?', goto:'margin' },
        ],
      },
      margin: {
        user: 'What do I actually make on these?',
        bot: [
          { t:'text', text:'Straight answer — here’s the counter maths on the three gifting SKUs, at full sell-through and printed MRP:' },
          { t:'cart', lines:[{ code:'KSN-ER-1042', qty:12 }, { code:'KSN-PD-1088', qty:10 }, { code:'KSN-NP-1150', qty:20 }],
            note:'Indicative basket at MOQ on each line' },
          { t:'text', text:'Your working capital sits blocked for the shelf life, not the credit period — which for you is 45 days. On this basket that means the lot is typically sold through before the invoice falls due.' },
        ],
        choices: [
          { label:'Place this order', goto:'build' },
          { label:'Change the quantities', goto:'qty' },
        ],
      },
      qty: {
        user: 'Make it 18 studs and 30 nose pins, drop the pendant',
        bot: [
          { t:'text', text:'Updated. 18 studs, 30 nose pins, pendant removed:' },
          { t:'cart', lines:[{ code:'KSN-ER-1042', qty:18 }, { code:'KSN-NP-1150', qty:30 }], note:'Revised basket' },
        ],
        choices: [ { label:'Confirm the order', goto:'build' } ],
      },
      build: {
        user: 'Confirm it',
        bot: [
          { t:'text', text:'Confirming against your account now — checking the sanctioned limit before I raise it.' },
          { t:'vox', text:'Credit check · ₹6,58,000 available against ₹25,00,000 limit → order value clears. No approval hop needed.' },
          { t:'cart', lines:[{ code:'KSN-ER-1042', qty:18 }, { code:'KSN-NP-1150', qty:30 }], note:'Order KO-24931 · confirmed', confirmed:true },
          { t:'text', text:'Done. Order *KO-24931* is in. Ready stock on both lines, so it dispatches in 5–7 working days and I’ll push the AWB here the moment it leaves the vault.' },
          { t:'vox', text:'ERP write-back · sales order created, stock reserved, karigar allocation skipped (ready stock). Dispatch SLA clock started.' },
        ],
        choices: [ { label:'Thanks', goto:'close' } ],
      },
      close: {
        bot: [
          { t:'intent', data:{ partner:'Shree Balaji Jewellers (KP-4417)', order:'KO-24931', value:'₹4,91,928 incl. GST', pcs:'48 pcs', channel:'WhatsApp · self-serve', kam:'Ankit Deshmukh' }, score:'Self-serve · no rep time' },
          { t:'system', text:'Order placed end-to-end in chat. Zero minutes of KAM time, against ~35 minutes for the same order by phone and email.' },
        ],
        choices: [],
      },
    },
  },

  /* 2 ─────────────────────── ORDER STATUS & DISPATCH ─────────────────────── */
  track: {
    title: 'Order Status & Dispatch', emoji: '📦', persona: 'Three live orders, one exception',
    blurb: 'Manufacturing → QC → HUID → AWB, live from ERP. Exceptions escalate themselves.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Status on my orders?',
        bot: [
          { t:'text', text:'You have three open. Here they are, newest movement first:' },
          { t:'orderlist' },
        ],
        choices: [
          { label:'Track KO-24881', goto:'dispatched' },
          { label:'Why is KO-24902 held?', goto:'hold' },
          { label:'KO-24915 status', goto:'making' },
        ],
      },
      dispatched: {
        user: 'Where is KO-24881?',
        bot: [
          { t:'orderpipe', id:'KO-24881' },
          { t:'text', text:'It left the vault yesterday evening. Delivery is against firm stamp and photo ID — please keep the seal video running when you open it, that is what a shortage claim rests on.' },
        ],
        choices: [
          { label:'Send me the e-way bill', goto:'docs' },
          { label:'Check the other orders', goto:'start' },
        ],
      },
      hold: {
        user: 'Why is the mangalsutra order held?',
        bot: [
          { t:'orderpipe', id:'KO-24902' },
          { t:'text', text:'Being straight with you: 2 of the 18 pieces failed the polish check at QC and went back to the karigar. The other 16 are through and moving to hallmarking.' },
          { t:'vox', text:'Exception detected · QC hold >48 hrs on KO-24902 → flagged, ETA recalculated (14 → 17 Aug on 2 pcs), partner notified without being asked.' },
          { t:'text', text:'So: 16 pieces land on the 14th as planned, the last 2 on the 17th. If you need all 18 together for a booking, say so and I’ll hold the lot and ship once.' },
        ],
        choices: [
          { label:'Split it — send the 16 now', goto:'split' },
          { label:'Hold and ship together', goto:'holdall' },
          { label:'Get me a person', goto:'human' },
        ],
      },
      split: {
        user: 'Split it, I need the 16 for the weekend',
        bot: [
          { t:'text', text:'Splitting it. 16 pieces dispatch on the 14th, the balance 2 follow on the 17th at no extra freight — the second leg is on us since the delay is ours.' },
          { t:'vox', text:'ERP · order split into KO-24902-A (16 pcs) and KO-24902-B (2 pcs). Freight waiver applied to leg B, reason coded *internal QC delay*.' },
        ],
        choices: [ { label:'Perfect', goto:'close' } ],
      },
      holdall: {
        user: 'Hold it, ship all 18 together',
        bot: [
          { t:'text', text:'Held. All 18 ship together on the 17th, and I’ve marked the consignment priority so it moves the same morning it clears hallmarking.' },
          { t:'vox', text:'ERP · dispatch hold set on KO-24902 until 17 Aug, priority flag applied.' },
        ],
        choices: [ { label:'Thanks', goto:'close' } ],
      },
      making: {
        user: 'And the festive edit?',
        bot: [
          { t:'orderpipe', id:'KO-24915' },
          { t:'text', text:'On schedule. 60 pieces, karigar allocation done, dispatching 22 Aug — that lands well inside your Diwali window.' },
        ],
        choices: [
          { label:'Can it come earlier?', goto:'expedite' },
          { label:'Check the other orders', goto:'start' },
        ],
      },
      expedite: {
        user: 'Can you pull it forward a week?',
        bot: [
          { t:'text', text:'Checking capacity rather than guessing…' },
          { t:'vox', text:'Production check · 60-pc run against karigar capacity for w/c 10 Aug → 40 pcs can be pulled to 15 Aug, 20 pcs cannot. Partial expedite offered.' },
          { t:'text', text:'Honest answer: 40 pieces can come on the 15th, 20 cannot move. I’d rather tell you that now than promise 60 and miss it.' },
        ],
        choices: [
          { label:'Take the 40 early', goto:'close' },
          { label:'Leave it as is', goto:'close' },
        ],
      },
      docs: {
        user: 'Send the e-way bill and invoice',
        bot: [
          { t:'text', text:'Both attached — e-invoice and e-way bill were generated automatically at dispatch:' },
          { t:'docs', files:[{ name:'KIS-26-27-3402.pdf', kind:'Tax invoice', size:'214 KB' }, { name:'EWB-771049283311.pdf', kind:'E-way bill', size:'96 KB' }] },
        ],
        choices: [ { label:'Thanks', goto:'close' } ],
      },
      human: {
        user: 'Can I speak to someone?',
        bot: [
          { t:'text', text:'Of course — connecting you to Ankit, your account manager, with this whole thread attached so you don’t repeat yourself.' },
          { t:'vox', text:'Warm handoff → KAM Ankit Deshmukh · full context, order state and QC note attached. Median pickup 45s in business hours.' },
        ],
        choices: [ { label:'Thanks', goto:'close' } ],
      },
      close: {
        bot: [
          { t:'system', text:'Every status question answered from live ERP and logistics data. Roughly 60% of a wholesaler’s inbound calls are this one question.' },
        ],
        choices: [],
      },
    },
  },

  /* 3 ─────────────────────── CREDIT, STATEMENT & LEDGER ──────────────────── */
  credit: {
    title: 'Credit & Statements', emoji: '🧾', persona: 'Ledger straight from ERP',
    blurb: 'Outstanding, ageing, credit limit and invoice copies — self-serve, any hour.',
    entry: 'start',
    nodes: {
      start: {
        user: 'What’s my outstanding?',
        bot: [
          { t:'text', text:'Here’s your account as of this morning:' },
          { t:'ledger' },
          { t:'text', text:'₹6,58,000 of your limit is still free. One bucket needs attention — ₹2,10,000 has crossed 45 days.' },
        ],
        choices: [
          { label:'Send invoice copies', goto:'invoices' },
          { label:'I want to pay now', goto:'pay' },
          { label:'Raise my credit limit', goto:'limit' },
        ],
      },
      invoices: {
        user: 'Send me the open invoices',
        bot: [
          { t:'text', text:'All three open invoices, oldest first:' },
          { t:'invoices' },
          { t:'text', text:'The ₹2,10,000 one falls due tomorrow. Want a payment link for just that, or for the full outstanding?' },
        ],
        choices: [
          { label:'Just the overdue one', goto:'pay' },
          { label:'Full outstanding', goto:'payall' },
        ],
      },
      pay: {
        user: 'Payment link for the overdue invoice',
        bot: [
          { t:'payment', amount:210000, invoice:'KIS/26-27/3268' },
          { t:'text', text:'UPI reflects against your ledger in about 30 minutes, NEFT the same working day. It is tagged to that invoice specifically, so it won’t get applied oldest-first.' },
        ],
        choices: [ { label:'Paid it', goto:'paid' } ],
      },
      payall: {
        user: 'Send it for the full amount',
        bot: [
          { t:'payment', amount:1842000, invoice:'All open invoices' },
          { t:'text', text:'That clears the account entirely and takes your available limit back to the full ₹25,00,000.' },
        ],
        choices: [ { label:'Paid it', goto:'paid' } ],
      },
      paid: {
        user: 'Done, paid via UPI',
        bot: [
          { t:'text', text:'Received — ₹2,10,000 credited and applied to KIS/26-27/3268. Receipt attached.' },
          { t:'docs', files:[{ name:'RCPT-26-27-8841.pdf', kind:'Payment receipt', size:'88 KB' }] },
          { t:'vox', text:'Ledger updated · ageing recalculated, 46–60 bucket cleared, risk score 62 → 71, collections cadence stood down for this partner.' },
        ],
        choices: [ { label:'Raise my credit limit', goto:'limit' } ],
      },
      limit: {
        user: 'Can you increase my limit to 40 lakhs?',
        bot: [
          { t:'rag', q:'credit limit terms enhance increase review' },
          { t:'text', text:'For your account specifically: YTD purchase ₹1.86 Cr, DSO 47 days against 45 sanctioned. The ageing is what holds it back, not the volume.' },
          { t:'vox', text:'Enhancement pre-screen · volume ✓, filings ✓, ageing ✗ (one bucket >45d). Routed to credit committee with a clearing condition, not rejected.' },
          { t:'text', text:'So it goes forward with one condition: clear the 46–60 day bucket and the enhancement is reviewed at the next committee, on the 20th. I’ll come back to you either way.' },
        ],
        choices: [ { label:'Understood', goto:'close' } ],
      },
      close: {
        bot: [
          { t:'system', text:'Ledger, invoices, payment and a limit request handled without a single call to accounts.' },
        ],
        choices: [],
      },
    },
  },

  /* 4 ─────────────────────── COLLECTIONS (OUTBOUND) ──────────────────────── */
  collect: {
    title: 'Collections Nudge', emoji: '⏰', persona: 'Agent-initiated · risk-scored',
    blurb: 'Soft reminders before and after due date, paced by the partner’s risk score.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'vox', text:'Collections trigger · invoice KIS/26-27/3268 due T-3. Partner risk band *Watch* (62) → soft cadence: T-3 nudge, T+1 reminder, T+7 KAM call. No hard tone before T+7.' },
          { t:'text', text:'Good morning 🙏 Small heads-up, nothing urgent — invoice *KIS/26-27/3268* for ₹2,10,000 falls due on the 8th, three days from now.' },
          { t:'text', text:'Payment link is here whenever it suits you. If the timing is tight this month, tell me and I’ll see what can be done rather than chase you.' },
          { t:'payment', amount:210000, invoice:'KIS/26-27/3268' },
        ],
        choices: [
          { label:'Paying today', goto:'pays' },
          { label:'Need a few more days', goto:'extend' },
          { label:'This is already paid', goto:'disputed' },
        ],
      },
      pays: {
        user: 'Paying it today',
        bot: [
          { t:'text', text:'Appreciated 🙏 I’ll stand the reminders down and confirm the moment it lands.' },
          { t:'vox', text:'Cadence paused · T+1 and T+7 steps suppressed pending settlement. Auto-resumes only if unpaid at T+2.' },
        ],
        choices: [ { label:'Done', goto:'close' } ],
      },
      extend: {
        user: 'Can I have till the 20th? Festive stock has blocked my cash',
        bot: [
          { t:'text', text:'That’s a fair reason and a common one this month. Let me check what I can actually authorise rather than promise you something.' },
          { t:'vox', text:'Extension request · 12 days on ₹2,10,000. Partner history: 14 invoices, 13 on time, zero defaults. Inside auto-approve band (≤15 days, risk ≥55) → approved without a human.' },
          { t:'text', text:'Approved — due date moves to the *20th*, no penalty, and your limit stays where it is. One ask in return: clear it on the 20th, because the credit committee reviews your enhancement on the same date.' },
          { t:'vox', text:'ERP · due date amended, ageing recalculated, KAM notified for visibility. Committee note attached to the enhancement file.' },
        ],
        choices: [ { label:'Fair enough', goto:'close' } ],
      },
      disputed: {
        user: 'I paid this last week by NEFT',
        bot: [
          { t:'text', text:'Then the fault is on our side, not yours. Let me check the bank file before I say anything else.' },
          { t:'vox', text:'Reconciliation · unapplied NEFT credit ₹2,10,000 dated 31 Jul found in suspense — UTR narration missing the invoice reference. Matched on amount + partner IFSC.' },
          { t:'text', text:'Found it. Your NEFT of the 31st was sitting in suspense because the narration didn’t carry the invoice number. It’s applied now and the reminder should never have gone out — apologies for that.' },
          { t:'ticket', data:{ id:'TKT-9914', type:'Invoice / GST error', sla:'Resolved', route:'Accounts · reconciliation', note:'Unapplied credit matched and posted. Root cause logged for narration rule fix.' } },
        ],
        choices: [ { label:'No problem', goto:'close' } ],
      },
      close: {
        bot: [
          { t:'system', text:'Collections that read as a service, not a chase. Wholesalers running this cadence typically pull 6–9 days out of DSO without a single angry call.' },
        ],
        choices: [],
      },
    },
  },

  /* 5 ─────────────────────── SCHEME & OFFER BROADCAST ────────────────────── */
  scheme: {
    title: 'Scheme Broadcast', emoji: '🪔', persona: 'Segmented broadcast → order intent',
    blurb: 'Festive scheme pushed to the right partner band, opt-in captured in the chat.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'vox', text:'Segment built · 214 partners in the ₹1Cr+ YTD band with ageing under 60 days. Broadcast queued on an approved template, opt-outs excluded.' },
          { t:'scheme', id:'FEST-26' },
          { t:'text', text:'You’re in the eligible band for this one. Want the terms in full, or shall I show you what other partners your size are booking?' },
        ],
        choices: [
          { label:'Show me the terms', goto:'terms' },
          { label:'What are others booking?', goto:'peers' },
          { label:'Not this year', goto:'optout' },
        ],
      },
      terms: {
        user: 'Show me the exact terms',
        bot: [
          { t:'schemeterms', id:'FEST-26' },
          { t:'text', text:'The part that matters: the unsold-stock exchange runs to *15 January*, so festive stock that doesn’t move isn’t money you’ve lost — it comes back at invoice value.' },
        ],
        choices: [
          { label:'I’m in — book it', goto:'optin' },
          { label:'What are others booking?', goto:'peers' },
        ],
      },
      peers: {
        user: 'What are similar partners booking?',
        bot: [
          { t:'text', text:'Two-counter partners in tier-2 Maharashtra are averaging ₹7.2 lakh on this scheme, weighted heavily to the gifting range under ₹25,000 MRP.' },
          { t:'reco', query:{ ticket:25000, tags:['gifting','fast-moving'], ready:true }, n:3 },
          { t:'text', text:'For your counter mix I’d put roughly 70% into gifting and 30% into one bridal anchor piece.' },
        ],
        choices: [
          { label:'Book ₹7 lakh on that split', goto:'optin' },
          { label:'Show me the terms', goto:'terms' },
        ],
      },
      optin: {
        user: 'Book me in for around ₹7 lakh',
        bot: [
          { t:'text', text:'Booked into the Diwali Stock-Up at ₹7,00,000 with the 60-day terms. I’ll send the design-wise split for your approval tomorrow morning, before anything is manufactured.' },
          { t:'vox', text:'Scheme opt-in recorded · booking ₹7,00,000, 60-day terms applied to scheme SKUs only. Draft split queued for partner approval. Credit limit temporarily uplifted for the scheme window.' },
          { t:'intent', data:{ partner:'Shree Balaji Jewellers (KP-4417)', scheme:'Diwali Stock-Up 2026', value:'₹7,00,000', split:'70% gifting / 30% bridal', terms:'60-day credit' }, score:'Opt-in · 4 messages' },
        ],
        choices: [ { label:'Good', goto:'close' } ],
      },
      optout: {
        user: 'Skipping the scheme this year',
        bot: [
          { t:'text', text:'Noted, and no follow-ups on this one — I won’t chase you about it.' },
          { t:'vox', text:'Opt-out recorded against scheme FEST-26 only. Partner stays on design-launch and service messaging. Preference written back to CRM.' },
        ],
        choices: [ { label:'Thanks', goto:'close' } ],
      },
      close: {
        bot: [
          { t:'system', text:'One broadcast, segmented by turnover and ageing, converting inside the same thread. WhatsApp open rates run ~90% against ~20% on trade email.' },
        ],
        choices: [],
      },
    },
  },

  /* 6 ─────────────────────── NEW DESIGN LAUNCH ───────────────────────────── */
  drop: {
    title: 'Design Launch', emoji: '✨', persona: 'Catalogue drop → interest signal',
    blurb: 'New line pushed with catalogue and reels; interest feeds the production run.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'drop', id:'DROP-AW26' },
          { t:'text', text:'24 new designs, all under ₹25,000 MRP, built for the gifting counter. Three heroes from the line:' },
          { t:'skus', codes:['KSN-ER-1042','KSN-PD-1088','KSN-RG-1121'] },
        ],
        choices: [
          { label:'Send the catalogue', goto:'assets' },
          { label:'I like the stackable band', goto:'interest' },
          { label:'Not for my counter', goto:'nofit' },
        ],
      },
      assets: {
        user: 'Send me the full catalogue and the videos',
        bot: [
          { t:'text', text:'All of it — catalogue, both reels, and the counter-display artwork you can print locally:' },
          { t:'docs', files:[{ name:'AW26-catalogue.pdf', kind:'Catalogue · 24 designs', size:'6.2 MB' }, { name:'AW26-reel-01.mp4', kind:'Shoot reel · 0:18', size:'11 MB' }, { name:'AW26-counter-display.pdf', kind:'Display artwork', size:'3.4 MB' }] },
          { t:'text', text:'The reels are cut for Instagram at 9:16 — you can post them under your own store handle, we don’t watermark partner assets.' },
        ],
        choices: [
          { label:'I like the stackable band', goto:'interest' },
          { label:'Book a first-run slot', goto:'book' },
        ],
      },
      interest: {
        user: 'The stackable band will work here. What’s the first-run position?',
        bot: [
          { t:'text', text:'Straight answer: first run is 900 pieces across all partners and 61% is already spoken for. Registering interest now gets you a September slot; after the run closes it’s November.' },
          { t:'vox', text:'Interest signal logged · KSN-RG-1121, partner KP-4417, tier-2 Maharashtra. Design analytics updated — this SKU now indexes 2.1× on two-counter partners, feeding the second-run sizing.' },
        ],
        choices: [
          { label:'Book a first-run slot', goto:'book' },
          { label:'Send the catalogue', goto:'assets' },
        ],
      },
      book: {
        user: 'Book me 30 pieces in the first run',
        bot: [
          { t:'cart', lines:[{ code:'KSN-RG-1121', qty:30 }], note:'First-run reservation · AW26', confirmed:true },
          { t:'text', text:'Reserved — 30 pieces in the September run, size mix 12 to 16. Nothing is billed until it dispatches.' },
          { t:'vox', text:'Reservation created against production run AW26-R1. No invoice raised. Partner notified at manufacturing start.' },
        ],
        choices: [ { label:'Thanks', goto:'close' } ],
      },
      nofit: {
        user: 'This line isn’t right for my counter',
        bot: [
          { t:'text', text:'Useful to know, and more useful than silence. What is your counter asking for that we aren’t showing you?' },
        ],
        choices: [
          { label:'Heavier bridal', goto:'feedback' },
          { label:'Lower price points', goto:'feedback' },
        ],
      },
      feedback: {
        user: 'Heavier bridal — that’s what sells here',
        bot: [
          { t:'text', text:'Logged against your account, and it goes to the design team as a signal, not a complaint. You’ll see bridal-weighted drops first from here.' },
          { t:'vox', text:'Negative signal captured · KP-4417 skews bridal-heavy. Partner segment reweighted for future drops. Aggregated into the AW26 post-launch review.' },
        ],
        choices: [ { label:'Good', goto:'close' } ],
      },
      close: {
        bot: [
          { t:'system', text:'Design launch that returns data. Interest and rejection both feed the production run, instead of dying in a WhatsApp group nobody reads.' },
        ],
        choices: [],
      },
    },
  },

  /* 7 ─────────────────────── SERVICE & DISPUTE DESK ──────────────────────── */
  desk: {
    title: 'Service & Dispute Desk', emoji: '🛠️', persona: 'HUID, GST, shortages, karigar',
    blurb: 'Trade FAQs answered from policy, shortages and damage logged as tickets.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Two things — a HUID question and a shortage in yesterday’s box',
        bot: [
          { t:'text', text:'Let’s take both. Which first?' },
        ],
        choices: [
          { label:'HUID question', goto:'huid' },
          { label:'Log the shortage', goto:'short' },
          { label:'GST on making', goto:'gst' },
          { label:'A piece needs rework', goto:'rework' },
        ],
      },
      huid: {
        user: 'A customer says the HUID on her pendant doesn’t show in BIS Care',
        bot: [
          { t:'rag', q:'huid hallmark bis six digit unique id marking' },
          { t:'text', text:'Nine times out of ten it’s a reading error — the 6-digit code mixes 0/O and 1/I. Send me a photo of the marking and I’ll read it off the dispatch record instead of the piece.' },
        ],
        choices: [
          { label:'Sent the photo', goto:'huidfix' },
          { label:'Log the shortage', goto:'short' },
        ],
      },
      huidfix: {
        user: '[photo · hallmark marking]',
        bot: [
          { t:'text', text:'Read it. The code is *K7F2M9* — the customer read the F as an E. It resolves correctly on BIS Care, and the assaying centre is Nagpur.' },
          { t:'vox', text:'Traced against dispatch record for KO-24881, line 7. No quality exception. Query closed without a ticket.' },
        ],
        choices: [
          { label:'Log the shortage', goto:'short' },
          { label:'That’s all', goto:'close' },
        ],
      },
      short: {
        user: 'The box was 42 pieces on the packing list but 41 arrived',
        bot: [
          { t:'text', text:'That’s a claim and the clock matters — it has to be raised inside 24 hours of delivery, which you are well within. I need the unopened-seal video and a photo of the packing list.' },
          { t:'rag', q:'shortage damage claim dispute short shipment' },
        ],
        choices: [
          { label:'Uploading both now', goto:'shortlog' },
        ],
      },
      shortlog: {
        user: '[video · seal opening] [photo · packing list]',
        bot: [
          { t:'text', text:'Both received and attached to the claim. Ticket is open:' },
          { t:'ticket', data:{ id:'TKT-9927', type:'Short shipment', sla:'24 hrs', route:'Dispatch audit · Surat', note:'1 pc short against packing list on KO-24881. Seal video + packing list attached. Vault CCTV pull requested.' } },
          { t:'vox', text:'Ticket opened and routed. Vault footage for the packing window requested automatically. Credit note pre-authorised pending audit, so settlement does not wait on a second approval.' },
          { t:'text', text:'You’ll have an answer inside 24 hours. If the audit confirms it, the credit note is already cleared to issue — you won’t have to chase it.' },
        ],
        choices: [
          { label:'A piece needs rework', goto:'rework' },
          { label:'That’s all', goto:'close' },
        ],
      },
      gst: {
        user: 'Customer is asking why making is taxed differently',
        bot: [
          { t:'rag', q:'gst tax hsn 3% 5% making job work invoice' },
        ],
        choices: [
          { label:'Log the shortage', goto:'short' },
          { label:'That’s all', goto:'close' },
        ],
      },
      rework: {
        user: 'A bangle from last month has a rough setting, customer returned it',
        bot: [
          { t:'rag', q:'rework karigar repair polish finish service' },
          { t:'ticket', data:{ id:'TKT-9931', type:'Finish / QC issue', sla:'72 hrs', route:'Karigar rework · no charge', note:'Within 6 months of invoice. Pickup scheduled, 10–14 working days including re-hallmarking.' } },
          { t:'text', text:'No charge — it’s inside six months. Pickup is arranged, and you’ll get a loaner-stock credit so your customer isn’t left waiting empty-handed.' },
        ],
        choices: [ { label:'Appreciated', goto:'close' } ],
      },
      close: {
        bot: [
          { t:'vox', text:'Pattern watch · 3rd short-shipment ticket this month traced to the same packing bench. Flagged to operations with the shift data, as a process fix rather than three separate claims.' },
          { t:'system', text:'Around 70% of trade service queries close without a human. The ones that don’t arrive at a person already evidenced.' },
        ],
        choices: [],
      },
    },
  },

  /* 8 ─────────────────────── ONBOARDING & KYC ────────────────────────────── */
  kyc: {
    title: 'Partner Onboarding', emoji: '🆕', persona: 'Ratnadeep Jewellers · Indore',
    blurb: 'Conversational KYC, document uploads, and opening credit terms proposed.',
    entry: 'start',
    nodes: {
      start: {
        user: 'We want to stock Kisna at our Indore showroom. How do we start?',
        bot: [
          { t:'text', text:'Welcome 🙏 I can do the whole thing here — no forms to print, no branch visit. Six items in total, and you can send them as you have them.' },
          { t:'rag', q:'kyc onboarding new partner documents' },
        ],
        choices: [
          { label:'Start now', goto:'collect' },
        ],
      },
      collect: {
        user: 'Let’s start. Firm is Ratnadeep Jewellers, Indore',
        bot: [
          { t:'text', text:'Noted. Send your GSTIN next — just type it, I’ll verify it live.' },
        ],
        choices: [ { label:'23AABCR5521M1Z4', goto:'gst' } ],
      },
      gst: {
        user: '23AABCR5521M1Z4',
        bot: [
          { t:'vox', text:'GSTIN verified against the GST portal · Ratnadeep Jewellers, Indore, registered 2019, filings current to Jun 2026, no cancellation flag. Name matched to the firm you gave me.' },
          { t:'text', text:'Verified, and the filings are current — that’s the part that usually holds an application up, so you’re in good shape.' },
          { t:'text', text:'Now PAN with proprietor KYC, and a cancelled cheque. Photos of the documents are fine.' },
        ],
        choices: [ { label:'[uploads PAN + cheque]', goto:'docs' } ],
      },
      docs: {
        user: '[photo · PAN card] [photo · cancelled cheque]',
        bot: [
          { t:'vox', text:'PAN validated, Aadhaar e-KYC name match 98%. Penny-drop to the HDFC account successful — account holder matches the firm. No manual data entry anywhere in this chain.' },
          { t:'text', text:'Both clear. Four down, two to go:' },
          { t:'kyc' },
        ],
        choices: [
          { label:'Send trade references', goto:'refs' },
          { label:'What happens after?', goto:'after' },
        ],
      },
      refs: {
        user: 'Second reference is Jain Jewellers, Bhopal — 98xxx 22114',
        bot: [
          { t:'vox', text:'Second trade reference captured. Reference 1 already responded positively. Shop photographs still pending — the only open item.' },
          { t:'text', text:'That’s five of six. Just the shop photographs left — three shots: the signage, the counter, and the entrance.' },
        ],
        choices: [ { label:'[uploads 3 shop photos]', goto:'complete' } ],
      },
      complete: {
        user: '[photo · signage] [photo · counter] [photo · entrance]',
        bot: [
          { t:'text', text:'That’s everything. Running the file now.' },
          { t:'vox', text:'File complete · all six items validated. Risk screen: GST filings current, no adverse flags, 1 counter, declared turnover ₹4.2 Cr. Opening terms computed and proposed for approval.' },
          { t:'terms' },
          { t:'text', text:'A person still signs this off — I don’t sanction credit on my own. Ankit will call you today to confirm and walk you through the first order.' },
        ],
        choices: [ { label:'Perfect', goto:'close' } ],
      },
      after: {
        user: 'What happens once we’re verified?',
        bot: [
          { t:'text', text:'Verification takes about two working days. Then opening credit terms are proposed, a KAM is assigned, and your first order can be placed right here in this chat. Display material and the counter app follow with the first dispatch.' },
        ],
        choices: [ { label:'Send trade references', goto:'refs' } ],
      },
      close: {
        bot: [
          { t:'intent', data:{ firm:'Ratnadeep Jewellers', city:'Indore', gst:'Verified · filings current', docs:'6 of 6 received', proposed:'₹8,00,000 · 30 days', kam:'Ankit Deshmukh' }, score:'Onboarded in one chat' },
          { t:'system', text:'Onboarding that used to take two weeks of couriered paperwork, closed in one conversation. The human decision stays human — everything before it does not.' },
        ],
        choices: [],
      },
    },
  },

  /* 9 ─────────────────────── VOICE & MULTILINGUAL ────────────────────────── */
  voice: {
    title: 'Voice & Multilingual', emoji: '🎙️', persona: 'The trade belt, in its own language',
    blurb: 'Gujarati and Hindi voice notes from the counter, understood and answered.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'text', text:'Most of our partners send voice notes from the shop floor, not typed messages — usually mid-sale with a customer standing there. That works here 🎙️' },
        ],
        choices: [
          { label:'▶️ Gujarati voice note', goto:'guj' },
          { label:'▶️ Hindi voice note', goto:'hin' },
          { label:'Type in Marathi', goto:'mar' },
        ],
      },
      guj: {
        user: '[voice note · Gujarati]',
        bot: [
          { t:'voiceIn', lang:'Gujarati', dur:'0:11', text:'“Customer beṭha chhe, mangalsutra joiye chhe — pachas hajār sudhi. Stock ma shu chhe?”', gloss:'“Customer is sitting here, wants a mangalsutra up to ₹50,000. What’s in stock?”' },
          { t:'text', text:'Customer waiting — so, quickly. Under ₹50,000 wholesale, ready stock, ships in 10 days:' },
          { t:'skus', codes:['KSN-MS-3318'] },
          { t:'voiceOut', lang:'Gujarati', dur:'0:13', text:'“Short daily mangalsutra chhe — ₹38,900 wholesale, ₹57,500 MRP. Ready stock, das divas ma pahonchi jashe. Booking karu?”', gloss:'“The short daily mangalsutra — ₹38,900 wholesale, ₹57,500 MRP. Ready stock, delivered in ten days. Shall I book it?”' },
        ],
        choices: [
          { label:'Book 6 pieces', goto:'book' },
          { label:'Try Hindi', goto:'hin' },
        ],
      },
      hin: {
        user: '[voice note · Hindi]',
        bot: [
          { t:'voiceIn', lang:'Hindi', dur:'0:09', text:'“Pichhle order ka bill nahi mila, aur payment link bhej dijiye.”', gloss:'“I didn’t get the bill for the last order, and please send a payment link.”' },
          { t:'text', text:'दोनों भेज रही हूँ — पिछले ऑर्डर का बिल और पेमेंट लिंक 👇' },
          { t:'docs', files:[{ name:'KIS-26-27-3402.pdf', kind:'Tax invoice · KO-24881', size:'214 KB' }] },
          { t:'payment', amount:210000, invoice:'KIS/26-27/3268' },
        ],
        choices: [
          { label:'Book 6 pieces', goto:'book' },
          { label:'Try Marathi', goto:'mar' },
        ],
      },
      mar: {
        user: 'दिवाळीसाठी नवीन डिझाईन कधी येणार?',
        bot: [
          { t:'text', text:'नवीन लाईन *ऑगस्टच्या शेवटी* येते आहे — २४ डिझाईन्स, सगळ्या ₹25,000 MRP च्या आत. कॅटलॉग तयार आहे, आत्ता पाठवू का?' },
          { t:'skus', codes:['KSN-ER-5522','KSN-RG-5540'] },
        ],
        choices: [ { label:'Book 6 pieces', goto:'book' } ],
      },
      book: {
        user: 'Book 6 of the short mangalsutra',
        bot: [
          { t:'cart', lines:[{ code:'KSN-MS-3318', qty:6 }], note:'Order KO-24938 · confirmed', confirmed:true },
          { t:'vox', text:'Order created from a voice instruction in Gujarati. Language detected per message, not per account — the same partner switches between three languages in one thread without any setting being changed.' },
        ],
        choices: [ { label:'Thanks', goto:'close' } ],
      },
      close: {
        bot: [
          { t:'system', text:'Gujarati, Hindi, Marathi and English in one thread. The trade belt does not operate in English, and the counter has no time to type.' },
        ],
        choices: [],
      },
    },
  },

};

// Display order for the launcher rail.
window.SCENARIO_ORDER = ['catalog', 'track', 'credit', 'collect', 'scheme', 'drop', 'desk', 'kyc', 'voice'];
