/*
 * Tara — Tata Power Solar WhatsApp AI Concierge · demo scenarios.
 * Each scenario is a small node graph: user msg → bot messages (typed specs) → quick-reply choices.
 * All data illustrative, grounded in public 2025-26 figures (PM Surya Ghar slabs,
 * net-metering timelines, payback norms). Renderer types: text, reco, cards, rate,
 * alloc, store, appt, order, profile, campaign, voiceIn, voiceOut, rag, lead, system.
 */
window.SCENARIOS = {

  /* 1 ──────────────────────── BILL → SYSTEM DISCOVERY ────────────────── */
  discovery: {
    title: 'Bill → Right System', emoji: '☀️', persona: 'Suresh · Pune homeowner',
    blurb: '"My bill is ₹4,000/month" → sized system, savings and payback.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Hi, my electricity bill is around ₹4,000 a month. Is solar worth it for me?',
        bot: [
          { t:'text', text:'Short answer, Suresh: yes — a ₹4,000 bill is squarely solar territory. ☀️ At ~₹8/unit you use about *500 units a month*, which needs a *4–5 kW* system. Here’s what fits:' },
          { t:'reco', query:{ bill: 4000, audience:'home' }, n:3 },
          { t:'text', text:'The *5 kW Solaroof* covers your entire bill. After the ₹78,000 PM Surya Ghar subsidy the net cost is ~₹2.3 lakh — your bill savings pay that back in *under 4 years*, then it’s free power for 20+.' },
        ],
        choices: [
          { label:'💰 How does the subsidy work?', goto:'subsidy' },
          { label:'📉 Show me the exact savings', goto:'savings' },
          { label:'📅 Book a site survey', goto:'survey' },
        ],
      },
      subsidy: {
        user: 'How does the subsidy work?',
        bot: [
          { t:'rag', q:'pm surya ghar subsidy' },
          { t:'text', text:'And no, you don’t chase it — we file the portal application, handle the discom feasibility and the inspection. The ₹78,000 lands in *your* bank account after commissioning.' },
        ],
        choices: [ { label:'📅 Book a site survey', goto:'survey' }, { label:'📉 Show the savings math', goto:'savings' } ],
      },
      savings: {
        user: 'Show me the savings math',
        bot: [
          { t:'rag', q:'payback savings roi' },
          { t:'text', text:'For *your* ₹4,000 bill specifically: 5 kW generates ~600 units/month → bill drops to near zero → *~₹48,000 saved every year*. Net cost ₹2.3L ÷ ₹48k ≈ *4 years to break even*. Your roof out-earns a fixed deposit 3× over.' },
        ],
        choices: [ { label:'📅 Book a site survey', goto:'survey' } ],
      },
      survey: {
        user: 'Book a site survey',
        bot: [
          { t:'text', text:'The survey is free — an engineer checks shadow-free roof area (you need ~400–500 sq ft for 5 kW), structure and wiring, and gives you a final quote on the spot.' },
          { t:'store', city:'Pune' },
          { t:'appt', kind:'visit', store:'Pune', when:'Sat 12 Jul, 10:30 AM' },
        ],
        choices: [ { label:'Done, thanks!', goto:'wrap' } ],
      },
      wrap: {
        bot: [
          { t:'lead', data:{ name:'Suresh', bill:'₹4,000/mo', system:'5 kW on-grid', city:'Pune', subsidy:'₹78,000 eligible', next_step:'Site survey Sat 10:30 AM' }, score:'HOT' },
          { t:'system', text:'Lead pushed to CRM · surveyor assigned · reminder scheduled' },
        ],
        choices: [],
      },
    },
  },

  /* 2 ──────────────────────── SUBSIDY ELIGIBILITY ────────────────────── */
  subsidy: {
    title: 'Subsidy Eligibility Check', emoji: '🏛️', persona: 'Rekha · Jaipur',
    blurb: 'PM Surya Ghar: slab, eligibility and the paperwork — pre-checked.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Am I eligible for the PM Surya Ghar subsidy? How much will I get?',
        bot: [
          { t:'rag', q:'subsidy amount surya ghar' },
          { t:'text', text:'Three quick checks decide eligibility, Rekha — answer these and I’ll confirm on the spot:\n1️⃣ Is the electricity connection in your name?\n2️⃣ Is it your own roof?\n3️⃣ Residential connection (not commercial)?' },
        ],
        choices: [
          { label:'Yes to all three', goto:'eligible' },
          { label:'It’s my father’s name', goto:'name' },
          { label:'We live on rent', goto:'rent' },
        ],
      },
      eligible: {
        user: 'Yes to all three!',
        bot: [
          { t:'text', text:'Then you qualify ✅ For a 3 kW system that’s the full *₹78,000* — credited to your bank account 4–8 weeks after commissioning. Here’s everything we’ll need:' },
          { t:'rag', q:'documents checklist' },
          { t:'text', text:'One thing that trips people up: the name on the electricity bill must match the application *exactly*. I pre-check that before filing, so your application doesn’t join the rejection pile.' },
        ],
        choices: [ { label:'📅 Start with a site survey', goto:'survey' }, { label:'What panels qualify?', goto:'dcr' } ],
      },
      name: {
        user: 'The connection is in my father’s name',
        bot: [
          { t:'text', text:'Very common, and easily solved: the application simply goes in *his* name with his bank account for the subsidy — you can still be the contact for everything. Alternatively the discom can transfer the connection name first, which takes a few weeks. Most families just apply in the existing name.' },
        ],
        choices: [ { label:'Apply in his name then', goto:'eligible' } ],
      },
      rent: {
        user: 'We live on rent',
        bot: [
          { t:'rag', q:'eligibility tenant noc' },
          { t:'text', text:'So: possible with the owner’s notarized NOC, and the subsidy goes to the connection holder. Honest advice — it works best when the owner is on board and the arrangement is long-term. Want me to send a one-page explainer you can forward to your landlord?' },
        ],
        choices: [ { label:'Send the explainer', goto:'explainer' } ],
      },
      explainer: {
        user: 'Send the explainer',
        bot: [
          { t:'system', text:'Owner explainer PDF sent · Hindi + English · covers NOC format' },
          { t:'lead', data:{ name:'Rekha', bill:'—', system:'3 kW (tenant case)', city:'Jaipur', subsidy:'via owner NOC', next_step:'Landlord explainer sent' }, score:'WARM' },
        ],
        choices: [],
      },
      dcr: {
        user: 'Which panels qualify for subsidy?',
        bot: [
          { t:'rag', q:'dcr panels eligibility' },
          { t:'text', text:'All our residential systems use DCR modules from our own factory — subsidy-safe by default. Imported panels void the subsidy; that’s the corner some vendors cut.' },
        ],
        choices: [ { label:'📅 Book the site survey', goto:'survey' } ],
      },
      survey: {
        user: 'Book the site survey',
        bot: [
          { t:'store', city:'Jaipur' },
          { t:'appt', kind:'visit', store:'Jaipur', when:'Sun 13 Jul, 11:00 AM' },
          { t:'lead', data:{ name:'Rekha', bill:'₹2,800/mo', system:'3 kW on-grid', city:'Jaipur', subsidy:'₹78,000 eligible ✓', next_step:'Site survey Sun 11 AM' }, score:'HOT' },
        ],
        choices: [],
      },
    },
  },

  /* 3 ──────────────────────── QUOTE + FINANCING ──────────────────────── */
  quote: {
    title: 'Quote & EMI Explainer', emoji: '🧾', persona: 'Amit · comparing quotes',
    blurb: 'Line-by-line quote, milestone payments and the ₹2,499 EMI path.',
    entry: 'start',
    nodes: {
      start: {
        user: 'I got your quote for the 3kW system. Walk me through it?',
        bot: [
          { t:'text', text:'Happily, Amit — a quote you don’t fully understand is a quote you shouldn’t sign. Yours is *₹1,95,000* all-in for 3 kW. Here’s how the payment actually flows:' },
          { t:'alloc', total: 195000 },
          { t:'text', text:'Then the *₹78,000 subsidy* comes back to your bank account after commissioning — so your true cost is *₹1,17,000*. No hidden line items: structure, wiring, net-meter liaison and 5-year service are all inside.' },
        ],
        choices: [
          { label:'💳 Can I pay by EMI?', goto:'emi' },
          { label:'Another vendor quoted ₹1.4L', goto:'compare' },
        ],
      },
      emi: {
        user: 'Can I pay by EMI?',
        bot: [
          { t:'rate' },
          { t:'rag', q:'emi finance down payment' },
          { t:'text', text:'On your 3 kW: roughly *₹7,499 down and ~₹2,499/month* — which is likely *less than your current electricity bill*. You swap the bill for an EMI that ends; the bill never does.' },
        ],
        choices: [ { label:'📅 Book it — site survey first', goto:'book' } ],
      },
      compare: {
        user: 'Another vendor quoted ₹1.4 lakh for 3kW',
        bot: [
          { t:'text', text:'Then ask them three questions:\n1️⃣ Are the panels *DCR-certified*? (If not, your ₹78,000 subsidy is gone — that “cheaper” quote just cost you ₹78k.)\n2️⃣ Who files the *net-metering* paperwork and chases the discom?\n3️⃣ Who answers the phone in year 3 when the inverter faults?\n\nOur price includes all three. The industry’s biggest complaint isn’t price — it’s vendors who disappear after installation.' },
        ],
        choices: [ { label:'Fair point. EMI options?', goto:'emi' }, { label:'📅 Book the survey', goto:'book' } ],
      },
      book: {
        user: 'Book the site survey',
        bot: [
          { t:'appt', kind:'visit', store:'Mumbai', when:'Sat 12 Jul, 4:00 PM' },
          { t:'lead', data:{ name:'Amit', bill:'₹3,200/mo', system:'3 kW on-grid', city:'Mumbai', financing:'EMI ₹2,499/mo', next_step:'Survey Sat 4 PM' }, score:'HOT' },
          { t:'system', text:'Quote QT-3104 linked · EMI pre-check initiated · surveyor assigned' },
        ],
        choices: [],
      },
    },
  },

  /* 4 ──────────────────────── INSTALL + NET-METER TRACKER ────────────── */
  status: {
    title: 'Installation & Net-Meter Tracker', emoji: '🛰️', persona: 'Existing customer · installed',
    blurb: 'The 1–3 month net-meter wait, made transparent — stage by stage.',
    entry: 'start',
    nodes: {
      start: {
        user: 'My panels were installed 3 weeks ago. Where is my net meter??',
        bot: [
          { t:'text', text:'I hear you — the net-meter wait is the most frustrating part of going solar, and it’s the discom’s queue, not your installation. But here’s *exactly* where yours stands:' },
          { t:'order', data:{ id:'NM-8842 · Net-meter application', item:'3 kW · Andheri West · MSEDCL', status:'Stage 3 of 4 — meter inspection PASSED on 6 Jul', eta:'Meter swap scheduled: 15–18 Jul (discom window)', note:'We escalated on 4 Jul when the queue slipped · next auto-update the moment the meter is installed.' } },
          { t:'text', text:'Until the swap, your panels still power your home during the day — you’re already saving on daytime units. The *export credits* start counting from the swap date.' },
        ],
        choices: [
          { label:'What are the 4 stages?', goto:'stages' },
          { label:'When does my subsidy come?', goto:'subsidy' },
        ],
      },
      stages: {
        user: 'What are the 4 stages?',
        bot: [
          { t:'rag', q:'net metering process timeline' },
          { t:'text', text:'You’re past application ✓, feasibility ✓ and inspection ✓ — only the physical swap remains. I ping you here the moment each stage moves. No more visits to the discom office; that’s my job now.' },
        ],
        choices: [ { label:'When does my subsidy come?', goto:'subsidy' } ],
      },
      subsidy: {
        user: 'And when does my ₹78,000 subsidy arrive?',
        bot: [
          { t:'order', data:{ id:'SG-5521 · Subsidy claim', item:'PM Surya Ghar · ₹78,000 · 3 kW', status:'Filed — awaiting commissioning certificate (auto-generated at meter swap)', eta:'Expected credit: 4–8 weeks after swap → mid-September', note:'Bank account verified ✓ · Aadhaar-bill name match ✓ · nothing pending from your side.' } },
          { t:'text', text:'Everything on your side is done. The moment the money hits your account, you’ll know — and knowing you, probably before the bank SMS arrives. 😄' },
        ],
        choices: [],
      },
    },
  },

  /* 5 ──────────────────────── BILL EXPLANATION ───────────────────────── */
  bill: {
    title: 'Post-Solar Bill Decoder', emoji: '🔍', persona: 'Confused customer · month 2',
    blurb: '"Why is my bill ₹2,100 with solar?!" — decoded line by line.',
    entry: 'start',
    nodes: {
      start: {
        user: 'This is wrong!! I installed solar and my bill is still ₹2,100?! It was supposed to be zero!',
        bot: [
          { t:'text', text:'Let’s get to the bottom of it right now — send me a photo of the bill and I’ll read it line by line. Meanwhile, pulling your generation data:' },
          { t:'order', data:{ id:'Bill audit · June', item:'Import: 410 units · Export: 356 units · Net billed: 54 units', status:'⚠️ Anomaly found: discom billed FULL import (410 units), export not adjusted', eta:'Correct bill should be ~₹430 + fixed charges, not ₹2,100', note:'This is the most common discom billing error in the first 2 cycles after a net-meter swap.' } },
          { t:'text', text:'So: your solar is working perfectly — *the discom billed your import without subtracting your export*. It happens to thousands of new solar homes. Here’s the fix:' },
        ],
        choices: [
          { label:'How do we fix it?', goto:'fix' },
          { label:'Explain import/export to me', goto:'explain' },
        ],
      },
      explain: {
        user: 'Explain this import export thing',
        bot: [
          { t:'rag', q:'bill import export credit' },
          { t:'text', text:'In your June numbers: 410 imported − 356 exported = *54 net units*. That’s a few hundred rupees, not ₹2,100. You did nothing wrong and your system is fine — the meter reading just wasn’t netted.' },
        ],
        choices: [ { label:'How do we fix it?', goto:'fix' } ],
      },
      fix: {
        user: 'So how do we fix it?',
        bot: [
          { t:'text', text:'Already moving. I’ve drafted the billing-correction request with your meter data attached — we file it with the discom and track it like a net-meter application. You do *not* pay the wrong bill; you pay the corrected one.' },
          { t:'system', text:'Complaint BC-1177 filed with MSEDCL · meter data + export log attached · SLA 7 working days' },
          { t:'text', text:'I’ll update you here at every stage. And from next cycle, I auto-check your bill against your generation data *before* you even see it — this doesn’t happen twice.' },
          { t:'lead', data:{ name:'Bill audit case', system:'3 kW · month 2', issue:'Export not adjusted by discom', action:'Correction filed · auto bill-check enabled', next_step:'Discom SLA 7 days' }, score:'RETAINED' },
        ],
        choices: [],
      },
    },
  },

  /* 6 ──────────────────────── SERVICE TICKET (VOICE) ─────────────────── */
  service: {
    title: 'Service · Voice Note Fault', emoji: '🔧', persona: 'Ramesh bhai · Hindi voice note',
    blurb: 'Hindi voice note in — inverter fault triaged, technician booked.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'voiceIn', lang:'हिं', dur:'0:09', text:'इन्वर्टर पर लाल लाइट जल रही है और मीटर पर कुछ नहीं दिख रहा। बिजली बन नहीं रही क्या?', gloss:'There’s a red light on the inverter and the meter shows nothing. Is it not generating?' },
          { t:'voiceOut', lang:'हिं', dur:'0:13', text:'रमेश जी, घबराइए मत — लाल लाइट अक्सर ग्रिड-साइड फ़ॉल्ट होती है। मैं अभी आपके सिस्टम का डेटा देख रही हूँ।', gloss:'Don’t worry Ramesh ji — a red light is usually a grid-side fault. Checking your system data right now.' },
          { t:'order', data:{ id:'Remote diagnostic · INV-2287', item:'3 kW · inverter GW-3000 · Jaipur', status:'⚠️ Fault code E-31: grid voltage out of range — inverter self-protected (not a hardware failure)', eta:'Generation paused since 9:40 AM · auto-resumes when grid stabilises', note:'If not resolved by evening, a technician visit is free under warranty.' } },
        ],
        choices: [
          { label:'Send a technician anyway', goto:'tech' },
          { label:'It restarted! What was that?', goto:'explain' },
        ],
      },
      tech: {
        user: 'Please send a technician',
        bot: [
          { t:'appt', kind:'visit', store:'Jaipur', when:'Tomorrow, 10:00–12:00 window' },
          { t:'text', text:'Booked — technician *Mahesh* (he installed your system) will check the earthing and grid connection. Free under warranty. You’ll get his live location when he starts. 🙂' },
          { t:'lead', data:{ name:'Ramesh', system:'3 kW · Jaipur', issue:'E-31 grid voltage fault', action:'Technician visit tomorrow 10–12', warranty:'Covered ✓' }, score:'SERVICE' },
        ],
        choices: [],
      },
      explain: {
        user: 'It restarted on its own! What happened?',
        bot: [
          { t:'voiceOut', lang:'हिं', dur:'0:11', text:'ग्रिड की वोल्टेज ठीक होते ही इन्वर्टर खुद चालू हो गया — यही उसका काम है। आपका सिस्टम बिल्कुल ठीक है।', gloss:'The inverter restarted itself once grid voltage stabilised — that’s its job. Your system is perfectly fine.' },
          { t:'rag', q:'maintenance cleaning amc' },
          { t:'text', text:'One tip while I have you: your last panel cleaning was 5 weeks ago and generation is down ~8%. Shall I schedule a cleaning visit?' },
        ],
        choices: [ { label:'Yes, schedule cleaning', goto:'clean' } ],
      },
      clean: {
        user: 'Yes, schedule the cleaning',
        bot: [
          { t:'appt', kind:'visit', store:'Jaipur', when:'Fri 11 Jul, 8:00 AM' },
          { t:'system', text:'Cleaning visit booked · AMC customer · no charge · monthly auto-reminder enabled' },
        ],
        choices: [],
      },
    },
  },

  /* 7 ──────────────────────── GENERATION REPORT ──────────────────────── */
  report: {
    title: 'Monthly Savings Report', emoji: '📈', persona: 'Customer · month 6',
    blurb: 'Proactive monthly report — generation, savings, payback progress.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'system', text:'1st of the month · auto-report to every active system owner' },
          { t:'text', text:'Good morning! ☀️ Your June solar report is in, and it’s a good one:' },
          { t:'order', data:{ id:'June report · 5 kW system', item:'Generated: 642 units (vs 610 forecast ✅)', status:'Bill: ₹184 (was ₹4,120 before solar) · Saved this month: ₹3,936', eta:'Total saved in 6 months: ₹22,400 · payback 19% complete', note:'Best day: 14 Jun (26.4 units) · generation 5% above your society’s average.' } },
          { t:'text', text:'You’re ahead of forecast. At this rate your system pays for itself in *3 years 8 months* — two months earlier than quoted. 📉⚡' },
        ],
        choices: [
          { label:'Why was week 4 lower?', goto:'why' },
          { label:'Refer my neighbour 😄', goto:'refer' },
        ],
      },
      why: {
        user: 'Why did week 4 dip?',
        bot: [
          { t:'rag', q:'monsoon cloud generation drop' },
          { t:'text', text:'Week 4 was the monsoon’s opening act — 4 cloudy days. Your annual forecast already budgets for it, which is why you’re still *above* target for the year. Nothing to fix.' },
        ],
        choices: [ { label:'Refer my neighbour 😄', goto:'refer' } ],
      },
      refer: {
        user: 'My neighbour keeps asking about my bill',
        bot: [
          { t:'text', text:'The ₹184 bill is the best salesperson we have. 😄 Share this link — if they install, you both get a *free year of AMC* (cleaning + inspections, worth ₹15,000 on a 5 kW).' },
          { t:'system', text:'Referral link sent · code SURESH-5K · reward: 1-yr AMC both sides' },
          { t:'lead', data:{ name:'Referral · neighbour', source:'Existing customer month-6 report', context:'₹184 bill screenshot shared', next_step:'Neighbour opt-in link sent' }, score:'WARM' },
        ],
        choices: [],
      },
    },
  },

  /* 8 ──────────────────────── HOUSING SOCIETY ────────────────────────── */
  society: {
    title: 'Housing Society · RWA', emoji: '🏢', persona: 'Mrs. Iyer · society secretary',
    blurb: 'Common-area solar for a 120-flat society — group net metering.',
    entry: 'start',
    nodes: {
      start: {
        user: 'I’m the secretary of a 120-flat society in Powai. Our common-area bill is ₹85,000/month. Can solar help?',
        bot: [
          { t:'text', text:'Mrs. Iyer, an ₹85,000 common-area bill is exactly what society solar was built for. Lifts, pumps, lobby lighting — all of it can run on your own terrace. Here’s the fit:' },
          { t:'cards', ids:['TS-10S'], note:'Sized for your bill, a *~60 kW* array typically fits a 120-flat terrace — shown here is the modular 10 kW block we scale up.' },
          { t:'rag', q:'society rwa group net metering' },
        ],
        choices: [
          { label:'What do we need to start?', goto:'docs' },
          { label:'How much would we save?', goto:'savings' },
        ],
      },
      savings: {
        user: 'How much would we actually save?',
        bot: [
          { t:'text', text:'On ₹85,000/month: a right-sized array cuts *60–90%* — call it *₹55,000–75,000 every month*, ₹7–9 lakh a year. That flows straight into lower maintenance charges for all 120 members. The committee that does this gets re-elected. 😄' },
        ],
        choices: [ { label:'What do we need to start?', goto:'docs' } ],
      },
      docs: {
        user: 'What do we need to start?',
        bot: [
          { t:'text', text:'Three things:\n1️⃣ A managing-committee resolution (I’ll send the standard draft)\n2️⃣ Last 6 months of common-area bills\n3️⃣ Society registration / OC copy\n\nThen a free terrace survey, and you present our proposal at your next AGM — we join on video for the members’ questions.' },
          { t:'system', text:'RWA resolution draft + AGM presentation pack sent' },
        ],
        choices: [ { label:'Book the terrace survey', goto:'survey' } ],
      },
      survey: {
        user: 'Book the terrace survey',
        bot: [
          { t:'appt', kind:'visit', store:'Mumbai', when:'Wed 16 Jul, 11:00 AM' },
          { t:'lead', data:{ name:'Mrs. Iyer (Secretary)', society:'120 flats · Powai', bill:'₹85,000/mo common area', system:'~60 kW group net metering', next_step:'Terrace survey Wed 11 AM + AGM pack' }, score:'HOT' },
          { t:'system', text:'Society lead routed to C&I team · AGM support flagged' },
        ],
        choices: [],
      },
    },
  },

  /* 9 ──────────────────────── C&I / COMMERCIAL ───────────────────────── */
  ci: {
    title: 'Factory · CAPEX vs OPEX', emoji: '🏭', persona: 'CFO · textile unit',
    blurb: '₹6L/month factory bill → both models compared on real numbers.',
    entry: 'start',
    nodes: {
      start: {
        user: 'We run a textile unit near Surat. Power bill is about ₹6 lakh/month. What would solar look like for us?',
        bot: [
          { t:'text', text:'At ₹6 lakh a month you’re the textbook C&I case. Roof or land available, roughly *750 kW–1 MW* offsets most of your daytime load. The real question is *how you want to pay for it* — and there are two answers:' },
          { t:'rag', q:'capex opex ppa commercial' },
          { t:'cards', ids:['TS-100C'], note:'Modular 100 kW blocks — your plant would take 7–10 of these' },
        ],
        choices: [
          { label:'We have capital — CAPEX math', goto:'capex' },
          { label:'Zero investment — OPEX math', goto:'opex' },
        ],
      },
      capex: {
        user: 'We’d rather own it. CAPEX numbers?',
        bot: [
          { t:'text', text:'Owning wins on lifetime value:\n• ~₹4 crore for 1 MW (indicative)\n• Offsets ~₹4.5–5 lakh of your monthly bill\n• *Payback 3–5 years*, then ~20 years of power at near-zero marginal cost\n• Accelerated depreciation shields profit in years 1–2\n\nYour CA will like this more than any machine you’ve bought. Next step is a load study on 12 months of bills.' },
        ],
        choices: [ { label:'Book the load study', goto:'audit' }, { label:'Compare with OPEX anyway', goto:'opex' } ],
      },
      opex: {
        user: 'What does zero-investment look like?',
        bot: [
          { t:'text', text:'OPEX/RESCO: we build, own and maintain the plant on your roof — you just buy the units it produces at a *tariff locked below your grid rate*. Zero capex, zero O&M headache, savings from month one. The trade: lower lifetime savings than owning, and a 15–25 year PPA term. Capital-light CFOs love it; asset-builders pick CAPEX.' },
        ],
        choices: [ { label:'Book the load study', goto:'audit' } ],
      },
      audit: {
        user: 'Book the load study',
        bot: [
          { t:'appt', kind:'visit', store:'Virtual', when:'Mon 14 Jul, 3:00 PM · Teams/WhatsApp video' },
          { t:'text', text:'Booked. Our C&I team will model both structures on your actual 12-month load profile — you’ll see CAPEX payback and OPEX tariff side by side, on your numbers, not brochure numbers.' },
          { t:'lead', data:{ name:'CFO · textile unit', bill:'₹6 lakh/mo', system:'~1 MW', models:'CAPEX vs OPEX comparison', next_step:'Load study Mon 3 PM' }, score:'HOT' },
          { t:'system', text:'Routed to C&I desk · 12-month bill upload link sent' },
        ],
        choices: [],
      },
    },
  },

  /* 10 ─────────────────────── LEAD QUALIFICATION ─────────────────────── */
  lead: {
    title: 'Midnight Lead Qualification', emoji: '🎯', persona: 'Campaign lead · 11:30 PM',
    blurb: 'Ad click at 11:30 PM → qualified and survey-booked before 9 AM.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'system', text:'11:31 PM · New lead from “Ghar Ghar Solar” Facebook ad → WhatsApp opt-in · responding in 4 seconds' },
          { t:'text', text:'Hi! I’m *Tara* from Tata Power Solar — you clicked our rooftop solar ad just now. I’m an AI assistant, answering instantly so you don’t wait till morning. 🙂 Quick one: is this for your *own house*, a *flat/society*, or a *business*?' },
        ],
        choices: [
          { label:'Own house', goto:'q2' },
          { label:'Business', goto:'q2biz' },
        ],
      },
      q2: {
        user: 'Own house',
        bot: [ { t:'text', text:'Perfect — own roof means full subsidy eligibility. What’s your monthly electricity bill, roughly? *Under ₹2,000*, *₹2,000–5,000*, or *above ₹5,000*?' } ],
        choices: [ { label:'₹2,000–5,000', goto:'q3' }, { label:'Above ₹5,000', goto:'q3big' } ],
      },
      q2biz: {
        user: 'For my business',
        bot: [ { t:'text', text:'Got it — shop/office or factory/warehouse scale? (This decides whether we talk subsidy-style systems or CAPEX/OPEX models.)' } ],
        choices: [ { label:'Shop / office', goto:'q3' }, { label:'Factory / warehouse', goto:'q4biz' } ],
      },
      q3: {
        user: 'Around ₹2,000–5,000 a month',
        bot: [ { t:'text', text:'That’s the 3–5 kW zone — full *₹78,000 subsidy* territory. Last question: is the roof your own (house/independent floor), and roughly *300+ sq ft* of open terrace?' } ],
        choices: [ { label:'Yes, own roof', goto:'close' }, { label:'Need to check size', goto:'close' } ],
      },
      q3big: {
        user: 'Above ₹5,000',
        bot: [ { t:'text', text:'Nice roof economics — 5–8 kW range, and the subsidy still knocks off ₹78,000. Is the roof your own, with *400+ sq ft* free of shadow?' } ],
        choices: [ { label:'Yes, own roof', goto:'close' } ],
      },
      q4biz: {
        user: 'Factory / warehouse',
        bot: [
          { t:'text', text:'Then you want our C&I desk, not the home team — they model CAPEX vs OPEX on your last 12 months of bills. I’ll set up a call at an hour that suits you, and email a one-pager tonight.' },
          { t:'lead', data:{ name:'Ad lead · 11:31 PM', type:'C&I · factory', bill:'TBD', next_step:'C&I desk call + one-pager sent' }, score:'HOT' },
        ],
        choices: [],
      },
      close: {
        user: 'Yes, own roof',
        bot: [
          { t:'text', text:'Then you’re a textbook case. Next step is a *free 30-minute site survey* — engineer checks the roof, you get the exact system size, subsidy and quote on the spot. Morning or evening slots tomorrow?' },
        ],
        choices: [ { label:'Morning', goto:'done' }, { label:'Evening', goto:'done' } ],
      },
      done: {
        user: 'Morning works',
        bot: [
          { t:'appt', kind:'visit', store:'Mumbai', when:'Tomorrow, 10:30 AM' },
          { t:'lead', data:{ name:'Ad lead', bill:'₹2,000–5,000/mo', system:'3–5 kW · subsidy eligible', roof:'Own ✓', next_step:'Site survey tomorrow 10:30 AM' }, score:'HOT' },
          { t:'system', text:'Qualified in 96 seconds at 11:33 PM · surveyor sees a complete brief at 9 AM · zero human minutes spent' },
        ],
        choices: [],
      },
    },
  },
};

window.SCENARIO_ORDER = ['discovery','subsidy','quote','status','bill','service','report','society','ci','lead'];
