/*
 * Naina — Hiranandani WhatsApp Property Concierge · demo scenarios.
 * Each scenario is a small node graph: user msg → bot messages (typed specs) → quick-reply choices.
 * All data illustrative. Renderer types: text, reco, cards, rate, alloc, store, appt,
 * order, profile, campaign, voiceIn, voiceOut, rag, lead, system.
 */
window.SCENARIOS = {

  /* 1 ──────────────────────────── HOME DISCOVERY ─────────────────────── */
  discovery: {
    title: 'Find My Home', emoji: '🏙️', persona: 'Rohan · IT professional',
    blurb: '"3BHK in Thane under ₹2.2Cr" → matched homes with the why.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Hi, looking for a 3BHK in Thane, budget around ₹2.2 crore',
        bot: [
          { t:'text', text:'Great brief, Rohan! 🏡 Thane it is — let me match that against live inventory at *Hiranandani Estate* (and one smart alternative).' },
          { t:'reco', query:{ budget: 22000000, config: '3 BHK', city: 'Thane' }, n:3 },
          { t:'text', text:'The *Estate Regina 3 BHK* is the strongest fit — township living, hill views, Jun 2027 possession on a construction-linked plan. Want the cost sheet, or shall I line up a visit?' },
        ],
        choices: [
          { label:'📄 Send cost sheet', goto:'costsheet' },
          { label:'🏢 What about Powai?', goto:'powai' },
          { label:'📅 Book a site visit', goto:'visit' },
        ],
      },
      costsheet: {
        user: 'Send me the cost sheet',
        bot: [
          { t:'text', text:'Sending the *Estate Regina* cost sheet 📄 — all-inclusive: agreement value, stamp duty & registration, GST and township charges, on RERA carpet area. Nothing hidden.' },
          { t:'system', text:'Cost sheet PDF sent · MahaRERA no. included · viewed-receipt tracking on' },
          { t:'text', text:'Most buyers also ask how the payments spread out — here’s the construction-linked schedule on ₹2.15Cr:' },
          { t:'alloc', total: 21500000 },
        ],
        choices: [ { label:'📅 Book a site visit', goto:'visit' }, { label:'Looks good, thanks!', goto:'wrap' } ],
      },
      powai: {
        user: 'What would Powai cost me?',
        bot: [
          { t:'text', text:'Powai is our flagship — same 3 BHK space runs higher because of the lake and the walk-to-work business park:' },
          { t:'cards', ids:['HG-3B-03','HG-2B-02'], note:'*Hiranandani Gardens, Powai* — ready to move, zero GST' },
          { t:'text', text:'Honest take: your ₹2.2Cr goes further in Thane, and the Estate township gives you the same schools-clubs-retail ecosystem. Powai wins on commute if you work in the business park.' },
        ],
        choices: [ { label:'Stick with Thane', goto:'visit' }, { label:'📅 See both', goto:'visit' } ],
      },
      visit: {
        user: 'Book a site visit',
        bot: [
          { t:'store', city:'Thane' },
          { t:'appt', kind:'visit', store:'Thane', when:'Sat 12 Jul, 11:00 AM' },
          { t:'text', text:'Done! Your relationship manager *Prakash* will meet you at the Experience Centre — show flat, township drive-through and cost sheet walkthrough, about 90 minutes. I’ll send a reminder the evening before. 🙂' },
        ],
        choices: [ { label:'Great, thanks!', goto:'wrap' } ],
      },
      wrap: {
        bot: [
          { t:'lead', data:{ name:'Rohan', config:'3 BHK', location:'Thane', budget:'₹2.0–2.2 Cr', timeline:'≤3 months', next_step:'Site visit Sat 11 AM' }, score:'HOT' },
          { t:'system', text:'Lead pushed to Salesforce · RM Prakash assigned · reminder scheduled' },
        ],
        choices: [],
      },
    },
  },

  /* 2 ──────────────────────────── SITE VISIT ─────────────────────────── */
  sitevisit: {
    title: 'Site Visit Booking', emoji: '📅', persona: 'Meera & Arjun · first home',
    blurb: 'Weekend show-flat slot booked in under a minute — with directions.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Can we see the Panvel project this Sunday?',
        bot: [
          { t:'text', text:'Of course! *Fortune City* show flats are open every day 10:00–19:00. Sunday has slots at *11:00 AM*, *2:30 PM* and *5:00 PM* — which suits you both?' },
        ],
        choices: [
          { label:'11:00 AM', goto:'confirm' },
          { label:'5:00 PM', goto:'confirm' },
          { label:'Can’t travel — video tour?', goto:'virtual' },
        ],
      },
      confirm: {
        user: 'Sunday works!',
        bot: [
          { t:'store', city:'Panvel' },
          { t:'appt', kind:'visit', store:'Panvel', when:'Sun 13 Jul, 11:00 AM' },
          { t:'text', text:'Booked! 🎉 Pro tip: take the Atal Setu if you’re coming from Mumbai — about 45 minutes. Carry any ID; parking is at Gate 2. You’ll tour the 2 BHK show flat, sports complex and school.' },
          { t:'lead', data:{ name:'Meera & Arjun', config:'2 BHK', location:'Panvel', budget:'exploring', timeline:'3–6 months', next_step:'Site visit Sun 11 AM' }, score:'WARM' },
        ],
        choices: [],
      },
      virtual: {
        user: 'We can’t travel this weekend — video tour?',
        bot: [
          { t:'store', city:'Virtual' },
          { t:'appt', kind:'visit', store:'Virtual', when:'Sun 13 Jul, 4:00 PM' },
          { t:'text', text:'Locked in! An RM will video-call you on this number and walk the *actual show flat* live — you steer, they walk. Half our NRI buyers book this way before flying down once to finalise. 📱' },
          { t:'lead', data:{ name:'Meera & Arjun', config:'2 BHK', location:'Panvel', budget:'exploring', timeline:'3–6 months', next_step:'Video walkthrough Sun 4 PM' }, score:'WARM' },
        ],
        choices: [],
      },
    },
  },

  /* 3 ──────────────────────────── PAYMENT PLAN ───────────────────────── */
  payment: {
    title: 'Payment Plan', emoji: '🧾', persona: 'Kavita · upgrading',
    blurb: 'CLP schedule on a real number — plus what you pay to hold a unit.',
    entry: 'start',
    nodes: {
      start: {
        user: 'If I book the Estate Regina, how do payments work?',
        bot: [
          { t:'text', text:'Smart question to ask *before* falling in love with a flat 😄 On the construction-linked plan, ₹2.15Cr spreads like this:' },
          { t:'alloc', total: 21500000 },
          { t:'text', text:'Your money tracks real construction — RERA escrow, demand letters at each certified slab. And you only start heavy EMIs as the tower actually rises.' },
        ],
        choices: [
          { label:'What holds a unit today?', goto:'token' },
          { label:'GST on this?', goto:'gst' },
        ],
      },
      token: {
        user: 'What do I pay to hold a unit today?',
        bot: [
          { t:'rag', q:'booking token EOI hold' },
          { t:'text', text:'So: a refundable EOI holds your exact unit and floor while you decide — no pressure, fully refundable inside the window. Shall I have your RM reserve *Regina 1204* (the corner 3 BHK you liked)?' },
        ],
        choices: [ { label:'Yes, hold 1204 for me', goto:'hold' }, { label:'Let me think', goto:'END' } ],
      },
      gst: {
        user: 'What about GST?',
        bot: [
          { t:'rag', q:'gst under construction' },
          { t:'text', text:'On Regina (under construction) that’s 5%. If zero GST matters more than the newer phase, the *ready* Estate Villa Row or Powai inventory skips it entirely.' },
        ],
        choices: [ { label:'Yes, hold 1204 for me', goto:'hold' }, { label:'Show ready options', goto:'ready' } ],
      },
      ready: {
        user: 'Show me ready-to-move options',
        bot: [ { t:'reco', query:{ style:'ready', budget: 25000000 }, n:3 } ],
        choices: [ { label:'Yes, hold one for me', goto:'hold' } ],
      },
      hold: {
        user: 'Hold it for me',
        bot: [
          { t:'appt', kind:'reserve', product:'HE-3B-07' },
          { t:'text', text:'Held! Your RM will call within the hour with the EOI link — UPI or netbanking, receipt lands right here. The 7-day clock only starts once you pay. 🤝' },
          { t:'lead', data:{ name:'Kavita', config:'3 BHK', location:'Thane', budget:'₹2.1–2.2 Cr', timeline:'≤3 months', next_step:'EOI payment link sent' }, score:'HOT' },
        ],
        choices: [],
      },
    },
  },

  /* 4 ──────────────────────────── EMI & LOAN ─────────────────────────── */
  emi: {
    title: 'EMI & Home Loan', emoji: '🏦', persona: 'Sandeep · Panvel buyer',
    blurb: 'Loan rates, EMI reckoner, and 3 bank offers without leaving chat.',
    entry: 'start',
    nodes: {
      start: {
        user: 'What EMI am I looking at for the Fortune Crest 2BHK?',
        bot: [
          { t:'text', text:'Let’s work it out. Fortune Crest 2 BHK is *₹1.10Cr* all-in. Here are today’s indicative numbers:' },
          { t:'rate' },
          { t:'text', text:'With 20% down (₹22L) you’d borrow *₹88 lakh* → roughly *₹75,700/month* over 20 years at 8.35%, or about *₹70,000* over 25. Every bank prices you a little differently though — that’s where we help.' },
        ],
        choices: [
          { label:'Get me bank offers', goto:'offers' },
          { label:'Am I even eligible?', goto:'eligible' },
        ],
      },
      eligible: {
        user: 'How do I know if I’m eligible?',
        bot: [
          { t:'rag', q:'home loan eligibility sanction' },
          { t:'text', text:'Rule of thumb: banks want the EMI under ~50% of net monthly income — so ₹75,700 needs roughly ₹1.5L take-home, single or joint. Add a co-applicant and the number relaxes fast.' },
        ],
        choices: [ { label:'Get me bank offers', goto:'offers' } ],
      },
      offers: {
        user: 'Get me the bank offers',
        bot: [
          { t:'text', text:'On it. Our loan desk floats your profile to *SBI, HDFC and ICICI* (all APF-approved on Fortune City) and brings back competing sanctions — usually within *3 working days*, at zero charge.' },
          { t:'system', text:'Loan desk ticket LD-2841 created · consent captured · docs checklist sent' },
          { t:'lead', data:{ name:'Sandeep', config:'2 BHK', location:'Panvel', budget:'₹1.1 Cr', timeline:'3–6 months', next_step:'Loan pre-sanction · 3 banks' }, score:'HOT' },
        ],
        choices: [],
      },
    },
  },

  /* 5 ──────────────────────────── CONSTRUCTION STATUS ────────────────── */
  status: {
    title: 'Construction Status', emoji: '🏗️', persona: 'Existing buyer · Tower B',
    blurb: 'Slab-by-slab progress, RERA milestone and possession ETA — 24/7.',
    entry: 'start',
    nodes: {
      start: {
        user: 'What’s the status of my flat? Booking FC-B-1802',
        bot: [
          { t:'text', text:'Welcome back! 👷 Pulling the live tracker for *Fortune Crest, Tower B*:' },
          { t:'order', data:{ id:'FC-B-1802 · Tower B', item:'2 BHK · 18th floor · Fortune Crest, Panvel', status:'22nd slab cast — structure 78% done', eta:'Possession on track: Mar 2027', note:'Last site update: 4 Jul · next demand letter at top-out (Sep 2026, est.)' } },
          { t:'text', text:'Want this month’s drone photos of Tower B, or the payment position on your CLP schedule?' },
        ],
        choices: [
          { label:'📸 Send drone photos', goto:'photos' },
          { label:'💰 Payment position', goto:'ledger' },
        ],
      },
      photos: {
        user: 'Send the drone photos',
        bot: [
          { t:'system', text:'July site-progress album sent · 6 photos + 40s drone clip · Tower B highlighted' },
          { t:'text', text:'Sent! 📸 You’ll get these automatically on the first Friday of every month now — no need to ask. Anything else on your booking?' },
        ],
        choices: [ { label:'💰 Payment position', goto:'ledger' }, { label:'All good, thanks!', goto:'END' } ],
      },
      ledger: {
        user: 'Where do my payments stand?',
        bot: [
          { t:'order', data:{ id:'Ledger · FC-B-1802', item:'Paid: ₹66.0L of ₹1.10Cr (60%)', status:'No demand pending', eta:'Next milestone: top-out (~₹16.5L, Sep 2026 est.)', note:'All receipts + agreement in your document vault — type "documents" anytime.' } },
          { t:'text', text:'You’re fully up to date ✅ I’ll ping you here the day the top-out demand letter is raised, with the bank-transfer details.' },
        ],
        choices: [],
      },
    },
  },

  /* 6 ──────────────────────────── DOCS & POLICY (RAG) ────────────────── */
  docs: {
    title: 'RERA & Paperwork Q&A', emoji: '📚', persona: 'Cautious buyer',
    blurb: 'Carpet vs built-up, stamp duty, RERA — grounded answers with sources.',
    entry: 'start',
    nodes: {
      start: {
        user: 'What exactly is carpet area vs built-up?',
        bot: [
          { t:'rag', q:'carpet area built up' },
          { t:'text', text:'Ask me anything else on the paperwork side — I answer from our actual policy documents, not from thin air.' },
        ],
        choices: [
          { label:'Stamp duty in Mumbai?', goto:'stamp' },
          { label:'Is the project RERA registered?', goto:'rera' },
        ],
      },
      stamp: {
        user: 'How much stamp duty will I pay?',
        bot: [
          { t:'rag', q:'stamp duty registration' },
          { t:'text', text:'On a ₹2.15Cr agreement that’s ~₹12.9L stamp duty + ₹30,000 registration — and ₹2.15L less if the flat is in a woman’s name. It’s all itemised on the cost sheet before you commit.' },
        ],
        choices: [ { label:'Is the project RERA registered?', goto:'rera' }, { label:'That helps!', goto:'END' } ],
      },
      rera: {
        user: 'Is everything RERA registered?',
        bot: [
          { t:'rag', q:'rera registration maharera' },
          { t:'text', text:'You can verify any of our registration numbers yourself on the MahaRERA portal — I can send the direct link for the phase you’re considering. Transparency is the whole point. 🙂' },
        ],
        choices: [],
      },
    },
  },

  /* 7 ──────────────────────────── NRI BUYER (VOICE) ──────────────────── */
  nri: {
    title: 'NRI Buyer · Voice Notes', emoji: '🌏', persona: 'Vikram · Dubai',
    blurb: 'Hindi voice note in, voice reply out — POA, FEMA, video tours handled.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'voiceIn', lang:'हिं', dur:'0:11', text:'मैं दुबई में हूँ, Powai का 3BHK देखना है। क्या सब कुछ वहीं से हो सकता है?', gloss:'I’m in Dubai, want to look at the Powai 3BHK. Can everything be done from here?' },
          { t:'voiceOut', lang:'हिं', dur:'0:14', text:'बिल्कुल विक्रम जी! Video walkthrough, loan, agreement — सब remote हो सकता है। सिर्फ़ registration के लिए POA चाहिए, वो भी हम guide कर देंगे।', gloss:'Absolutely! Video walkthrough, loan, agreement — all remote. Only registration needs a POA, and we guide that too.' },
          { t:'rag', q:'nri power of attorney fema' },
        ],
        choices: [
          { label:'Book my video tour', goto:'tour' },
          { label:'Which flat suits NRIs?', goto:'reco' },
        ],
      },
      reco: {
        user: 'Which homes work best for NRI buyers?',
        bot: [
          { t:'reco', query:{ audience:'nri', budget: 50000000 }, n:3 },
          { t:'text', text:'Powai’s rental market is the NRI favourite — the business park keeps corporate tenants queued up. I can add a rental-management brief to your pack.' },
        ],
        choices: [ { label:'Book my video tour', goto:'tour' } ],
      },
      tour: {
        user: 'Book the video tour',
        bot: [
          { t:'appt', kind:'visit', store:'Virtual', when:'Fri 11 Jul, 8:00 PM IST (6:30 PM GST)' },
          { t:'text', text:'Booked for a Dubai-friendly hour 🌆 Your NRI-desk RM *Sneha* will call on this number — she’ll walk the Lake Verandah show flat live and stay on for FEMA/POA questions.' },
          { t:'lead', data:{ name:'Vikram (Dubai)', config:'3 BHK', location:'Powai', budget:'₹4.5 Cr', timeline:'3–6 months', next_step:'Video tour Fri 8 PM IST · NRI desk' }, score:'HOT' },
        ],
        choices: [],
      },
    },
  },

  /* 8 ──────────────────────────── FESTIVE CAMPAIGN ───────────────────── */
  festival: {
    title: 'Festive Launch Broadcast', emoji: '🪔', persona: 'Campaign · opt-in list',
    blurb: 'Diwali offer to 50,000 opt-ins — every reply handled instantly.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'campaign', data:{ title:'Diwali at Fortune City ✨', body:'New tower launch this Diwali — early-bird pricing for the first 100 bookings, stamp duty on us, and a festive home-decor package. Priority access for existing residents & their referrals.', cta:'Explore the launch' } },
          { t:'system', text:'Broadcast: 50,000 opt-ins · 91% delivered · 38% opened in first hour (illustrative)' },
          { t:'text', text:'👆 That’s what lands on every opted-in customer’s WhatsApp. And when thousands reply at once — I answer *all of them*, at once. Try it:' },
        ],
        choices: [
          { label:'What’s the early-bird price?', goto:'price' },
          { label:'I want priority access', goto:'lead' },
        ],
      },
      price: {
        user: 'What’s the early-bird pricing?',
        bot: [
          { t:'cards', ids:['FC-2B-10','FC-3B-11'], note:'Launch-tower pricing opens ~4% under current phase (SAMPLE) — exact sheet at the preview' },
          { t:'text', text:'First-100 slots go by EOI order. Shall I put you on the priority-preview list?' },
        ],
        choices: [ { label:'Yes — priority list', goto:'lead' } ],
      },
      lead: {
        user: 'Put me on the priority list',
        bot: [
          { t:'appt', kind:'bridal', store:'Panvel', when:'Launch preview · Sat 19 Jul, 10:30 AM' },
          { t:'lead', data:{ name:'Festive lead', config:'2/3 BHK', location:'Panvel', budget:'TBD', timeline:'≤3 months', next_step:'Launch preview RSVP' }, score:'WARM' },
          { t:'system', text:'RSVP confirmed · referral code applied · reminder T-1 day scheduled' },
        ],
        choices: [],
      },
    },
  },

  /* 9 ──────────────────────────── RETURNING BUYER MEMORY ─────────────── */
  concierge: {
    title: 'Returning Buyer Memory', emoji: '🧠', persona: 'Priya · visited in May',
    blurb: 'Remembers her visit, shortlist and loan status — picks up mid-journey.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Hi, I visited in May — any update on that 2BHK?',
        bot: [
          { t:'text', text:'Welcome back, Priya! 👋 Of course I remember — here’s where we left off:' },
          { t:'profile', data:{ visited:'Estate Experience Centre · 18 May', shortlist:'Bella Vista 2 BHK · high floor', budget:'₹1.4–1.5 Cr', loan:'HDFC pre-sanctioned ₹1.1 Cr (valid till Sep)', preference:'East-facing · post-Dec possession' } },
          { t:'text', text:'Update since your visit: *two east-facing high-floor units* opened up in Bella Vista last week, and your pre-sanction is still valid. One of them matches every box you ticked. 🎯' },
        ],
        choices: [
          { label:'Show me that unit', goto:'unit' },
          { label:'Revisit this weekend', goto:'visit' },
        ],
      },
      unit: {
        user: 'Show me the unit',
        bot: [
          { t:'cards', ids:['HE-2B-06'], note:'*B-1904* · east-facing · 19th floor · matches your May shortlist' },
          { t:'text', text:'At ₹1.42Cr it sits inside your sanction with room to spare. High floors in this line went fast last phase — want me to hold it while you plan the revisit?' },
        ],
        choices: [ { label:'Hold it + revisit Sat', goto:'hold' } ],
      },
      visit: {
        user: 'I’ll come this weekend',
        bot: [
          { t:'appt', kind:'visit', store:'Thane', when:'Sat 12 Jul, 4:00 PM' },
          { t:'text', text:'Booked — and I’ve asked Prakash to keep keys for *both* east-facing units so you can stand in the actual rooms, not just the show flat.' },
        ],
        choices: [ { label:'Hold B-1904 too', goto:'hold' } ],
      },
      hold: {
        user: 'Hold B-1904 for me',
        bot: [
          { t:'appt', kind:'reserve', product:'HE-2B-06' },
          { t:'lead', data:{ name:'Priya', config:'2 BHK · east-facing', location:'Thane', budget:'₹1.42 Cr', timeline:'≤1 month', next_step:'Unit held · revisit Sat 4 PM' }, score:'HOT' },
          { t:'system', text:'Continuity: 54 days since first visit · zero context lost · RM notified' },
        ],
        choices: [],
      },
    },
  },

  /* 10 ─────────────────────────── LEAD QUALIFICATION ─────────────────── */
  lead: {
    title: 'Lead Qualification', emoji: '🎯', persona: 'Portal lead · 11:40 PM',
    blurb: 'Midnight portal lead → qualified, scored and booked before breakfast.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'system', text:'11:42 PM · New lead from property portal → WhatsApp opt-in · responding in 4 seconds' },
          { t:'text', text:'Hi! I’m *Naina* from Hiranandani — you enquired about *Fortune City, Panvel* just now. I’m an AI assistant; answering instantly so you don’t wait till morning. 🙂 Quick one: is this your first home, or an upgrade/investment?' },
        ],
        choices: [
          { label:'First home', goto:'q2' },
          { label:'Investment', goto:'q2inv' },
        ],
      },
      q2: {
        user: 'First home for us',
        bot: [ { t:'text', text:'Lovely — Fortune City was built for exactly that. Which size fits your family: *1 BHK*, *2 BHK*, or *3 BHK*?' } ],
        choices: [ { label:'2 BHK', goto:'q3' }, { label:'3 BHK', goto:'q3' } ],
      },
      q2inv: {
        user: 'Mainly investment',
        bot: [ { t:'text', text:'Panvel’s the right map pin for that — airport corridor + Atal Setu. Are you thinking *residential* (2 BHK rents best) or the *business studios*?' } ],
        choices: [ { label:'Residential 2 BHK', goto:'q3' }, { label:'Business studio', goto:'q3' } ],
      },
      q3: {
        user: '2 BHK',
        bot: [ { t:'text', text:'Got it. And budget band — roughly *₹90L–1.1Cr*, *₹1.1–1.3Cr*, or still working it out? (No judgement either way 😄)' } ],
        choices: [ { label:'₹1.1–1.3 Cr', goto:'q4' }, { label:'Still working it out', goto:'q4' } ],
      },
      q4: {
        user: 'Around ₹1.1–1.3 crore',
        bot: [ { t:'text', text:'Perfect — Fortune Crest sits right in that band. Last one: when would you want to move — *within 3 months*, *3–6 months*, or *just exploring*?' } ],
        choices: [ { label:'3–6 months', goto:'close' }, { label:'Just exploring', goto:'closeExplore' } ],
      },
      close: {
        user: 'In the next 3–6 months',
        bot: [
          { t:'cards', ids:['FC-2B-10'], note:'Your match — held for your visit' },
          { t:'text', text:'You’re a serious buyer, so let’s do this properly: show-flat visit this weekend? Saturday *11 AM* or Sunday *4 PM* — I’ll have the cost sheet and CLP schedule printed and waiting.' },
        ],
        choices: [ { label:'Saturday 11 AM', goto:'done' }, { label:'Sunday 4 PM', goto:'done' } ],
      },
      closeExplore: {
        user: 'Just exploring for now',
        bot: [
          { t:'text', text:'Totally fine — buying a home should never feel rushed. I’ll send the Fortune City brochure and add you to the monthly progress-photo list. When you’re ready, I’m one message away. 🙏' },
          { t:'lead', data:{ name:'Portal lead', config:'2 BHK', location:'Panvel', budget:'₹1.1–1.3 Cr', timeline:'exploring', next_step:'Nurture track · brochure sent' }, score:'NURTURE' },
        ],
        choices: [],
      },
      done: {
        user: 'Saturday 11 AM',
        bot: [
          { t:'appt', kind:'visit', store:'Panvel', when:'Sat 12 Jul, 11:00 AM' },
          { t:'lead', data:{ name:'Portal lead', config:'2 BHK', location:'Panvel', budget:'₹1.1–1.3 Cr', timeline:'3–6 months', next_step:'Site visit Sat 11 AM' }, score:'HOT' },
          { t:'system', text:'Qualified in 94 seconds at 11:44 PM · RM sees a complete brief at 9 AM · zero human minutes spent' },
        ],
        choices: [],
      },
    },
  },
};

window.SCENARIO_ORDER = ['discovery','sitevisit','payment','emi','status','docs','nri','festival','concierge','lead'];
