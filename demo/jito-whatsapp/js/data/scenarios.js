/*
 * Jinal — JITO WhatsApp Community Concierge · demo scenarios.
 * Each scenario is a small node graph: user msg → bot messages (typed specs) → quick-reply chips.
 * All member names, fees and figures are illustrative. Renderer types: text, reco, cards,
 * rate, store, appt, order, profile, campaign, voiceIn, voiceOut, rag, lead, system.
 */
window.SCENARIOS = {

  /* 1 ──────────────────────────── MEMBER DIRECTORY ───────────────────── */
  directory: {
    title: 'Member Directory Search', emoji: '🔎', persona: 'Amit · JBN Mumbai member',
    blurb: '"Need a CA in Pune" → verified member matches + warm intro.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Need a good CA in Pune for GST and export compliance',
        bot: [
          { t:'text', text:'On it, Amit! 🔎 Searching the verified member directory for *chartered accountants in Pune*…' },
          { t:'reco', query:{ need:'ca', city:'Pune', keywords:['gst'] }, n:2 },
          { t:'text', text:'*Sanghvi & Associates* is the strongest match — they run GST and cross-border compliance for SME exporters, exactly your use case. Shall I make a warm intro?' },
        ],
        choices: [
          { label:'🤝 Request the intro', goto:'intro' },
          { label:'Show Mumbai options too', goto:'mumbai' },
        ],
      },
      mumbai: {
        user: 'Also show me Mumbai firms',
        bot: [
          { t:'reco', query:{ need:'ca', city:'Mumbai' }, n:2 },
          { t:'text', text:'*Jain Mehta & Co.* also does JIIF deal diligence — handy if you ever raise. Member-to-member work carries the JBN referral ethic: tracked, accountable, celebrated.' },
        ],
        choices: [ { label:'🤝 Intro to Sanghvi (Pune)', goto:'intro' } ],
      },
      intro: {
        user: 'Yes, connect me',
        bot: [
          { t:'appt', kind:'reserve', product:'M-CA-01' },
          { t:'text', text:'Intro sent! 📨 Both sides get each other’s cards; CA Sanghvi typically responds within a few hours. The referral is logged to your JBN chapter’s tally. 🙌' },
          { t:'lead', data:{ member:'Amit (JBN Mumbai)', request:'CA — GST & export compliance', matched:'Sanghvi & Associates, Pune', channel:'Directory search', outcome:'Warm intro sent' }, score:'REFERRAL' },
          { t:'system', text:'Referral logged · JBN Mumbai ↔ JBN Pune · both members notified' },
        ],
        choices: [],
      },
    },
  },

  /* 2 ──────────────────────────── MEMBERSHIP ONBOARDING ──────────────── */
  membership: {
    title: 'New Member Onboarding', emoji: '📝', persona: 'Nirav · Ahmedabad, first contact',
    blurb: 'Chapter finder → tiers explained → application captured in-chat.',
    entry: 'start',
    nodes: {
      start: {
        user: 'How do I become a JITO member? I run a packaging business in Ahmedabad',
        bot: [
          { t:'text', text:'Welcome, Nirav! 🙏 Great news — Ahmedabad has one of our most active chapters. Membership is through your city chapter, and one membership opens every wing: JBN networking, education programmes, JIIF investing, matrimony and events.' },
          { t:'store', city:'Ahmedabad' },
          { t:'rag', q:'membership eligibility tiers fees' },
        ],
        choices: [
          { label:'📝 Start my application', goto:'apply' },
          { label:'What will I actually get?', goto:'value' },
        ],
      },
      value: {
        user: 'What do members actually get?',
        bot: [
          { t:'text', text:'Straight answer: *business first*. JBN chapter meetings put you in a room of verified members exchanging referrals — one member per category, so your packaging business has the seat to itself. Plus JIIF dealflow if you invest, education support for your kids, and the community network across chapters worldwide.' },
        ],
        choices: [ { label:'📝 Start my application', goto:'apply' } ],
      },
      apply: {
        user: 'Start my application',
        bot: [
          { t:'text', text:'Done in a minute. I have your name and this WhatsApp number — just confirm: business name *Nirav Packaging* (from your profile), category *Packaging & Printing*, chapter *Ahmedabad*. Correct?' },
        ],
        choices: [ { label:'✔ Correct — submit', goto:'submit' } ],
      },
      submit: {
        user: 'Correct, submit it',
        bot: [
          { t:'lead', data:{ name:'Nirav', business:'Nirav Packaging', category:'Packaging & Printing', chapter:'Ahmedabad', stage:'Application submitted', next_step:'Chapter secretary call + JBN guest invite' }, score:'NEW MEMBER' },
          { t:'text', text:'Application in! 🎉 The Ahmedabad chapter secretary will call you within two working days, and I’ve reserved a *guest seat at the next JBN meeting* so you can experience it before your membership is even processed.' },
          { t:'appt', kind:'visit', store:'Ahmedabad', when:'JBN guest seat · Thu 17 Jul, 8:00 AM' },
        ],
        choices: [],
      },
    },
  },

  /* 3 ──────────────────────────── JBN MEETING RSVP ───────────────────── */
  jbn: {
    title: 'JBN Meeting & Referrals', emoji: '🤝', persona: 'Chapter member · weekly meet',
    blurb: 'RSVP the Thursday meeting, invite a guest, check your referral tally.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Am I confirmed for Thursday’s JBN meeting?',
        bot: [
          { t:'text', text:'Checking… you’re *not RSVP’d yet* for Thursday 8:00 AM at the Pune chapter. 42 of 51 members confirmed so far. Shall I lock your seat?' },
        ],
        choices: [
          { label:'✔ Confirm my seat', goto:'confirm' },
          { label:'➕ I’m bringing a guest', goto:'guest' },
        ],
      },
      confirm: {
        user: 'Confirm my seat',
        bot: [
          { t:'appt', kind:'visit', store:'Pune', when:'Thu 17 Jul, 8:00 AM · JBN Pune' },
          { t:'text', text:'Locked ✔ This week’s spotlight: *logistics & warehousing*. Your referral tally this quarter: *7 given · 4 received* — two ahead of last quarter. See you Thursday!' },
          { t:'system', text:'RSVP recorded · reminder Wed 8 PM · agenda PDF sent' },
        ],
        choices: [],
      },
      guest: {
        user: 'I want to bring a guest — he runs a hardware business',
        bot: [
          { t:'rag', q:'jbn guest policy' },
          { t:'text', text:'And *hardware* is an open category at Pune — perfect timing. Send me his name and number, and I’ll WhatsApp him the guest pass + venue pin directly.' },
        ],
        choices: [ { label:'Rajesh Jain, 98220-XXXXX', goto:'guestdone' } ],
      },
      guestdone: {
        user: 'Rajesh Jain, 98220-XXXXX',
        bot: [
          { t:'appt', kind:'visit', store:'Pune', when:'Thu 17 Jul, 8:00 AM · guest pass' },
          { t:'lead', data:{ guest:'Rajesh Jain', category:'Hardware (open at Pune)', invited_by:'Chapter member', stage:'Guest pass sent', next_step:'Attend Thu · membership pitch after' }, score:'PROSPECT' },
          { t:'system', text:'Guest pass WhatsApp’d to Rajesh · category conflict check: none' },
        ],
        choices: [],
      },
    },
  },

  /* 4 ──────────────────────────── JITO CONNECT EXPO ──────────────────── */
  connect: {
    title: 'JITO Connect Expo', emoji: '🎪', persona: 'Broadcast · 80,000 members',
    blurb: 'Expo broadcast → stall booking & visitor passes, handled at scale.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'campaign', data:{ title:'JITO Connect 2026 🎪', body:'The flagship global trade fair returns — 100+ stalls, the JPoint Deal Arena, startup pavilion and speaker summit. Members get priority stall allotment and free visitor passes. Three days of the community doing business with the community.', cta:'Book stalls & passes' } },
          { t:'system', text:'Broadcast: 80,000 members · illustrative delivery 94% · every reply answered instantly' },
          { t:'text', text:'👆 One broadcast, thousands of replies — I handle every single one. Try it:' },
        ],
        choices: [
          { label:'🏬 Book an exhibition stall', goto:'stall' },
          { label:'🎟️ Free visitor pass', goto:'pass' },
        ],
      },
      stall: {
        user: 'I want a stall for my textile business',
        bot: [
          { t:'rag', q:'jito connect stall exhibition' },
          { t:'text', text:'For textiles you’d sit in the *fabrics & apparel* zone — great footfall from export buyers last edition. Standard stalls are 9 sqm; corner and pavilion options go by priority allotment. Shall I raise your allotment request?' },
        ],
        choices: [ { label:'Yes — request a stall', goto:'stalldone' } ],
      },
      stalldone: {
        user: 'Request the stall',
        bot: [
          { t:'lead', data:{ member:'Textile exhibitor', zone:'Fabrics & apparel', stall:'9 sqm standard (corner requested)', stage:'Allotment request raised', next_step:'Committee confirms slot + payment link' }, score:'EXHIBITOR' },
          { t:'system', text:'Request #JC-0412 sent to organising committee · queue position shared' },
          { t:'text', text:'Raised! The committee confirms allotments in order of request — you’re in the queue with a corner preference noted. Payment link follows on confirmation. 🤞' },
        ],
        choices: [],
      },
      pass: {
        user: 'Send me a visitor pass',
        bot: [
          { t:'appt', kind:'bridal', store:'Hyderabad', when:'JITO Connect · 3–5 Oct, all-day pass' },
          { t:'text', text:'Pass sent 🎟️ — QR code lands here on WhatsApp, valid all three days. Want me to build you a *personal agenda* — which pavilions and speakers match your business — a week before the event?' },
          { t:'lead', data:{ visitor:'Member + 1', pass:'3-day QR issued', interest:'To be profiled', next_step:'Personal agenda opt-in' }, score:'VISITOR' },
        ],
        choices: [],
      },
    },
  },

  /* 5 ──────────────────────────── JATF · UPSC ────────────────────────── */
  jatf: {
    title: 'JATF · UPSC Aspirant', emoji: '🎓', persona: 'Khushi · final-year student',
    blurb: 'CET application, eligibility and hostel Q&A — grounded in the prospectus.',
    entry: 'start',
    nodes: {
      start: {
        user: 'I want to prepare for UPSC. What is JATF and can I apply?',
        bot: [
          { t:'rag', q:'jatf upsc cet coaching' },
          { t:'text', text:'In short, Khushi: serious coaching at a fraction of market cost, because the community funds it. *CET-2026 applications are open now.* Want me to check your eligibility?' },
        ],
        choices: [
          { label:'✅ Check my eligibility', goto:'eligible' },
          { label:'What does it cost?', goto:'cost' },
        ],
      },
      eligible: {
        user: 'Check my eligibility',
        bot: [
          { t:'text', text:'Three quick things: 1️⃣ Are you a graduate (or final year)? 2️⃣ Jain community family? 3️⃣ Ready for full-time residential prep? Reply yes/no in order — e.g. *yes, yes, yes*.' },
        ],
        choices: [ { label:'Yes, yes, yes', goto:'apply' } ],
      },
      cost: {
        user: 'What does it cost?',
        bot: [
          { t:'text', text:'Coaching, lodging and boarding come *heavily subsidised* — the exact fee schedule is in the CET-2026 prospectus I can send right here (SAMPLE figures until you receive it). The selection filter is merit: CET written + interview, not your wallet.' },
        ],
        choices: [ { label:'✅ Check my eligibility', goto:'eligible' } ],
      },
      apply: {
        user: 'Yes, yes and yes!',
        bot: [
          { t:'text', text:'You qualify to sit the CET 🎯 I’ve started your application — prospectus + past CET papers coming to this chat. Fun fact for motivation: the community celebrated *35 Jain officers in the 2025 UPSC results*. One of those seats has your name on it.' },
          { t:'lead', data:{ name:'Khushi', programme:'JATF CET-2026', status:'Application started · docs requested', documents:'Graduation proof, ID, photo', next_step:'CET admit card on verification' }, score:'APPLICANT' },
          { t:'system', text:'Application #CET-3117 · document checklist sent · deadline reminder scheduled' },
        ],
        choices: [],
      },
    },
  },

  /* 6 ──────────────────────────── EDUCATION LOAN ─────────────────────── */
  eduloan: {
    title: 'Education Loan Subsidy', emoji: '🏦', persona: 'Parent · son admitted abroad',
    blurb: 'Interest-subsidy scheme explained + document checklist + application.',
    entry: 'start',
    nodes: {
      start: {
        user: 'My son got admission in Germany. Does JITO help with education loans?',
        bot: [
          { t:'text', text:'Congratulations to him! 🎉 Yes — this is one of JITO’s most-used programmes. Here’s how the numbers work:' },
          { t:'rate' },
          { t:'rag', q:'education loan interest subsidy' },
        ],
        choices: [
          { label:'📋 What documents?', goto:'docs' },
          { label:'Start the application', goto:'apply' },
        ],
      },
      docs: {
        user: 'What documents are needed?',
        bot: [
          { t:'text', text:'Checklist: admission letter, fee schedule, the bank’s loan sanction letter, student ID + community reference from your chapter, and income proof. You upload everything right here on WhatsApp — no office visit needed. 📎' },
        ],
        choices: [ { label:'Start the application', goto:'apply' } ],
      },
      apply: {
        user: 'Start the application',
        bot: [
          { t:'lead', data:{ applicant:'Parent (Mumbai chapter)', student:'Son · MS in Germany', loan:'Bank sanction pending', scheme:'Interest subsidy (SAMPLE terms)', next_step:'Docs on WhatsApp → education desk review' }, score:'APPLICANT' },
          { t:'system', text:'Application #EDU-8804 opened · document upload link active 30 days' },
          { t:'text', text:'Application opened ✔ Upload the documents as you get them — I’ll track what’s pending and nudge you gently. The education desk reviews within a week of the full set. 🙏' },
        ],
        choices: [],
      },
    },
  },

  /* 7 ──────────────────────────── MATRIMONY ──────────────────────────── */
  matrimony: {
    title: 'JITO Matrimony', emoji: '💐', persona: 'Mother · enquiring for daughter',
    blurb: 'Free portal, privacy-first profile setup, convention meet RSVP.',
    entry: 'start',
    nodes: {
      start: {
        user: 'I heard JITO has a matrimony service? Asking for my daughter',
        bot: [
          { t:'rag', q:'matrimony free profile privacy' },
          { t:'text', text:'Two ways to begin, whenever the family is ready: create her portal profile (I can set it up right here), or attend the *matrimonial meet at the upcoming convention* — a graceful, family-friendly setting for introductions.' },
        ],
        choices: [
          { label:'💐 Create her profile', goto:'profile' },
          { label:'🎟️ RSVP the convention meet', goto:'meet' },
        ],
      },
      profile: {
        user: 'Let’s create the profile',
        bot: [
          { t:'text', text:'Lovely. I’ll ask a few details one at a time — education, profession, city, and the family’s preferences. *Nothing is visible publicly*: contact details unlock only when both families consent. You can pause anytime and pick up later — I remember where we left off.' },
          { t:'profile', data:{ profile:'Daughter · 27 · Mumbai', education:'CA, working at Big-4', preferences:'Professional family · Mumbai/Pune · vegetarian', visibility:'Private · consent-gated', status:'Draft — 60% complete' } },
          { t:'text', text:'Draft saved 🔒 Whenever you send the remaining details, it goes live to matched families only.' },
        ],
        choices: [ { label:'🎟️ Also RSVP the meet', goto:'meet' }, { label:'We’ll continue later', goto:'END' } ],
      },
      meet: {
        user: 'RSVP us for the convention meet',
        bot: [
          { t:'appt', kind:'bridal', store:'Mumbai', when:'Apex Convention matrimonial meet · 14 Sep' },
          { t:'lead', data:{ family:'Mother + daughter', profile:'Draft on portal', event:'Convention matrimonial meet', chapter:'Mumbai', next_step:'Event brief + etiquette note sent' }, score:'RSVP' },
          { t:'text', text:'Reserved 💐 You’ll receive the format brief a week before — profiles exchange only between families who mutually opt in. Wishing your daughter the very best. 🙏' },
        ],
        choices: [],
      },
    },
  },

  /* 8 ──────────────────────────── JAN · STARTUP DEALFLOW ─────────────── */
  jan: {
    title: 'JAN · Startup Pitch', emoji: '🚀', persona: 'Founder · agritech startup',
    blurb: 'Founder qualified into JIIF dealflow — sector, stage, raise captured.',
    entry: 'start',
    nodes: {
      start: {
        user: 'I run an agritech startup. How do I pitch JITO Angel Network?',
        bot: [
          { t:'rag', q:'angel network jan startup funding pitch' },
          { t:'text', text:'So you’re pitching a network that has *actually deployed* — ₹106Cr+ across 56+ startups. Let me qualify your round for the screening committee. What stage are you at?' },
        ],
        choices: [
          { label:'Seed — raising ₹3 Cr', goto:'q2' },
          { label:'Series A', goto:'q2' },
        ],
      },
      q2: {
        user: 'Seed round, raising ₹3 crore',
        bot: [ { t:'text', text:'Got it. Revenue-stage or pre-revenue? And do you have a lead investor yet, or would you want JAN to lead? (They do both — lead and co-invest.)' } ],
        choices: [ { label:'₹40L ARR, need a lead', goto:'q3' } ],
      },
      q3: {
        user: '₹40 lakh ARR, looking for a lead',
        bot: [
          { t:'cards', ids:['M-ST-11'], note:'For reference — a JAN agritech portfolio company (SAMPLE)' },
          { t:'text', text:'Strong fit on paper: agritech, seed, revenue-stage, lead-seeking — squarely in JAN’s pocket. Send your deck here and I’ll package the one-pager the screening committee sees.' },
        ],
        choices: [ { label:'📎 Deck sent — submit me', goto:'done' } ],
      },
      done: {
        user: '[deck.pdf attached]',
        bot: [
          { t:'lead', data:{ founder:'Agritech · Pune', stage:'Seed · ₹3 Cr · seeking lead', traction:'₹40L ARR', source:'WhatsApp intake', next_step:'JIIF screening → pitch day shortlist' }, score:'DEALFLOW' },
          { t:'system', text:'Deal #JAN-0287 in screening queue · founder gets outcome either way in 10 days' },
          { t:'text', text:'You’re in the queue 🚀 Screening takes ~10 days and you hear back *either way* — no ghosting. If shortlisted, you pitch at the next JIIF pitch day in front of 1,000+ member-investors. Best of luck!' },
        ],
        choices: [],
      },
    },
  },

  /* 9 ──────────────────────────── VERNACULAR VOICE ───────────────────── */
  voice: {
    title: 'Seva Desk · Voice Notes', emoji: '🎙️', persona: 'Senior member · Gujarati',
    blurb: 'Gujarati voice note in, voice reply out — medical assistance routed.',
    entry: 'start',
    nodes: {
      start: {
        bot: [
          { t:'voiceIn', lang:'ગુજ', dur:'0:13', text:'મારા પતિની બાયપાસ સર્જરી છે. મેં સાંભળ્યું કે JITO હોસ્પિટલમાં મદદ કરે છે?', gloss:'My husband needs bypass surgery. I heard JITO helps with hospitals?' },
          { t:'voiceOut', lang:'ગુજ', dur:'0:16', text:'જી બહેન, ચિંતા ના કરો. આપણી chapter helpdesk હોસ્પિટલ tie-up અને સહાય માટે તરત મદદ કરશે. હું હમણાં જ તમારી વિનંતી મોકલી રહી છું.', gloss:'Yes behn, don’t worry. Our chapter helpdesk will help right away with hospital tie-ups and assistance. I’m sending your request now.' },
          { t:'rag', q:'medical emergency assistance seva' },
        ],
        choices: [
          { label:'🙏 Please send the request', goto:'route' },
        ],
      },
      route: {
        user: 'Please send it',
        bot: [
          { t:'lead', data:{ member:'Senior member · Mumbai', request:'Medical assistance — bypass surgery', language:'Gujarati (voice)', urgency:'High', next_step:'Chapter seva desk callback < 2 hrs' }, score:'SEVA' },
          { t:'system', text:'Routed to Mumbai chapter seva desk · marked urgent · coordinator assigned' },
          { t:'voiceOut', lang:'ગુજ', dur:'0:09', text:'મોકલી દીધું છે બહેન. બે કલાકમાં આપણા coordinator નો ફોન આવશે. જય જિનેન્દ્ર.', gloss:'It’s sent, behn. Our coordinator will call within two hours. Jai Jinendra.' },
        ],
        choices: [],
      },
    },
  },

  /* 10 ─────────────────────────── RENEWAL · MEMORY ───────────────────── */
  renewal: {
    title: 'Renewal · Member Memory', emoji: '🧠', persona: 'Suresh · member since 2015',
    blurb: 'Knows his chapter, history and dues — renewal in two taps.',
    entry: 'start',
    nodes: {
      start: {
        user: 'Hi, I think my membership is due for renewal?',
        bot: [
          { t:'text', text:'Jai Jinendra, Suresh bhai! 🙏 Yes — your renewal window opened this week. Here’s your JITO year at a glance:' },
          { t:'profile', data:{ chapter:'Pune · member since 2015', jbn:'Referrals: 11 given · 9 received this year', events:'JITO Connect ’25 + 2 chapter meets', family:'Daughter availed education-loan subsidy 2024', renewal:'Due 31 Jul (SAMPLE)' } },
          { t:'text', text:'Same tier renewal takes two taps — or, given your referral numbers, the chapter would happily consider you for the *Patron* tier. Interested?' },
        ],
        choices: [
          { label:'♻️ Renew same tier', goto:'renew' },
          { label:'Tell me about Patron', goto:'patron' },
        ],
      },
      patron: {
        user: 'What does Patron get me?',
        bot: [
          { t:'text', text:'Patron members get priority stall allotment at JITO Connect, invitations to the apex leadership circle, and first access to JIIF pitch days. Fee difference is modest at your tenure (SAMPLE — chapter confirms). Many members upgrade in their 10th year — which is you. 😄' },
        ],
        choices: [ { label:'⬆️ Upgrade to Patron', goto:'renew' }, { label:'♻️ Same tier for now', goto:'renew' } ],
      },
      renew: {
        user: 'Renew it',
        bot: [
          { t:'system', text:'Renewal link sent · UPI/netbanking · receipt + 80G (where eligible) auto-issued here' },
          { t:'lead', data:{ member:'Suresh · Pune', tenure:'11th year', action:'Renewal link sent', tier:'Decision pending Patron upgrade', next_step:'Auto-receipt on payment' }, score:'RENEWAL' },
          { t:'text', text:'Link sent ✔ Pay whenever convenient — receipt lands right here. Thank you for eleven years with the JITO Pariwar, Suresh bhai. 🙏' },
        ],
        choices: [],
      },
    },
  },
};

window.SCENARIO_ORDER = ['directory','membership','jbn','connect','jatf','eduloan','matrimony','jan','voice','renewal'];
