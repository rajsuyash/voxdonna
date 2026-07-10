/*
 * Jinal — JITO WhatsApp AI Community Concierge · interactive demo controller.
 * Pure front-end. Drives the scripted scenarios in scenarios.js, renders WhatsApp-style
 * messages, and handles free-typed text via a small NLU + the RAG / recommendation engines.
 */
(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
  const inr = n => '₹' + Number(n).toLocaleString('en-IN');
  const now = () => { const d = new Date(); return d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0'); };

  const state = { scenario: null, node: null, busy: false, profile: null, leadCount: 0, gen: 0 };
  const bump = () => ++state.gen;            // invalidate any in-flight playback
  const stale = g => state.gen !== g;        // true if a newer interaction started

  const thread = () => $('#thread');
  const scrollDown = () => { const t = thread(); t.scrollTop = t.scrollHeight; };

  // ---------- low-level bubble helpers ----------
  function addOutgoing(html) {
    const row = el('div', 'row out');
    row.appendChild(el('div', 'bubble b-out', `${html}<span class="meta">${now()} <span class="ticks">✓✓</span></span>`));
    thread().appendChild(row); scrollDown();
  }
  function addIncoming(node) {
    const row = el('div', 'row in');
    const b = el('div', 'bubble b-in');
    b.appendChild(node);
    b.appendChild(el('span', 'meta', `${now()}`));
    row.appendChild(b);
    thread().appendChild(row); scrollDown();
    return b;
  }
  function addSystem(text) {
    const row = el('div', 'row sys');
    row.appendChild(el('div', 'syschip', text));
    thread().appendChild(row); scrollDown();
  }
  function typing(on) {
    let t = $('#typing');
    if (on) {
      setHeaderStatus('typing…');
      if (t) return;
      const row = el('div', 'row in'); row.id = 'typing';
      row.appendChild(el('div', 'bubble b-in typing', '<span></span><span></span><span></span>'));
      thread().appendChild(row); scrollDown();
    } else {
      setHeaderStatus('online');
      if (t) t.remove();
    }
  }
  const wait = ms => new Promise(r => setTimeout(r, ms));

  // ---------- product card rendering ----------
  function productCard(p, why) {
    const c = el('div', 'pcard');
    c.innerHTML = `
      <div class="pimg">${window.jewelSVG(p.icon)}<span class="brandtag">${p.township}</span></div>
      <div class="pbody">
        <div class="ptitle">${p.name}</div>
        <div class="pmeta">${p.config} · ${p.city}</div>
        ${why ? `<div class="pwhy">✨ ${why}</div>` : ''}
        <div class="pprice" style="font-size:12px">${p.since}</div>
        <div class="pacts">
          <button class="pbtn" data-act="reserve" data-id="${p.id}">Request intro</button>
          <button class="pbtn ghost" data-act="visit" data-id="${p.id}">Chapter details</button>
        </div>
      </div>`;
    c.querySelectorAll('.pbtn').forEach(btn => btn.addEventListener('click', () => {
      const id = btn.dataset.id, p2 = window.PRODUCT_BY_ID[id];
      const chapterCity = window.STORE_BY_CITY[p2.city.toLowerCase()] ? p2.city : 'Virtual';
      addOutgoing(btn.dataset.act === 'reserve' ? `Intro to ${p2.name}` : `Chapter details for ${p2.name}`);
      botSay([
        { t:'text', text: btn.dataset.act === 'reserve'
            ? `Done! 🤝 Warm intro sent to *${p2.name}* — both sides receive each other’s cards, and the referral is logged to your JBN chapter tally.`
            : `*${p2.name}* is with the ${p2.township} chapter — here are the chapter’s details:` },
        btn.dataset.act === 'reserve' ? { t:'appt', kind:'reserve', product:id } : { t:'store', city: chapterCity },
      ]);
    }));
    return c;
  }

  function cardCarousel(ids, withWhy) {
    const wrap = el('div', 'carousel');
    ids.forEach(item => {
      if (typeof item === 'string') wrap.appendChild(productCard(window.PRODUCT_BY_ID[item]));
      else wrap.appendChild(productCard(item.p, withWhy ? item.why : null));
    });
    return wrap;
  }

  // ---------- rich message renderers ----------
  const RENDER = {
    text(spec) { addIncoming(el('div', '', fmt(spec.text))); },

    reco(spec) {
      const recs = window.RecoEngine.recommend(spec.query, spec.n || 3);
      addIncoming(cardCarousel(recs, true));
    },
    cards(spec) {
      if (spec.note) addIncoming(el('div', '', fmt(spec.note)));
      addIncoming(cardCarousel(spec.ids, false));
    },
    rate() {
      const r = window.EDU_RATES;
      const n = el('div', 'ratecard', `
        <div class="rc-h">🎓 Education Support <span class="rc-tag">JITO programmes</span></div>
        <div class="rc-row"><span>Bank loan rate from</span><b>${r.bankFrom}</b></div>
        <div class="rc-row"><span>JITO benefit</span><b>Interest subsidy</b></div>
        <div class="rc-row"><span>JATF (UPSC)</span><b>${r.cetWindow}</b></div>
        <div class="rc-foot">${r.subsidy} · as of ${r.asOf}</div>`);
      addIncoming(n);
    },
    alloc(spec) {
      const plan = window.RecoEngine.bridalAllocation(spec.total);
      let rows = plan.map(x => `<div class="al-row"><span>${x.part}</span><b>${inr(x.amount)}</b><i>${x.pct*100}%</i></div>`).join('');
      const n = el('div', 'alloccard', `
        <div class="al-h">🧾 Construction-linked schedule · ${inr(spec.total)}</div>${rows}
        <div class="al-foot">Demands raised only on architect-certified slabs · payments sit in the RERA escrow account.</div>`);
      addIncoming(n);
    },
    store(spec) {
      const s = window.STORE_BY_CITY[spec.city.toLowerCase()];
      const n = el('div', 'storecard', `
        <div class="map">📍</div>
        <div class="st-body">
          <div class="st-name">${s.name}</div>
          <div class="st-area">${s.area}</div>
          <div class="st-meta">🕙 ${s.hours} · 🗣️ ${s.langs.slice(0,3).join(', ')}${s.showFlat ? ' · 🏠 Show flat open' : ''}</div>
          <div class="st-acts"><button class="pbtn ghost" disabled>Get directions</button></div>
        </div>`);
      addIncoming(n);
    },
    appt(spec) {
      let title, body;
      if (spec.kind === 'reserve') {
        const p = window.PRODUCT_BY_ID[spec.product];
        title = '🤝 Intro requested'; body = `${p.name}<br><b>${p.config}</b> · ${p.township}<br>Ref: <b>INT${(1000+(state.leadCount*7)%9000)}</b> · both members notified`;
      } else if (spec.kind === 'bridal') {
        title = '🎟️ RSVP confirmed'; body = `${window.STORE_BY_CITY[spec.store.toLowerCase()].name}<br><b>${spec.when}</b><br>QR pass on WhatsApp · priority entry`;
      } else {
        title = '📅 Seat confirmed'; body = `${window.STORE_BY_CITY[spec.store.toLowerCase()].name}<br><b>${spec.when}</b><br>Chapter desk notified · reminder scheduled`;
      }
      addIncoming(el('div', 'apptcard', `<div class="ap-h">${title}</div><div class="ap-b">${body}</div><div class="ap-cal">＋ Add to calendar</div>`));
    },
    order(spec) {
      const d = spec.data;
      const ok = /ready|delivered|out for/i.test(d.status);
      addIncoming(el('div', 'ordercard', `
        <div class="or-h">🏗️ ${d.id}</div>
        <div class="or-item">${d.item}</div>
        <div class="or-status ${ok ? 'good':''}">${d.status}</div>
        <div class="or-eta">${d.eta}</div>
        <div class="or-note">${d.note || ''}</div>`));
    },
    profile(spec) {
      state.profile = spec.data; const d = spec.data;
      addIncoming(el('div', 'profilecard', `
        <div class="pf-h">🧠 Customer memory</div>
        ${Object.entries(d).map(([k,v]) => `<div class="pf-row"><span>${cap(k)}</span><b>${v}</b></div>`).join('')}`));
    },
    campaign(spec) {
      const d = spec.data;
      addIncoming(el('div', 'campaigncard', `
        <div class="cmp-banner">🪔</div>
        <div class="cmp-title">${d.title}</div>
        <div class="cmp-body">${d.body}</div>
        <button class="cmp-cta" disabled>${d.cta}</button>`));
    },
    voiceIn(spec) { renderVoice(spec, 'out'); },   // simulated customer voice (outgoing side)
    voiceOut(spec) { renderVoice(spec, 'in'); },   // Jinal voice reply (incoming side)
    photo() {
      const row = el('div', 'row out');
      row.appendChild(el('div', 'bubble b-out photo', `<div class="ph"><img src="assets/ananya.jpg" alt="your photo"><span>your photo.jpg</span></div><span class="meta">${now()} <span class="ticks">✓✓</span></span>`));
      thread().appendChild(row); scrollDown();
    },
    tryon(spec) {
      const visual = spec.img
        ? `<div class="to-frame has-img"><img src="${spec.img}" alt="AI try-on render"><div class="to-badge">✨ AI render</div></div>`
        : `<div class="to-frame has-img"><img src="assets/ananya.jpg" alt="analysing your photo"><div class="to-scan"></div></div>`;
      const n = el('div', 'tryoncard', `
        <div class="to-h">🪄 AI Visual Try-On</div>
        ${visual}
        <div class="to-detect">${spec.detect.map(d => `<span>${d}</span>`).join('')}</div>`);
      addIncoming(n);
    },
    rag(spec) {
      const a = window.RAG.answer(spec.q);
      if (!a) { RENDER.text({ text:'Let me connect you with a store expert for that. 👩‍💼' }); return; }
      const n = el('div', '', `${fmt(a.text)}<div class="cite">📄 Source: ${a.cites}</div>`);
      addIncoming(n);
    },
    lead(spec) {
      state.leadCount++;
      const d = spec.data;
      const n = el('div', 'leadcard', `
        <div class="ld-h">🎯 Lead captured ${spec.score ? `<span class="ld-score">${spec.score}</span>`:''}</div>
        ${Object.entries(d).map(([k,v]) => `<div class="ld-row"><span>${cap(k)}</span><b>${v}</b></div>`).join('')}`);
      addIncoming(n);
    },
    system(spec) { addSystem(spec.text); },
  };

  function renderVoice(spec, side) {
    const isIn = side === 'in';
    const row = el('div', 'row ' + (isIn ? 'in' : 'out'));
    const b = el('div', 'bubble ' + (isIn ? 'b-in' : 'b-out') + ' voice');
    b.innerHTML = `
      <div class="vc">
        <button class="vc-play">▶</button>
        <div class="vc-wave">${'<i></i>'.repeat(22)}</div>
        <span class="vc-dur">${spec.dur}</span>
        <span class="vc-lang">${spec.lang}</span>
      </div>
      <div class="vc-tx"><b>${isIn ? 'Jinal' : 'Heard'} (${spec.lang}):</b> ${spec.text}<br><i>“${spec.gloss}”</i></div>
      ${isIn ? `<span class="meta">${now()}</span>` : `<span class="meta">${now()} <span class="ticks">✓✓</span></span>`}`;
    b.querySelector('.vc-play').addEventListener('click', e => {
      e.target.textContent = e.target.textContent === '▶' ? '❚❚' : '▶';
      b.querySelector('.vc-wave').classList.toggle('playing');
    });
    row.appendChild(b); thread().appendChild(row); scrollDown();
  }

  // ---------- play a list of bot messages with realistic typing ----------
  async function botSay(specs) {
    const g = state.gen;
    state.busy = true; setControls(false);
    for (const spec of specs) {
      typing(true);
      const base = spec.t === 'text' ? 500 + Math.min((spec.text||'').length * 11, 1400) : 650;
      await wait(base);
      if (stale(g)) { typing(false); return; }      // a newer scenario/interaction took over
      typing(false);
      (RENDER[spec.t] || RENDER.text)(spec);
      await wait(180);
      if (stale(g)) return;
    }
    state.busy = false; setControls(true);
  }

  // ---------- quick replies ----------
  function renderChoices(choices) {
    const bar = $('#chips'); bar.innerHTML = '';
    if (!choices || !choices.length) { bar.classList.add('empty'); return; }
    bar.classList.remove('empty');
    choices.forEach(c => {
      const chip = el('button', 'chip', c.label);
      chip.addEventListener('click', () => { if (state.busy) return; chooseChoice(c); });
      bar.appendChild(chip);
    });
  }

  async function chooseChoice(c) {
    bump();
    $('#chips').innerHTML = '';
    addOutgoing(c.label);
    await gotoNode(c.goto);
  }

  // ---------- node engine ----------
  async function startScenario(key) {
    bump();                              // cancel any in-flight playback
    state.busy = false; setControls(true);
    const sc = window.SCENARIOS[key];
    state.scenario = sc; state.node = null; state.profile = null;
    clearThread();
    setHeaderSub(sc.persona ? `Demo · ${sc.persona}` : 'online');
    highlightLauncher(key);
    await gotoNode(sc.entry);
  }

  async function gotoNode(key) {
    if (key === 'END' || !key) { renderChoices([]); return; }
    const node = state.scenario.nodes[key];
    if (!node) { renderChoices([]); return; }
    const g = state.gen;               // pin this interaction; abort if superseded
    state.node = node;
    renderChoices([]);                 // hide chips while bot "types"
    if (node.user) { addOutgoing(node.user); await wait(350); if (stale(g)) return; }
    if (node.bot) await botSay(node.bot);
    if (stale(g)) return;
    renderChoices(node.choices);
  }

  // ---------- free-typed text: NLU + RAG + reco fallback ----------
  async function handleFreeText(text) {
    bump();
    addOutgoing(escapeHtml(text));
    const t = text.toLowerCase();

    // 1) directory intent → member matches
    const need = detectNeed(t);
    const city = detectCity(t);
    if (need) {
      await botSay([
        { t:'text', text:'Searching the verified member directory 👇' },
        { t:'reco', query:{ need: need, city: city || undefined }, n:3 },
        { t:'text', text:'Want a warm intro to any of them? Member-to-member referrals are logged to your JBN chapter.' },
      ]);
    }
    // 2) education loan / JATF numbers
    else if (/(education loan|edu loan|interest|subsidy|jatf|upsc|cet)/.test(t)) {
      await botSay([{ t:'text', text:'Here’s the education-support snapshot:' }, { t:'rate' }]);
    }
    // 3) wings / policy via RAG
    else if (window.RAG.answer(t)) {
      await botSay([{ t:'rag', q: t }]);
    }
    // 4) chapter / office
    else if (/(chapter|office|near|location|address|contact|meet)/.test(t)) {
      await botSay([{ t:'text', text:'Tell me your city — *Mumbai*, *Ahmedabad*, *Pune* or *Hyderabad* — and I’ll share your chapter’s details. Here’s the Apex HQ:' }, { t:'store', city:'Mumbai' }]);
    }
    // 5) greeting / fallback
    else if (/(hi|hello|hey|namaste|namaskar|jai jinendra|jsk|micchami)/.test(t)) {
      await botSay([{ t:'text', text:'Jai Jinendra! 🙏 I’m *Jinal*, the JITO community concierge. I can *find member businesses*, help you *join a chapter*, RSVP *JBN meetings & JITO Connect*, guide *JATF and education-loan* applications, or take a *startup pitch to JAN*. What would you like?' }]);
    }
    else {
      await botSay([{ t:'text', text:'Happy to help! 🙏 I’m best at member-directory search, membership, JBN meetings, JITO Connect, JATF/education support, matrimony and JAN startup pitches. Try “need a CA in Pune”, or pick a scenario from the menu on the left. Your chapter desk is always one tap away.' }]);
    }
    // restore the current node's choices if any
    renderChoices(state.node && state.node.choices);
  }

  function parseBudget(t) {
    let m = t.match(/(\d+(?:\.\d+)?)\s*(crore|crores|cr)\b/);
    if (m) return Math.round(parseFloat(m[1]) * 10000000);
    m = t.match(/(\d+(?:\.\d+)?)\s*(lakh|lakhs|lac|l\b)/);
    if (m) return Math.round(parseFloat(m[1]) * 100000);
    m = t.match(/₹?\s?(\d{6,9})/);
    if (m) return parseInt(m[1], 10);
    return null;
  }
  function detectNeed(t) {
    const map = { ' ca ':'ca', 'chartered':'ca', 'accountant':'ca', 'tax':'ca', 'audit':'ca',
      'textile':'textile', 'fabric':'textile', 'pharma':'pharma', 'medicine':'pharma',
      'diamond':'diamond', 'jewel':'diamond', 'software':'it', ' it ':'it', 'erp':'it', 'app develop':'it',
      'real estate':'realestate', 'property':'realestate', 'builder':'realestate', 'construction':'realestate',
      'food':'food', 'fmcg':'food', 'snack':'food', 'logistic':'logistics', 'transport':'logistics', 'warehouse':'logistics',
      'coaching':'education', 'tuition':'education', 'startup':'startup', 'agritech':'startup',
      'event':'events', 'exhibition':'events', 'stall fabric':'events' };
    const padded = ' ' + t + ' ';
    for (const k in map) if (padded.includes(k)) return map[k];
    return null;
  }
  function detectCity(t) {
    if (/mumbai|bombay/.test(t)) return 'Mumbai';
    if (/ahmedabad|gujarat/.test(t)) return 'Ahmedabad';
    if (/pune/.test(t)) return 'Pune';
    if (/hyderabad/.test(t)) return 'Hyderabad';
    if (/surat/.test(t)) return 'Surat';
    return null;
  }

  // ---------- formatting helpers ----------
  function fmt(s) { return escapeHtml(s).replace(/\*(.+?)\*/g, '<b>$1</b>').replace(/\n/g, '<br>'); }
  function escapeHtml(s) { return (s || '').replace(/[&<>"]/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c])); }
  function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  // ---------- UI plumbing ----------
  function clearThread() { thread().innerHTML = ''; }
  function setControls(on) { $('#msg').disabled = !on; $('#send').disabled = !on; }
  function setHeaderStatus(s) { const e = $('#hstatus'); if (e && !e.dataset.locked) e.textContent = s; }
  function setHeaderSub(s) { const e = $('#hstatus'); if (e) { e.textContent = s; } }
  function highlightLauncher(key) {
    document.querySelectorAll('.scn').forEach(b => b.classList.toggle('active', b.dataset.key === key));
  }

  function buildLauncher() {
    const list = $('#scnlist');
    window.SCENARIO_ORDER.forEach(key => {
      const sc = window.SCENARIOS[key];
      const b = el('button', 'scn', `<span class="scn-emo">${sc.emoji}</span><span class="scn-tx"><b>${sc.title}</b><i>${sc.blurb}</i></span>`);
      b.dataset.key = key;
      b.addEventListener('click', () => startScenario(key));
      list.appendChild(b);
    });
  }

  // ---------- init ----------
  document.addEventListener('DOMContentLoaded', () => {
    buildLauncher();

    $('#send').addEventListener('click', send);
    $('#msg').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } });
    async function send() {
      const v = $('#msg').value.trim(); if (!v || state.busy) return;
      $('#msg').value = ''; $('#chips').innerHTML = '';
      await handleFreeText(v);
    }

    $('#reset').addEventListener('click', () => location.reload());
    $('#langsel').addEventListener('change', e => {
      const map = { en:'I’ll chat in English 🇬🇧', hi:'अब मैं हिंदी में बात करूँगी 🙏', mr:'आता मी मराठीत बोलेन 🙏', gu:'હવે હું ગુજરાતીમાં વાત કરીશ 🙏' };
      botSay([{ t:'text', text: map[e.target.value] }]);
    });

    // Opening welcome (guard the trailing chips so a mid-welcome scenario click can't clobber them)
    const welcomeGen = state.gen;
    botSay([
      { t:'text', text:'Jai Jinendra! 🙏 I’m *Jinal*, the AI community concierge for *JITO — Jain International Trade Organisation*. I’m an AI assistant — and your chapter desk is always one tap away.' },
      { t:'text', text:'Pick a demo scenario from the left, tap a quick reply, or just *type* what you need — e.g. “need a CA in Pune” or “how do I join JITO”. 🤝' },
    ]).then(() => {
      if (stale(welcomeGen)) return;     // user already launched a scenario — don't override its chips
      renderChoices([
        { label:'🔎 Find a member business', goto:'__directory' },
        { label:'📝 Become a member', goto:'__membership' },
        { label:'🎪 JITO Connect expo', goto:'__connect' },
      ]);
    });

    // map welcome chips to scenarios
    document.addEventListener('click', e => {
      const chip = e.target.closest('.chip'); if (!chip) return;
    });
  });

  // Allow welcome chips (goto starting with __) to launch a scenario
  const _goto = gotoNode;
  gotoNode = async function (key) {
    if (typeof key === 'string' && key.startsWith('__')) return startScenario(key.slice(2));
    return _goto(key);
  };

  window.JitoDemo = { startScenario, state };
})();
