/*
 * Naina — Hiranandani WhatsApp AI Property Concierge · interactive demo controller.
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
        <div class="pmeta">${p.config} · ${p.carpet} · ${p.possession}</div>
        ${why ? `<div class="pwhy">✨ ${why}</div>` : ''}
        <div class="pprice">${inr(p.price)}</div>
        <div class="pacts">
          <button class="pbtn" data-act="reserve" data-id="${p.id}">Hold unit</button>
          <button class="pbtn ghost" data-act="visit" data-id="${p.id}">Site visit</button>
        </div>
      </div>`;
    c.querySelectorAll('.pbtn').forEach(btn => btn.addEventListener('click', () => {
      const id = btn.dataset.id, p2 = window.PRODUCT_BY_ID[id];
      addOutgoing(btn.dataset.act === 'reserve' ? `Hold the ${p2.name}` : `Site visit for the ${p2.name}`);
      botSay([
        { t:'text', text: btn.dataset.act === 'reserve'
            ? `Done! ✨ I’ve held the *${p2.name}* (${inr(p2.price)}) for 7 days with a refundable EOI. Your RM will send the payment link.`
            : `Great choice! I’ll set up a show-flat visit for the *${p2.name}* — the Experience Centre is open every day.` },
        btn.dataset.act === 'reserve' ? { t:'appt', kind:'reserve', product:id } : { t:'appt', kind:'visit', store: p2.city, when:'Sat 12 Jul, 11:00 AM' },
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
      const r = window.LOAN_RATES;
      const n = el('div', 'ratecard', `
        <div class="rc-h">🏦 Home Loan & Pricing <span class="rc-tag">APF-approved banks</span></div>
        <div class="rc-row"><span>Home loan from</span><b>${r.homeLoan} · ${r.maxTenure}</b></div>
        <div class="rc-row"><span>Powai (Gardens)</span><b>${inr(r.sqft['Powai'])}/sqft</b></div>
        <div class="rc-row"><span>Thane (Estate)</span><b>${inr(r.sqft['Thane'])}/sqft</b></div>
        <div class="rc-row"><span>Panvel (Fortune City)</span><b>${inr(r.sqft['Panvel'])}/sqft</b></div>
        <div class="rc-foot">As of ${r.asOf} · indicative demo figures</div>`);
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
        title = '✅ Unit held'; body = `${p.name}<br><b>${inr(p.price)}</b> · refundable EOI · 7 days<br>Ref: <b>EOI${(1000+(state.leadCount*7)%9000)}</b>`;
      } else if (spec.kind === 'bridal') {
        title = '🎟️ Priority preview RSVP'; body = `${window.STORE_BY_CITY[spec.store.toLowerCase()].name}<br><b>${spec.when}</b><br>Launch preview · early-bird pricing window`;
      } else {
        title = '📅 Site visit confirmed'; body = `${window.STORE_BY_CITY[spec.store.toLowerCase()].name}<br><b>${spec.when}</b><br>RM assigned · show flat + township tour`;
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
    voiceOut(spec) { renderVoice(spec, 'in'); },   // Naina voice reply (incoming side)
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
      <div class="vc-tx"><b>${isIn ? 'Naina' : 'Heard'} (${spec.lang}):</b> ${spec.text}<br><i>“${spec.gloss}”</i></div>
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

    // 1) buying intent → recommend
    const budget = parseBudget(t);
    const config = detectConfig(t);
    const city = detectCity(t);
    const aud = detectAudience(t);
    if (budget || config || city) {
      await botSay([
        { t:'text', text:'Let me match that against live inventory 👇' },
        { t:'reco', query:{ budget: budget || undefined, config: config || undefined, city: city || undefined, audience: aud || undefined }, n:3 },
        { t:'text', text:'Want a cost sheet for any of these, or shall I book a show-flat visit?' },
      ]);
    }
    // 2) loan / EMI / pricing rates
    else if (/(emi|loan|interest|rate|per sqft|price)/.test(t) && /(emi|loan|rate|sqft|interest|much)/.test(t)) {
      await botSay([{ t:'text', text:'Here are today’s indicative numbers:' }, { t:'rate' }]);
    }
    // 3) policy / paperwork via RAG
    else if (window.RAG.answer(t)) {
      await botSay([{ t:'rag', q: t }]);
    }
    // 4) site visit / lounge
    else if (/(visit|show flat|showflat|sample|lounge|office|near|location|address|directions)/.test(t)) {
      await botSay([{ t:'text', text:'Show flats are open every day at all three townships — tell me *Powai*, *Thane* or *Panvel* and I’ll book a slot. Here’s one:' }, { t:'store', city:'Thane' }]);
    }
    // 5) greeting / fallback
    else if (/(hi|hello|hey|namaste|namaskar)/.test(t)) {
      await botSay([{ t:'text', text:'Hello! 🙏 I’m *Naina*, the Hiranandani property concierge. I can *find your home*, share *cost sheets & payment plans*, work out *EMIs*, *track construction*, or *book a site visit*. What would you like?' }]);
    }
    else {
      await botSay([{ t:'text', text:'Happy to help! 🏡 I’m best at home discovery, payment plans, EMIs, RERA/paperwork questions, construction tracking and site visits. Try “3 BHK in Thane under ₹2.2 crore”, or pick a scenario from the menu on the left. A human relationship manager is always one tap away.' }]);
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
  function detectAudience(t) {
    const map = { 'first home':'first-home', 'first-home':'first-home', invest:'investment', rental:'investment',
      upgrade:'upgrade', bigger:'upgrade', nri:'nri', abroad:'nri', family:'family', retire:'retirement' };
    for (const k in map) if (t.includes(k)) return map[k];
    return null;
  }
  function detectConfig(t) {
    const m = t.match(/([1-4])\s*bhk/);
    if (m) return m[1] + ' BHK';
    if (/villa/.test(t)) return '4 BHK Villa';
    if (/(studio|office)/.test(t)) return 'Studio';
    return null;
  }
  function detectCity(t) {
    if (/powai|mumbai/.test(t)) return 'Mumbai';
    if (/thane|ghodbunder/.test(t)) return 'Thane';
    if (/panvel|navi mumbai|fortune/.test(t)) return 'Panvel';
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
      { t:'text', text:'👋 Welcome! I’m *Naina*, the AI property concierge for the *Hiranandani Group*. I’m an AI assistant — and a human relationship manager is always one tap away.' },
      { t:'text', text:'Pick a demo scenario from the left, tap a quick reply, or just *type* what you’re looking for — e.g. “3 BHK in Thane under ₹2.2 crore”. 🏡' },
    ]).then(() => {
      if (stale(welcomeGen)) return;     // user already launched a scenario — don't override its chips
      renderChoices([
        { label:'🏙️ Find my home', goto:'__discovery' },
        { label:'🏦 EMI & loan help', goto:'__emi' },
        { label:'📅 Book a site visit', goto:'__sitevisit' },
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

  window.NainaDemo = { startScenario, state };
})();
