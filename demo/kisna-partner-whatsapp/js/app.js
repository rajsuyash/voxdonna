/*
 * Kisna Partner Desk — B2B WhatsApp agent demo controller.
 * Pure front-end, no network calls. Plays the node-graphs in scenarios.js, renders
 * WhatsApp-style messages, and handles free-typed text with a small intent parser
 * plus the catalogue and RAG engines.
 */
(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const el = (tag, cls, html) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    return e;
  };
  const inr = n => '₹' + Number(n).toLocaleString('en-IN');
  const now = () => {
    const d = new Date();
    return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
  };
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const state = { scenario: null, node: null, busy: false, gen: 0, orderSeq: 0 };
  const bump = () => ++state.gen;           // invalidates any in-flight playback
  const stale = g => state.gen !== g;

  const thread = () => $('#thread');
  // Cards with aspect-ratio SVGs grow after insertion, so re-pin on the next frame
  // or the last message sits half-cut under the chip bar.
  const scrollDown = () => {
    const t = thread();
    t.scrollTop = t.scrollHeight;
    requestAnimationFrame(() => { t.scrollTop = t.scrollHeight; });
  };

  // ---------- bubble primitives ----------
  function addOutgoing(html) {
    const row = el('div', 'row out');
    row.appendChild(el('div', 'bubble b-out', `${html}<span class="meta">${now()} <span class="ticks">✓✓</span></span>`));
    thread().appendChild(row);
    scrollDown();
  }
  function addIncoming(node) {
    const row = el('div', 'row in');
    const b = el('div', 'bubble b-in');
    b.appendChild(node);
    b.appendChild(el('span', 'meta', now()));
    row.appendChild(b);
    thread().appendChild(row);
    scrollDown();
    return b;
  }
  function addSystem(text) {
    const row = el('div', 'row sys');
    row.appendChild(el('div', 'syschip', escapeHtml(text)));
    thread().appendChild(row);
    scrollDown();
  }
  function addHermes(text) {
    const row = el('div', 'row sys');
    row.appendChild(el('div', 'hermeschip', `<b>Hermes</b><span>${escapeHtml(text)}</span>`));
    thread().appendChild(row);
    scrollDown();
  }
  function typing(on) {
    const existing = $('#typing');
    if (on) {
      setStatus('typing…');
      if (existing) return;
      const row = el('div', 'row in');
      row.id = 'typing';
      row.appendChild(el('div', 'bubble b-in typing', '<span></span><span></span><span></span>'));
      thread().appendChild(row);
      scrollDown();
    } else {
      setStatus('online');
      if (existing) existing.remove();
    }
  }
  const wait = ms => new Promise(r => setTimeout(r, reducedMotion ? Math.min(ms, 120) : ms));

  // ---------- SKU cards ----------
  function skuCard(sku, why) {
    const marginPct = Math.round(window.CatalogEngine.margin(sku) * 100);
    const c = el('div', 'skucard');
    c.innerHTML = `
      <div class="sk-img">${window.kisnaSVG(sku.icon)}<span class="sk-code">${escapeHtml(sku.code)}</span>${sku.fast ? '<span class="sk-fast">Fast mover</span>' : ''}</div>
      <div class="sk-body">
        <div class="sk-title">${escapeHtml(sku.name)}</div>
        <div class="sk-spec">${escapeHtml(sku.purity)} · ${escapeHtml(sku.dia)} · ${escapeHtml(sku.gross)}</div>
        ${why ? `<div class="sk-why">${escapeHtml(why)}</div>` : ''}
        <div class="sk-price"><span>Wholesale</span><b>${inr(sku.wsp)}</b></div>
        <div class="sk-price muted"><span>MRP</span><b>${inr(sku.mrp)}</b></div>
        <div class="sk-tags"><span>${marginPct}% margin</span><span>MOQ ${sku.moq}</span><span>${sku.stock === 'ready' ? 'Ready' : 'MTO'} · ${sku.lead}d</span></div>
        <div class="sk-acts">
          <button class="sk-btn" data-act="add" data-code="${sku.code}">Add ${sku.moq} to order</button>
          <button class="sk-btn ghost" data-act="spec" data-code="${sku.code}">Details</button>
        </div>
      </div>`;
    c.querySelectorAll('.sk-btn').forEach(btn => btn.addEventListener('click', () => {
      if (state.busy) return;
      const s = window.SKU_BY_CODE[btn.dataset.code];
      if (btn.dataset.act === 'add') {
        bump();
        addOutgoing(`Add ${s.moq} × ${escapeHtml(s.name)}`);
        botSay([
          { t:'text', text:`Added. ${s.moq} × *${s.name}* at ${inr(s.wsp)} a piece.` },
          { t:'cart', lines:[{ code:s.code, qty:s.moq }], note:'Working basket' },
          { t:'text', text:'Add more lines, or say *confirm* and I’ll raise it against your account.' },
        ]);
      } else {
        bump();
        addOutgoing(`Details on ${escapeHtml(s.code)}`);
        botSay([
          { t:'text', text:`*${s.name}* (${s.code})\n${s.desc}` },
          { t:'text', text:`${s.purity} · ${s.dia} · ${s.gross} gross\nWholesale ${inr(s.wsp)} · MRP ${inr(s.mrp)} · ${Math.round(window.CatalogEngine.margin(s) * 100)}% margin\nMOQ ${s.moq} · ${s.stock === 'ready' ? 'ready stock' : 'made to order'}, ${s.lead} working days` },
        ]);
      }
    }));
    return c;
  }

  function skuCarousel(items) {
    const wrap = el('div', 'carousel');
    items.forEach(item => {
      if (typeof item === 'string') wrap.appendChild(skuCard(window.SKU_BY_CODE[item]));
      else wrap.appendChild(skuCard(item.p, item.why));
    });
    return wrap;
  }

  // ---------- rich renderers ----------
  const RENDER = {
    text(spec) { addIncoming(el('div', '', fmt(spec.text))); },

    reco(spec) { addIncoming(skuCarousel(window.CatalogEngine.recommend(spec.query, spec.n || 3))); },

    skus(spec) {
      if (spec.note) addIncoming(el('div', '', fmt(spec.note)));
      addIncoming(skuCarousel(spec.codes));
    },

    rate() {
      const r = window.KISNA_RATE;
      addIncoming(el('div', 'ratecard', `
        <div class="rc-h">Today’s trade rate<span class="rc-tag">ex-GST</span></div>
        <div class="rc-row"><span>22K gold</span><b>${inr(r.gold22)}/g</b></div>
        <div class="rc-row"><span>18K gold</span><b>${inr(r.gold18)}/g</b></div>
        <div class="rc-row"><span>14K gold</span><b>${inr(r.gold14)}/g</b></div>
        <div class="rc-row"><span>Diamond index</span><b>${escapeHtml(r.diamondIndex)}</b></div>
        <div class="rc-row"><span>Making</span><b>${escapeHtml(r.making)}</b></div>
        <div class="rc-foot">As of ${escapeHtml(r.asOf)} · indicative demo rate</div>`));
    },

    cart(spec) {
      const order = window.CatalogEngine.buildOrder(spec.lines);
      const st = window.CatalogEngine.sellThrough(order);
      const rows = order.rows.map(r => `
        <div class="ct-row">
          <span>${escapeHtml(r.sku.name)}<i>${escapeHtml(r.sku.code)} · ${r.qty} pcs × ${inr(r.sku.wsp)}</i></span>
          <b>${inr(r.amount)}</b>
        </div>`).join('');
      addIncoming(el('div', 'cartcard' + (spec.confirmed ? ' done' : ''), `
        <div class="ct-h">${spec.confirmed ? '✅ ' : ''}${escapeHtml(spec.note || 'Order summary')}<span>${order.pcs} pcs</span></div>
        ${rows}
        <div class="ct-tot"><span>Subtotal</span><b>${inr(order.subtotal)}</b></div>
        <div class="ct-tot"><span>GST @ 3%</span><b>${inr(order.gst)}</b></div>
        <div class="ct-tot grand"><span>Payable</span><b>${inr(order.total)}</b></div>
        <div class="ct-sell">At full sell-through: <b>${inr(st.retail)}</b> retail · <b>${inr(st.profit)}</b> counter profit (${st.pct}%)</div>`));
    },

    orderlist() {
      const rows = window.ORDERS.map(o => `
        <div class="ol-row">
          <div class="ol-id">${escapeHtml(o.id)}<i>${o.pcs} pcs · ${escapeHtml(o.items)}</i></div>
          <div class="ol-right">
            <span class="ol-stage${o.flag ? ' flag' : ''}">${escapeHtml(o.flag || window.ORDER_STAGES[o.stage])}</span>
            <i>${inr(o.value)}</i>
          </div>
        </div>`).join('');
      addIncoming(el('div', 'orderlist', `<div class="ol-h">📦 Open orders</div>${rows}`));
    },

    orderpipe(spec) {
      const o = window.ORDER_BY_ID[spec.id];
      const steps = window.ORDER_STAGES.map((label, i) => {
        const cls = i < o.stage ? 'done' : i === o.stage ? 'current' : '';
        return `<div class="pp-step ${cls}"><span class="pp-dot"></span><span class="pp-lb">${escapeHtml(label)}</span></div>`;
      }).join('');
      addIncoming(el('div', 'pipecard', `
        <div class="pp-h">${escapeHtml(o.id)}<span>${o.pcs} pcs · ${inr(o.value)}</span></div>
        <div class="pp-item">${escapeHtml(o.items)}</div>
        <div class="pp-rail">${steps}</div>
        ${o.awb ? `<div class="pp-awb">AWB <b>${escapeHtml(o.awb)}</b><i>${escapeHtml(o.courier)}</i></div>` : ''}
        <div class="pp-eta">${o.flag ? `<span class="pp-flag">${escapeHtml(o.flag)}</span>` : ''}ETA <b>${escapeHtml(o.eta)}</b></div>
        ${o.note ? `<div class="pp-note">${escapeHtml(o.note)}</div>` : ''}`));
    },

    ledger() {
      const p = window.PARTNER;
      const usedPct = Math.round((p.outstanding / p.creditLimit) * 100);
      const rows = p.ageing.map(a => `
        <div class="lg-row ${a.state}"><span>${escapeHtml(a.bucket)}</span><b>${inr(a.amount)}</b></div>`).join('');
      addIncoming(el('div', 'ledgercard', `
        <div class="lg-h">${escapeHtml(p.firm)}<span>${escapeHtml(p.code)}</span></div>
        <div class="lg-big">${inr(p.outstanding)}<i>outstanding of ${inr(p.creditLimit)} limit</i></div>
        <div class="lg-bar"><span style="width:${usedPct}%"></span></div>
        <div class="lg-free">${inr(p.available)} available · ${p.creditDays}-day terms</div>
        ${rows}
        <div class="lg-foot">DSO ${p.dso} days · risk band <b>${escapeHtml(p.riskBand)} (${p.riskScore})</b></div>`));
    },

    invoices() {
      const rows = window.INVOICES.map(v => `
        <div class="iv-row">
          <span>${escapeHtml(v.no)}<i>raised ${escapeHtml(v.date)} · due ${escapeHtml(v.due)}</i></span>
          <b>${inr(v.amount)}</b>
          <em class="${v.status === 'current' ? '' : 'warn'}">${escapeHtml(v.status)}</em>
        </div>`).join('');
      addIncoming(el('div', 'invcard', `<div class="iv-h">🧾 Open invoices</div>${rows}`));
    },

    payment(spec) {
      addIncoming(el('div', 'paycard', `
        <div class="py-h">Payment request</div>
        <div class="py-amt">${inr(spec.amount)}</div>
        <div class="py-ref">Against ${escapeHtml(spec.invoice)}</div>
        <div class="py-modes"><span>UPI</span><span>NEFT / RTGS</span><span>Card</span></div>
        <button class="py-cta" type="button" disabled>Pay securely →</button>
        <div class="py-note">kisna@demoupi · link expires in 48 hrs</div>`));
    },

    docs(spec) {
      const rows = spec.files.map(f => `
        <div class="dc-row">
          <span class="dc-ico">📄</span>
          <span class="dc-tx">${escapeHtml(f.name)}<i>${escapeHtml(f.kind)} · ${escapeHtml(f.size)}</i></span>
        </div>`).join('');
      addIncoming(el('div', 'doccard', rows));
    },

    scheme(spec) {
      const s = window.SCHEMES.find(x => x.id === spec.id);
      addIncoming(el('div', 'schemecard', `
        <div class="sc-banner">🪔</div>
        <div class="sc-title">${escapeHtml(s.title)}</div>
        <div class="sc-seg">${escapeHtml(s.segment)}</div>
        <div class="sc-body">${escapeHtml(s.body)}</div>`));
    },

    schemeterms(spec) {
      const s = window.SCHEMES.find(x => x.id === spec.id);
      addIncoming(el('div', 'termscard', `
        <div class="tm-h">${escapeHtml(s.title)} · terms</div>
        ${s.terms.map(t => `<div class="tm-row">• ${escapeHtml(t)}</div>`).join('')}`));
    },

    drop(spec) {
      const d = window.DESIGN_DROPS.find(x => x.id === spec.id);
      addIncoming(el('div', 'dropcard', `
        <div class="dp-strip">${d.hero.map(c => window.kisnaSVG(window.SKU_BY_CODE[c].icon)).join('')}</div>
        <div class="dp-title">${escapeHtml(d.title)}</div>
        <div class="dp-meta">${d.pieces} new designs</div>
        <div class="dp-body">${escapeHtml(d.body)}</div>`));
    },

    ticket(spec) {
      const d = spec.data;
      addIncoming(el('div', 'ticketcard', `
        <div class="tk-h">🎫 ${escapeHtml(d.id)}<span>${escapeHtml(d.sla)}</span></div>
        <div class="tk-type">${escapeHtml(d.type)}</div>
        <div class="tk-route">Routed to ${escapeHtml(d.route)}</div>
        <div class="tk-note">${escapeHtml(d.note)}</div>`));
    },

    kyc() {
      const a = window.KYC_APPLICANT;
      const rows = a.steps.map(s => `
        <div class="ky-row ${s.done ? 'done' : 'pending'}">
          <span class="ky-tick">${s.done ? '✓' : '○'}</span>
          <span class="ky-tx">${escapeHtml(s.label)}<i>${escapeHtml(s.detail)}</i></span>
        </div>`).join('');
      const done = a.steps.filter(s => s.done).length;
      addIncoming(el('div', 'kyccard', `
        <div class="ky-h">${escapeHtml(a.firm)}<span>${done} of ${a.steps.length}</span></div>
        ${rows}`));
    },

    terms() {
      const t = window.KYC_APPLICANT.proposedTerms;
      addIncoming(el('div', 'proposecard', `
        <div class="pr-h">Proposed opening terms</div>
        <div class="pr-big">${inr(t.limit)}<i>credit limit</i></div>
        <div class="pr-row"><span>Terms</span><b>${t.days} days</b></div>
        <div class="pr-row"><span>Security</span><b>${escapeHtml(t.security)}</b></div>
        <div class="pr-row"><span>Review</span><b>${escapeHtml(t.review)}</b></div>
        <div class="pr-foot">Subject to sign-off by the credit manager.</div>`));
    },

    intent(spec) {
      const d = spec.data;
      addIncoming(el('div', 'intentcard', `
        <div class="in-h">Captured${spec.score ? `<span class="in-score">${escapeHtml(spec.score)}</span>` : ''}</div>
        ${Object.entries(d).map(([k, v]) => `<div class="in-row"><span>${escapeHtml(cap(k))}</span><b>${escapeHtml(v)}</b></div>`).join('')}`));
    },

    rag(spec) {
      const a = window.RAG.answer(spec.q);
      if (!a) { RENDER.text({ text: 'Let me put that in front of your account manager rather than guess at it.' }); return; }
      addIncoming(el('div', '', `${fmt(a.text)}<div class="cite">📄 ${escapeHtml(a.cites)}</div>`));
    },

    voiceIn(spec) { renderVoice(spec, 'out'); },
    voiceOut(spec) { renderVoice(spec, 'in'); },
    hermes(spec) { addHermes(spec.text); },
    system(spec) { addSystem(spec.text); },
  };

  function renderVoice(spec, side) {
    const isIn = side === 'in';
    const row = el('div', 'row ' + (isIn ? 'in' : 'out'));
    const b = el('div', 'bubble ' + (isIn ? 'b-in' : 'b-out') + ' voice');
    b.innerHTML = `
      <div class="vc">
        <button class="vc-play" type="button" aria-label="Play voice note">▶</button>
        <div class="vc-wave">${'<i></i>'.repeat(22)}</div>
        <span class="vc-dur">${escapeHtml(spec.dur)}</span>
        <span class="vc-lang">${escapeHtml(spec.lang)}</span>
      </div>
      <div class="vc-tx"><b>${isIn ? 'Riya' : 'Heard'} (${escapeHtml(spec.lang)}):</b> ${escapeHtml(spec.text)}<br><i>“${escapeHtml(spec.gloss)}”</i></div>
      <span class="meta">${now()}${isIn ? '' : ' <span class="ticks">✓✓</span>'}</span>`;
    const btn = b.querySelector('.vc-play');
    btn.addEventListener('click', () => {
      const playing = btn.textContent === '▶';
      btn.textContent = playing ? '❚❚' : '▶';
      b.querySelector('.vc-wave').classList.toggle('playing', playing);
    });
    row.appendChild(b);
    thread().appendChild(row);
    scrollDown();
  }

  // ---------- playback ----------
  async function botSay(specs) {
    const g = state.gen;
    state.busy = true;
    setControls(false);
    for (const spec of specs) {
      typing(true);
      const base = spec.t === 'text' ? 480 + Math.min((spec.text || '').length * 10, 1300) : 620;
      await wait(base);
      if (stale(g)) { typing(false); return; }
      typing(false);
      (RENDER[spec.t] || RENDER.text)(spec);
      await wait(160);
      if (stale(g)) return;
    }
    state.busy = false;
    setControls(true);
  }

  // ---------- quick replies ----------
  function renderChoices(choices) {
    const bar = $('#chips');
    bar.innerHTML = '';
    if (!choices || !choices.length) { bar.classList.add('empty'); scrollDown(); return; }
    bar.classList.remove('empty');
    choices.forEach(c => {
      const chip = el('button', 'chip', escapeHtml(c.label));
      chip.type = 'button';
      chip.addEventListener('click', async () => {
        if (state.busy) return;
        bump();
        bar.innerHTML = '';
        // The target node usually carries a fuller version of what the chip says.
        // Echo one or the other, never both.
        if (!targetUserLine(c.goto)) addOutgoing(escapeHtml(c.label));
        await gotoNode(c.goto);
      });
      bar.appendChild(chip);
    });
    scrollDown();   // the chip bar takes height off the thread, so re-pin to the bottom
  }

  // The inbound line the given chip target will render itself, if any.
  function targetUserLine(goto) {
    if (typeof goto !== 'string') return null;
    if (goto.startsWith('__')) {
      const sc = window.SCENARIOS[goto.slice(2)];
      return sc && sc.nodes[sc.entry] && sc.nodes[sc.entry].user;
    }
    const node = state.scenario && state.scenario.nodes[goto];
    return node && node.user;
  }

  // ---------- node engine ----------
  async function startScenario(key) {
    bump();
    state.busy = false;
    setControls(true);
    const sc = window.SCENARIOS[key];
    if (!sc) return;
    state.scenario = sc;
    state.node = null;
    thread().innerHTML = '';
    setStatus(sc.persona ? `Demo · ${sc.persona}` : 'online');
    document.querySelectorAll('.scn').forEach(b => {
      const on = b.dataset.key === key;
      b.classList.toggle('active', on);
      if (on) b.scrollIntoView({ block: 'nearest' });   // the rail scrolls; keep the running one visible
    });
    await gotoNode(sc.entry);
  }

  async function gotoNode(key) {
    if (typeof key === 'string' && key.startsWith('__')) return startScenario(key.slice(2));
    if (!key || key === 'END') { renderChoices([]); return; }
    const node = state.scenario && state.scenario.nodes[key];
    if (!node) { renderChoices([]); return; }
    const g = state.gen;
    state.node = node;
    renderChoices([]);
    if (node.user) { addOutgoing(escapeHtml(node.user)); await wait(320); if (stale(g)) return; }
    if (node.bot) await botSay(node.bot);
    if (stale(g)) return;
    renderChoices(node.choices);
  }

  // ---------- free-typed text: intent parsing + RAG ----------
  async function handleFreeText(text) {
    bump();
    addOutgoing(escapeHtml(text));
    const t = text.toLowerCase();
    const orderId = (text.match(/KO-?\s?(\d{5})/i) || [])[1];

    if (orderId && window.ORDER_BY_ID['KO-' + orderId]) {
      await botSay([{ t:'orderpipe', id:'KO-' + orderId }]);
    } else if (/(outstanding|balance|ledger|owe|due|statement|credit limit|limit)/.test(t)) {
      await botSay([
        { t:'text', text:'Here’s your account as it stands:' },
        { t:'ledger' },
        { t:'text', text:'Want the invoice copies, or a payment link?' },
      ]);
    } else if (/(invoice|bill|copy|receipt)/.test(t)) {
      await botSay([{ t:'text', text:'Your open invoices:' }, { t:'invoices' }]);
    } else if (/(pay|payment link|upi|neft|settle)/.test(t)) {
      await botSay([
        { t:'text', text:'Payment link for the invoice falling due first:' },
        { t:'payment', amount:210000, invoice:'KIS/26-27/3268' },
      ]);
    } else if (/(status|track|dispatch|awb|order|shipment|delivery)/.test(t)) {
      await botSay([{ t:'text', text:'Your open orders:' }, { t:'orderlist' }]);
    } else if (/(rate|gold rate|making charge|bhav)/.test(t)) {
      await botSay([{ t:'text', text:'Today’s trade rate:' }, { t:'rate' }]);
    } else if (parseIntent(t)) {
      const q = parseIntent(t);
      await botSay([
        { t:'text', text:'Pulling what fits that:' },
        { t:'reco', query:q, n:3 },
        { t:'text', text:'Say *add* on any card, or tell me the quantities and I’ll build the order.' },
      ]);
    } else if (window.RAG.answer(t)) {
      await botSay([{ t:'rag', q:t }]);
    } else if (/^(hi|hello|hey|namaste|namaskar|jai|good morning|good evening)/.test(t)) {
      await botSay([{ t:'text', text:'Hello 🙏 Riya here from the *Kisna Partner Desk*. I can show you the *catalogue*, *track an order*, pull your *ledger or invoices*, raise a *payment link*, log a *shortage or rework*, or take you through *onboarding*. What do you need?' }]);
    } else {
      await botSay([{ t:'text', text:'I can help with the catalogue and ordering, order status and dispatch, your ledger and invoices, payments, schemes and new design drops, service and disputes, or partner onboarding. Try *“mangalsutra under 50,000”* or *“status of KO-24902”* — or pick a scenario from the list on the left. A person is always one message away.' }]);
    }
    renderChoices(state.node && state.node.choices);
  }

  // Maps a free-typed trade query onto a catalogue intent. Returns null if nothing matched.
  function parseIntent(t) {
    const q = {};
    const cat = detectCategory(t);
    if (cat) q.category = cat;
    const ticket = parseTicket(t);
    if (ticket) q.ticket = ticket;
    if (/14\s?k/.test(t)) q.purity = '14K';
    if (/18\s?k/.test(t)) q.purity = '18K';
    if (/(ready|in stock|immediate|urgent)/.test(t)) q.ready = true;
    const tags = ['bridal', 'wedding', 'festive', 'gifting', 'everyday', 'men', 'kids', 'premium', 'fast-moving']
      .filter(tag => t.includes(tag.replace('-', ' ')) || t.includes(tag));
    if (/fast|moving|best sell|bestsell/.test(t)) tags.push('fast-moving');
    if (tags.length) q.tags = tags;
    return Object.keys(q).length ? q : null;
  }

  function parseTicket(t) {
    let m = t.match(/(\d+(?:\.\d+)?)\s*(lakh|lakhs|lac|l\b)/);
    if (m) return Math.round(parseFloat(m[1]) * 100000);
    m = t.match(/(\d+(?:\.\d+)?)\s*(k\b|thousand)/);
    if (m) return Math.round(parseFloat(m[1]) * 1000);
    m = t.match(/₹?\s?(\d{4,7})/);
    if (m) return parseInt(m[1], 10);
    return null;
  }

  function detectCategory(t) {
    if (/(mangalsutra|mangal sutra)/.test(t)) return 'mangalsutra';
    if (/(nose ?pin|nath)/.test(t)) return 'nosepin';
    if (/(bangle|kada)/.test(t)) return 'bangle';
    if (/(bracelet|tennis)/.test(t)) return 'bracelet';
    if (/(pendant set|set)/.test(t)) return 'pendantset';
    if (/(pendant|locket)/.test(t)) return 'pendant';
    if (/(earring|stud|jhumka|drop|tops)/.test(t)) return 'earring';
    if (/(men'?s|gents|signet)/.test(t)) return 'mensring';
    if (/(kid|baby|child)/.test(t)) return 'kids';
    if (/(ring|band)/.test(t)) return 'ring';
    return null;
  }

  // ---------- formatting ----------
  function fmt(s) { return escapeHtml(s).replace(/\*(.+?)\*/g, '<b>$1</b>').replace(/\n/g, '<br>'); }
  function escapeHtml(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;' }[c])); }
  function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  // ---------- UI plumbing ----------
  function setControls(on) { $('#msg').disabled = !on; $('#send').disabled = !on; }
  function setStatus(s) { const e = $('#hstatus'); if (e) e.textContent = s; }

  function buildLauncher() {
    const list = $('#scnlist');
    window.SCENARIO_ORDER.forEach(key => {
      const sc = window.SCENARIOS[key];
      const b = el('button', 'scn', `<span class="scn-emo" aria-hidden="true">${sc.emoji}</span><span class="scn-tx"><b>${escapeHtml(sc.title)}</b><i>${escapeHtml(sc.blurb)}</i></span>`);
      b.type = 'button';
      b.dataset.key = key;
      b.addEventListener('click', () => startScenario(key));
      list.appendChild(b);
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    buildLauncher();

    const send = async () => {
      const v = $('#msg').value.trim();
      if (!v || state.busy) return;
      $('#msg').value = '';
      $('#chips').innerHTML = '';
      await handleFreeText(v);
    };
    $('#send').addEventListener('click', send);
    $('#msg').addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
    });
    $('#reset').addEventListener('click', () => location.reload());
    window.addEventListener('resize', scrollDown);
    $('#langsel').addEventListener('change', e => {
      const map = {
        en: 'Switching to English.',
        hi: 'ठीक है, अब हिंदी में बात करते हैं 🙏',
        gu: 'સારું, હવે ગુજરાતીમાં વાત કરીએ 🙏',
        mr: 'ठीक आहे, आता मराठीत बोलूया 🙏',
        ta: 'சரி, இனி தமிழில் பேசலாம் 🙏',
        bn: 'ঠিক আছে, এখন বাংলায় কথা বলি 🙏',
      };
      bump();
      botSay([{ t:'text', text: map[e.target.value] }]);
    });

    const welcomeGen = state.gen;
    botSay([
      { t:'text', text:'🙏 Welcome to the *Kisna Partner Desk*. I’m *Riya* — the AI on this number for our retail partners.' },
      { t:'text', text:'I can pull the *catalogue*, place and *track orders*, show your *ledger and invoices*, raise a *payment link*, log a *shortage or rework*, or take a new partner through *onboarding*. Pick a scenario on the left, or just type.' },
    ]).then(() => {
      if (stale(welcomeGen)) return;
      renderChoices([
        { label:'📖 Show me the catalogue', goto:'__catalog' },
        { label:'📦 Where is my order?', goto:'__track' },
        { label:'🧾 My outstanding', goto:'__credit' },
      ]);
    });
  });

  window.KisnaDemo = { startScenario, state };
})();
