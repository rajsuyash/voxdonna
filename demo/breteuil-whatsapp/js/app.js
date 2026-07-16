/*
 * Juliette — Concierge immobilier WhatsApp Breteuil · contrôleur de démo interactif.
 * 100 % front-end. Pilote les scénarios scriptés de scenarios.js, rend des messages
 * façon WhatsApp, et gère le texte libre via un petit NLU + les moteurs RAG / recommandation.
 */
(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
  const eur = n => Number(n).toLocaleString('fr-FR') + ' €';
  const now = () => { const d = new Date(); return d.getHours().toString().padStart(2,'0') + 'h' + d.getMinutes().toString().padStart(2,'0'); };

  const state = { scenario: null, node: null, busy: false, profile: null, leadCount: 0, gen: 0 };
  const bump = () => ++state.gen;            // invalide toute lecture en cours
  const stale = g => state.gen !== g;        // vrai si une interaction plus récente a démarré

  const thread = () => $('#thread');
  const scrollDown = () => { const t = thread(); t.scrollTop = t.scrollHeight; };

  // ---------- helpers bulles bas-niveau ----------
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
      setHeaderStatus('en train d\'écrire…');
      if (t) return;
      const row = el('div', 'row in'); row.id = 'typing';
      row.appendChild(el('div', 'bubble b-in typing', '<span></span><span></span><span></span>'));
      thread().appendChild(row); scrollDown();
    } else {
      setHeaderStatus('en ligne');
      if (t) t.remove();
    }
  }
  const wait = ms => new Promise(r => setTimeout(r, ms));

  // ---------- rendu des fiches bien ----------
  function productCard(p, why) {
    const c = el('div', 'pcard');
    c.innerHTML = `
      <div class="pimg">${window.jewelSVG(p.icon)}<span class="brandtag">${p.township}</span></div>
      <div class="pbody">
        <div class="ptitle">${p.name}</div>
        <div class="pmeta">${p.config} · ${p.carpet} · ${p.possession}</div>
        ${why ? `<div class="pwhy">✨ ${why}</div>` : ''}
        <div class="pprice">${eur(p.price)}</div>
        <div class="pacts">
          <button class="pbtn" data-act="reserve" data-id="${p.id}">Réserver</button>
          <button class="pbtn ghost" data-act="visit" data-id="${p.id}">Visite privée</button>
        </div>
      </div>`;
    c.querySelectorAll('.pbtn').forEach(btn => btn.addEventListener('click', () => {
      const id = btn.dataset.id, p2 = window.PRODUCT_BY_ID[id];
      addOutgoing(btn.dataset.act === 'reserve' ? `Réservez le ${p2.name}` : `Visite privée du ${p2.name}`);
      botSay([
        { t:'text', text: btn.dataset.act === 'reserve'
            ? `C'est fait ! ✨ J'ai bloqué le *${p2.name}* (${eur(p2.price)}) pendant 7 jours avec un dépôt de garantie remboursable. Votre conseiller vous envoie l'offre d'achat.`
            : `Excellent choix ! J'organise une visite privée du *${p2.name}* — nos conseillers reçoivent tous les jours.` },
        btn.dataset.act === 'reserve' ? { t:'appt', kind:'reserve', product:id } : { t:'appt', kind:'visit', store: p2.city, when:'Sam. 19 juil., 11h00' },
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

  // ---------- renderers de messages riches ----------
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
        <div class="rc-h">🏦 Financement & prix <span class="rc-tag">banques privées partenaires</span></div>
        <div class="rc-row"><span>Crédit à partir de</span><b>${r.credit} · ${r.maxTenure}</b></div>
        <div class="rc-row"><span>Paris (beaux quartiers)</span><b>${eur(r.m2['Paris'])}/m²</b></div>
        <div class="rc-row"><span>Neuilly-sur-Seine</span><b>${eur(r.m2['Neuilly'])}/m²</b></div>
        <div class="rc-row"><span>Côte d'Azur (Nice)</span><b>${eur(r.m2["Côte d'Azur"])}/m²</b></div>
        <div class="rc-foot">Au ${r.asOf} · chiffres indicatifs (démo)</div>`);
      addIncoming(n);
    },
    alloc(spec) {
      const plan = window.RecoEngine.bridalAllocation(spec.total);
      let rows = plan.map(x => `<div class="al-row"><span>${x.part}</span><b>${eur(x.amount)}</b><i>${x.pct*100}%</i></div>`).join('');
      const n = el('div', 'alloccard', `
        <div class="al-h">🧾 Échéancier VEFA · ${eur(spec.total)}</div>${rows}
        <div class="al-foot">Appels de fonds émis au fil de l'avancement · sécurisés par la Garantie Financière d'Achèvement.</div>`);
      addIncoming(n);
    },
    store(spec) {
      const s = window.STORE_BY_CITY[spec.city.toLowerCase()];
      const n = el('div', 'storecard', `
        <div class="map">📍</div>
        <div class="st-body">
          <div class="st-name">${s.name}</div>
          <div class="st-area">${s.area}</div>
          <div class="st-meta">🕙 ${s.hours} · 🗣️ ${s.langs.slice(0,3).join(', ')}${s.showFlat ? ' · 🏠 Visite possible' : ''}</div>
          <div class="st-acts"><button class="pbtn ghost" disabled>Itinéraire</button></div>
        </div>`);
      addIncoming(n);
    },
    appt(spec) {
      let title, body;
      if (spec.kind === 'reserve') {
        const p = window.PRODUCT_BY_ID[spec.product];
        title = '✅ Bien réservé'; body = `${p.name}<br><b>${eur(p.price)}</b> · dépôt remboursable · 7 jours<br>Réf : <b>RES${(1000+(state.leadCount*7)%9000)}</b>`;
      } else if (spec.kind === 'bridal') {
        title = '🎟️ Inscription avant-première'; body = `${window.STORE_BY_CITY[spec.store.toLowerCase()].name}<br><b>${spec.when}</b><br>Avant-première privée · accès prioritaire`;
      } else {
        title = '📅 Visite confirmée'; body = `${window.STORE_BY_CITY[spec.store.toLowerCase()].name}<br><b>${spec.when}</b><br>Conseiller assigné · visite du bien + quartier`;
      }
      addIncoming(el('div', 'apptcard', `<div class="ap-h">${title}</div><div class="ap-b">${body}</div><div class="ap-cal">＋ Ajouter au calendrier</div>`));
    },
    order(spec) {
      const d = spec.data;
      const ok = /prêt|livré|à jour|aucun/i.test(d.status);
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
        <div class="pf-h">🧠 Mémoire du client</div>
        ${Object.entries(d).map(([k,v]) => `<div class="pf-row"><span>${cap(k)}</span><b>${v}</b></div>`).join('')}`));
    },
    campaign(spec) {
      const d = spec.data;
      addIncoming(el('div', 'campaigncard', `
        <div class="cmp-banner">💎</div>
        <div class="cmp-title">${d.title}</div>
        <div class="cmp-body">${d.body}</div>
        <button class="cmp-cta" disabled>${d.cta}</button>`));
    },
    voiceIn(spec) { renderVoice(spec, 'out'); },   // voix client simulée (côté sortant)
    voiceOut(spec) { renderVoice(spec, 'in'); },   // réponse vocale de Juliette (côté entrant)
    rag(spec) {
      const a = window.RAG.answer(spec.q);
      if (!a) { RENDER.text({ text:'Je vous mets en relation avec un conseiller pour ce point. 👩‍💼' }); return; }
      const n = el('div', '', `${fmt(a.text)}<div class="cite">📄 Source : ${a.cites}</div>`);
      addIncoming(n);
    },
    lead(spec) {
      state.leadCount++;
      const d = spec.data;
      const n = el('div', 'leadcard', `
        <div class="ld-h">🎯 Lead capté ${spec.score ? `<span class="ld-score">${spec.score}</span>`:''}</div>
        ${Object.entries(d).map(([k,v]) => `<div class="ld-row"><span>${cap(k.replace(/_/g,' '))}</span><b>${v}</b></div>`).join('')}`);
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
      <div class="vc-tx"><b>${isIn ? 'Juliette' : 'Reçu'} (${spec.lang}) :</b> ${spec.text}<br><i>« ${spec.gloss} »</i></div>
      ${isIn ? `<span class="meta">${now()}</span>` : `<span class="meta">${now()} <span class="ticks">✓✓</span></span>`}`;
    b.querySelector('.vc-play').addEventListener('click', e => {
      e.target.textContent = e.target.textContent === '▶' ? '❚❚' : '▶';
      b.querySelector('.vc-wave').classList.toggle('playing');
    });
    row.appendChild(b); thread().appendChild(row); scrollDown();
  }

  // ---------- lecture d'une liste de messages avec frappe réaliste ----------
  async function botSay(specs) {
    const g = state.gen;
    state.busy = true; setControls(false);
    for (const spec of specs) {
      typing(true);
      const base = spec.t === 'text' ? 500 + Math.min((spec.text||'').length * 11, 1400) : 650;
      await wait(base);
      if (stale(g)) { typing(false); return; }      // un scénario/interaction plus récent a pris la main
      typing(false);
      (RENDER[spec.t] || RENDER.text)(spec);
      await wait(180);
      if (stale(g)) return;
    }
    state.busy = false; setControls(true);
  }

  // ---------- réponses rapides ----------
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

  // ---------- moteur de nœuds ----------
  async function startScenario(key) {
    bump();                              // annule toute lecture en cours
    state.busy = false; setControls(true);
    const sc = window.SCENARIOS[key];
    state.scenario = sc; state.node = null; state.profile = null;
    clearThread();
    setHeaderSub(sc.persona ? `Démo · ${sc.persona}` : 'en ligne');
    highlightLauncher(key);
    await gotoNode(sc.entry);
  }

  async function gotoNode(key) {
    if (key === 'END' || !key) { renderChoices([]); return; }
    const node = state.scenario.nodes[key];
    if (!node) { renderChoices([]); return; }
    const g = state.gen;               // épingle cette interaction ; abandonne si supplantée
    state.node = node;
    renderChoices([]);                 // masque les puces pendant que le bot "écrit"
    if (node.user) { addOutgoing(node.user); await wait(350); if (stale(g)) return; }
    if (node.bot) await botSay(node.bot);
    if (stale(g)) return;
    renderChoices(node.choices);
  }

  // ---------- texte libre : NLU + RAG + repli reco ----------
  async function handleFreeText(text) {
    bump();
    addOutgoing(escapeHtml(text));
    const t = text.toLowerCase();

    // 1) intention d'achat → recommander
    const budget = parseBudget(t);
    const config = detectConfig(t);
    const city = detectCity(t);
    const aud = detectAudience(t);
    if (budget || config || city) {
      await botSay([
        { t:'text', text:'Je confronte cela à nos biens disponibles 👇' },
        { t:'reco', query:{ budget: budget || undefined, config: config || undefined, city: city || undefined, audience: aud || undefined }, n:3 },
        { t:'text', text:'Vous souhaitez le dossier de l\'un d\'eux, ou je vous organise une visite privée ?' },
      ]);
    }
    // 2) financement / mensualité / prix
    else if (/(mensualit|crédit|credit|prêt|pret|financement|emprunt|taux|m2|m²|prix au)/.test(t)) {
      await botSay([{ t:'text', text:'Voici les repères indicatifs du moment :' }, { t:'rate' }]);
    }
    // 3) frais / fiscalité / paperasse via RAG
    else if (window.RAG.answer(t)) {
      await botSay([{ t:'rag', q: t }]);
    }
    // 4) visite / agence
    else if (/(visite|visiter|rendez-vous|rdv|agence|bureau|proche|adresse|itinéraire|itineraire)/.test(t)) {
      await botSay([{ t:'text', text:'Nos conseillers reçoivent tous les jours à *Paris*, *Neuilly* et *Nice* — dites-moi le quartier et je réserve un créneau. En voici un :' }, { t:'store', city:'Paris' }]);
    }
    // 5) salutation / repli
    else if (/(bonjour|bonsoir|salut|coucou|hello|hey)/.test(t)) {
      await botSay([{ t:'text', text:'Bonjour ! 🙏 Je suis *Juliette*, la concierge immobilière Breteuil. Je peux *trouver votre bien*, envoyer *dossiers & fiscalité*, calculer un *financement*, *suivre un chantier* ou *organiser une visite privée*. Que puis-je pour vous ?' }]);
    }
    else {
      await botSay([{ t:'text', text:'Avec plaisir ! 🏡 Je suis à l\'aise sur la recherche de biens, l\'échéancier VEFA, le financement, les frais de notaire & la fiscalité, le suivi de chantier et les visites. Essayez « 4 pièces à Passy, 1,6 M€ », ou choisissez un scénario dans le menu à gauche. Un conseiller reste à un message.' }]);
    }
    // restaure les puces du nœud courant s'il y en a
    renderChoices(state.node && state.node.choices);
  }

  function parseBudget(t) {
    let m = t.match(/(\d+(?:[.,]\d+)?)\s*(millions?|m€|m\b)/);
    if (m) return Math.round(parseFloat(m[1].replace(',', '.')) * 1000000);
    m = t.match(/(\d+(?:[.,]\d+)?)\s*k€?\b/);
    if (m) return Math.round(parseFloat(m[1].replace(',', '.')) * 1000);
    m = t.match(/€?\s?(\d{6,9})/);
    if (m) return parseInt(m[1], 10);
    return null;
  }
  function detectAudience(t) {
    const map = { 'résidence secondaire':'residence-secondaire', 'secondaire':'residence-secondaire',
      'résidence principale':'residence-principale', 'principale':'residence-principale',
      'famille':'famille', 'familial':'famille',
      'investir':'investissement', 'investissement':'investissement', 'locatif':'investissement', 'rendement':'investissement',
      'pied-à-terre':'pied-a-terre', 'pied à terre':'pied-a-terre',
      'étranger':'international', 'international':'international', 'non-résident':'international',
      'prestige':'prestige', 'luxe':'prestige' };
    for (const k in map) if (t.includes(k)) return map[k];
    return null;
  }
  function detectConfig(t) {
    const m = t.match(/([1-9])\s*(?:pièces|pieces|p\b)/);
    if (m) return m[1] + ' pièces';
    if (/villa/.test(t)) return 'Villa';
    if (/maison|hôtel particulier|hotel particulier/.test(t)) return 'Maison';
    if (/penthouse/.test(t)) return 'Penthouse';
    if (/atelier|loft/.test(t)) return 'Atelier';
    if (/studio/.test(t)) return 'Studio';
    return null;
  }
  function detectCity(t) {
    if (/neuilly|sablons|saint-james/.test(t)) return 'Neuilly';
    if (/paris|marais|passy|trocadéro|trocadero|monceau|saint-germain|odéon|odeon|madeleine|champ-de-mars|champ de mars|boulogne|haussmann/.test(t)) return 'Paris';
    if (/nice|antibes|cap d'antibes|côte d'azur|cote d'azur|riviera|azur|cannes|mer/.test(t)) return "Côte d'Azur";
    return null;
  }

  // ---------- helpers de formatage ----------
  function fmt(s) { return escapeHtml(s).replace(/\*(.+?)\*/g, '<b>$1</b>').replace(/\n/g, '<br>'); }
  function escapeHtml(s) { return (s || '').replace(/[&<>"]/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c])); }
  function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  // ---------- plomberie UI ----------
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
      const map = { fr:'Je continue en français 🇫🇷', en:'I’ll switch to English 🇬🇧', it:'Passo all’italiano 🇮🇹', ar:'سأتحدث بالعربية 🙏' };
      botSay([{ t:'text', text: map[e.target.value] }]);
    });

    // Message d'accueil (on protège les puces finales pour qu'un clic de scénario ne les écrase pas)
    const welcomeGen = state.gen;
    botSay([
      { t:'text', text:'👋 Bienvenue ! Je suis *Juliette*, la concierge immobilière IA de *Breteuil*. Je suis une assistante IA — et un conseiller reste toujours à un message.' },
      { t:'text', text:'Choisissez un scénario à gauche, tapez une réponse rapide, ou *écrivez* simplement ce que vous cherchez — par ex. « 4 pièces à Passy, 1,6 M€ ». 🏡' },
    ]).then(() => {
      if (stale(welcomeGen)) return;     // l'utilisateur a déjà lancé un scénario — ne pas écraser ses puces
      renderChoices([
        { label:'🏙️ Trouver mon bien', goto:'__discovery' },
        { label:'🏦 Financement', goto:'__emi' },
        { label:'📅 Visite privée', goto:'__sitevisit' },
      ]);
    });
  });

  // Permet aux puces d'accueil (goto commençant par __) de lancer un scénario
  const _goto = gotoNode;
  gotoNode = async function (key) {
    if (typeof key === 'string' && key.startsWith('__')) return startScenario(key.slice(2));
    return _goto(key);
  };

  window.JulietteDemo = { startScenario, state };
})();
