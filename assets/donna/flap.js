// Split-flap rotating headline. Static "Donna." markup stays for no-JS and reduced motion.
const root = document.querySelector('.donna-hero');
const line = document.querySelector('#dh-title .dh-line');
const PHRASES = ['Donna.', 'the voice of your business.', 'here after closing time.', 'welcoming your next customer.',
  'calling while the lead is warm.', 'following up on that quote.', 'confirming tomorrow’s visits.'];
const HOLD = 2600, HOLD_HOME = 3600, STAGGER = 26, TICK = 64, LETTERS = 'abcdefghijklmnopqrstuvwxyz';
const rm = matchMedia('(prefers-reduced-motion: reduce)');

if (root && line && !rm.matches) init();

function init() {
  const lead = line.firstChild.textContent;
  let idx = 0, gen = 0, running = false, inView = true, live;

  const half = (cls, ch) => { const h = document.createElement('b'); h.className = cls; h.append(document.createElement('i')); h.firstChild.textContent = ch; return h; };
  const tile = (ch) => {
    const t = document.createElement('span');
    t.className = 'fl' + (ch === ' ' ? ' blank' : '');
    t.dataset.c = ch;
    t.append(half('t', ch), half('b', ch), half('ft', ch), half('fb', ch));
    return t;
  };
  const setChar = (t, ch) => { t.dataset.c = ch; t.classList.toggle('blank', ch === ' '); for (const i of t.querySelectorAll('i')) i.textContent = ch; };

  // words are nowrap groups so phrases wrap between words; `from` seeds each tile with the previous phrase's glyph
  const em = (phrase, from = '') => {
    const flat = from.replace(/ /g, ''); let n = 0;
    const el = document.createElement('em');
    el.className = 'dh-flap';
    phrase.split(' ').forEach((word, wi) => {
      if (wi) el.append(' ');
      const w = document.createElement('span'); w.className = 'w';
      for (const ch of word) w.append(tile(from ? (flat[n++] || ' ') : ch));
      el.append(w);
    });
    return el;
  };
  const row = (phrase, ghost) => {
    const r = document.createElement('span');
    r.className = ghost ? 'dh-row dh-ghost' : 'dh-row';
    r.append(lead, em(phrase));
    return r;
  };
  const place = (phrase) => { const r = row(phrase); live?.replaceWith(r); live = r; if (!r.isConnected) line.append(r); };

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const flip = async (t, ch, g) => {
    t.classList.remove('blank');
    for (const i of t.querySelectorAll('.t i, .fb i')) i.textContent = ch;
    const ft = t.querySelector('.ft'), fb = t.querySelector('.fb');
    const opt = { duration: TICK / 2, fill: 'both' };
    await ft.animate([{ transform: 'rotateX(0)' }, { transform: 'rotateX(-90deg)' }], { ...opt, easing: 'ease-in' }).finished;
    await fb.animate([{ transform: 'rotateX(90deg)' }, { transform: 'rotateX(0)' }], { ...opt, easing: 'ease-out' }).finished;
    if (g !== gen) return;
    setChar(t, ch);
    for (const a of t.getAnimations({ subtree: true })) a.cancel();
  };
  const settle = async (t, i, target, g) => {
    await sleep(i * STAGGER);
    const ticks = target === ' ' ? 0 : 2 + (i % 3);
    for (let k = 0; k < ticks && g === gen; k++) await flip(t, LETTERS[Math.floor(Math.random() * 26)], g);
    if (g === gen && t.dataset.c !== target) await flip(t, target, g);
  };

  async function transition(g) {
    const from = PHRASES[(idx + PHRASES.length - 1) % PHRASES.length], to = PHRASES[idx];
    const r = row(to); r.querySelector('em').replaceWith(em(to, from));
    live.replaceWith(r); live = r;
    const target = to.replace(/ /g, '');
    await Promise.all([...r.querySelectorAll('.fl')].map((t, i) => settle(t, i, target[i], g)));
  }

  async function loop(g) {
    while (g === gen) {
      await sleep(idx === 0 ? HOLD_HOME : HOLD);
      if (g !== gen) return;
      idx = (idx + 1) % PHRASES.length;
      await transition(g);
    }
  }

  function update() {
    const want = !document.hidden && inView && root.dataset.mode === 'ready' && !rm.matches;
    if (want && !running) { running = true; loop(gen); }
    else if (!want && running) { running = false; gen++; place(PHRASES[idx]); }
    if (root.dataset.mode !== 'ready' && idx !== 0) { idx = 0; place(PHRASES[0]); }
  }

  line.textContent = '';
  PHRASES.forEach((p) => line.append(row(p, true)));
  place(PHRASES[0]);
  line.classList.add('is-board');

  new IntersectionObserver(([e]) => { inView = e.isIntersecting; update(); }).observe(root);
  new MutationObserver(update).observe(root, { attributes: true, attributeFilter: ['data-mode'] });
  document.addEventListener('visibilitychange', update);
  rm.addEventListener('change', update);
  update();
}
