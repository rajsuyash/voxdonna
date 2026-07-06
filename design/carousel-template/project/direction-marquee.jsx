// ============================================================
// Direction C — Marquee
// ------------------------------------------------------------
// Bold, graphic, premium. Display-weight Inter (800) at large sizes,
// tight tracking, copper glows behind statements, copper-filled
// chips and outlined elements. The "campaign" mood — feels more like
// a brand film still than a doc.
// ============================================================

(function injectMarqueeStyles() {
  if (document.getElementById('mq-styles')) return;
  const s = document.createElement('style');
  s.id = 'mq-styles';
  s.textContent = `
    .mq-slide {
      width: 1080px; height: 1080px;
      background: #000; color: var(--fg-1);
      font-family: var(--font-sans);
      position: relative; overflow: hidden;
      box-sizing: border-box;
    }
    .mq-glow {
      position: absolute; pointer-events: none;
      width: 900px; height: 900px; border-radius: 50%;
      background: radial-gradient(circle, var(--copper-15) 0%, transparent 60%);
      filter: blur(40px);
    }
    .mq-glow.tl { top: -300px; left: -300px; }
    .mq-glow.br { bottom: -360px; right: -360px;
                  background: radial-gradient(circle, rgba(45,92,79,0.18) 0%, transparent 60%); }

    .mq-body { position: absolute; inset: 80px 80px 132px 80px;
                display: flex; flex-direction: column; }

    /* Chip / pill */
    .mq-chip {
      display: inline-flex; align-items: center; gap: 12px;
      font-family: var(--font-mono); font-size: 14px; font-weight: 600;
      letter-spacing: 0.18em; text-transform: uppercase;
      color: var(--copper-light);
      padding: 10px 18px; border-radius: 100px;
      border: 1px solid var(--copper-30);
      background: var(--copper-08);
      align-self: flex-start;
    }
    .mq-chip .mq-dot { width: 6px; height: 6px; border-radius: 50%;
                        background: var(--copper);
                        box-shadow: 0 0 12px var(--copper); }

    .mq-h1 {
      font-family: var(--font-sans);
      font-weight: 800; letter-spacing: -0.045em;
      line-height: 0.94; color: var(--fg-1);
    }

    /* Bottom chrome */
    .mq-bot {
      position: absolute; bottom: 0; left: 0; right: 0; height: 96px;
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 80px;
    }
    .mq-wm { display: flex; align-items: center; gap: 14px;
              padding: 12px 22px 12px 14px;
              border-radius: 100px;
              background: var(--surface-1);
              border: 1px solid var(--border-1); }
    .mq-wm img { width: 32px; height: 32px; display: block; }
    .mq-wm .mq-wt { font-size: 22px; font-weight: 800; letter-spacing: -0.02em; }
    .mq-wm .mq-wt span { color: var(--copper); }
    .mq-counter { display: flex; align-items: center; gap: 16px;
                   font-family: var(--font-mono); font-size: 16px;
                   color: var(--fg-3); letter-spacing: 0.18em; }
    .mq-counter .mq-bars { display: flex; gap: 4px; }
    .mq-counter .mq-bar { width: 18px; height: 4px; border-radius: 100px;
                           background: var(--surface-3); }
    .mq-counter .mq-bar.on { background: var(--copper); }

    /* ── Cover ───────────────────────────── */
    .mq-cover .mq-body { justify-content: space-between; }
    .mq-cover h1 { font-size: 96px; }
    .mq-cover h1 .l3 {
      background: linear-gradient(135deg, var(--copper-light), var(--copper));
      -webkit-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .mq-cover .mq-sub {
      font-size: 26px; line-height: 1.5; color: var(--fg-2);
      font-weight: 400; max-width: 720px;
      padding-top: 32px; border-top: 1px solid var(--copper-20);
    }

    /* ── Section ─────────────────────────── */
    .mq-section .mq-body { justify-content: center; align-items: flex-start; }
    .mq-section .mq-part-ring {
      width: 220px; height: 220px; border-radius: 50%;
      border: 1px solid var(--copper-30);
      display: flex; align-items: center; justify-content: center;
      position: relative; margin-bottom: 48px;
      background: radial-gradient(circle, var(--copper-08) 0%, transparent 70%);
    }
    .mq-section .mq-part-ring::after {
      content: ""; position: absolute; inset: 12px; border-radius: 50%;
      border: 1px dashed var(--copper-20);
    }
    .mq-section .mq-part-num { font-family: var(--font-mono); font-weight: 700;
                                 font-size: 96px; color: var(--copper-light);
                                 letter-spacing: -0.04em; line-height: 1; }
    .mq-section .mq-part-l { font-family: var(--font-mono); font-size: 14px;
                              letter-spacing: 0.24em; color: var(--copper);
                              text-transform: uppercase; margin-bottom: 24px; }
    .mq-section h1 { font-size: 168px; letter-spacing: -0.05em;
                      max-width: 880px; }
    .mq-section .mq-kicker { font-size: 26px; color: var(--fg-3);
                              max-width: 680px; line-height: 1.45;
                              margin-top: 36px; font-weight: 400; }

    /* ── Stat ────────────────────────────── */
    .mq-stat .mq-body { justify-content: center; }
    .mq-stat .mq-statwrap {
      position: relative; align-self: flex-start; padding: 32px 0;
      margin: 32px 0;
    }
    .mq-stat .mq-bignum {
      font-family: var(--font-sans); font-weight: 800;
      font-size: 480px; line-height: 0.82; letter-spacing: -0.07em;
      color: var(--fg-1); display: flex; align-items: flex-start;
      position: relative; z-index: 1;
    }
    .mq-stat .mq-bignum::before {
      content: attr(data-num); position: absolute; inset: 0;
      color: transparent;
      -webkit-text-stroke: 2px var(--copper-30);
      z-index: -1; transform: translate(16px, 12px);
    }
    .mq-stat .mq-unit {
      font-size: 240px; line-height: 1;
      background: linear-gradient(180deg, var(--copper-light), var(--copper));
      -webkit-background-clip: text; background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-left: 4px;
    }
    .mq-stat .mq-sublabel { font-size: 36px; font-weight: 500;
                             line-height: 1.3; color: var(--fg-1);
                             letter-spacing: -0.015em; max-width: 740px; }
    .mq-stat .mq-source { display: flex; align-items: center; gap: 14px;
                           margin-top: 24px; font-family: var(--font-mono);
                           font-size: 14px; color: var(--fg-3);
                           letter-spacing: 0.06em; }
    .mq-stat .mq-source::before { content: ""; width: 24px; height: 1px;
                                    background: var(--copper); }

    /* ── Bullets ─────────────────────────── */
    .mq-bullets h1 { font-size: 64px; margin: 20px 0 44px; max-width: 800px; }
    .mq-bullets .mq-list { display: flex; flex-direction: column; gap: 14px;
                            flex: 1; }
    .mq-bullets .mq-it {
      display: grid; grid-template-columns: 84px 1fr;
      gap: 24px; align-items: center;
      padding: 24px 28px;
      border-radius: 20px;
      background: var(--surface-1);
      border: 1px solid var(--border-1);
      position: relative;
    }
    .mq-bullets .mq-it::before {
      content: ""; position: absolute; left: 0; top: 16px; bottom: 16px;
      width: 3px; border-radius: 0 3px 3px 0;
      background: var(--copper);
    }
    .mq-bullets .mq-itn {
      font-family: var(--font-mono); font-weight: 700;
      font-size: 36px; color: var(--copper-light);
      letter-spacing: -0.03em;
    }
    .mq-bullets .mq-itt { font-size: 26px; font-weight: 700;
                           letter-spacing: -0.02em; line-height: 1.2; }
    .mq-bullets .mq-itd { font-size: 17px; color: var(--fg-3);
                           font-weight: 400; line-height: 1.45;
                           margin-top: 6px; max-width: 680px; }

    /* ── Compare ─────────────────────────── */
    .mq-compare h1 { font-size: 60px; margin: 20px 0 40px; }
    .mq-compare .mq-cols { display: grid; grid-template-columns: 1fr 1fr;
                            gap: 20px; flex: 1; }
    .mq-compare .mq-col {
      display: flex; flex-direction: column;
      padding: 32px; border-radius: 24px;
      background: var(--surface-1);
      border: 1px solid var(--border-1);
    }
    .mq-compare .mq-col.is-right {
      background: linear-gradient(160deg, var(--copper-12), var(--copper-04));
      border-color: var(--copper-30);
      box-shadow: var(--glow-copper-md);
    }
    .mq-compare .mq-cbadge {
      align-self: flex-start;
      font-family: var(--font-mono); font-size: 12px; font-weight: 700;
      letter-spacing: 0.2em; text-transform: uppercase;
      padding: 6px 14px; border-radius: 100px;
      background: var(--surface-3); color: var(--fg-3);
    }
    .mq-compare .is-right .mq-cbadge {
      background: var(--copper); color: #1a0e07;
    }
    .mq-compare .mq-cname { font-size: 32px; font-weight: 800;
                             letter-spacing: -0.025em; margin: 20px 0 24px; }
    .mq-compare .is-right .mq-cname { color: var(--copper-light); }
    .mq-compare .mq-cquote {
      font-size: 24px; line-height: 1.4; color: var(--fg-1);
      font-weight: 400; flex: 1; letter-spacing: -0.005em;
    }
    .mq-compare .mq-cfoot {
      font-family: var(--font-mono); font-size: 13px;
      color: var(--fg-3); letter-spacing: 0.08em;
      text-transform: uppercase; margin-top: 24px;
      padding-top: 20px; border-top: 1px solid var(--border-1);
    }
    .mq-compare .is-right .mq-cfoot { border-color: var(--copper-20);
                                        color: var(--copper-light); }

    /* ── Steps ───────────────────────────── */
    .mq-steps h1 { font-size: 56px; margin: 20px 0 40px; max-width: 880px; }
    .mq-steps .mq-track { position: relative; display: flex;
                           flex-direction: column; gap: 20px; flex: 1; }
    .mq-steps .mq-track::before {
      content: ""; position: absolute; top: 32px; bottom: 32px; left: 36px;
      width: 1px;
      background: linear-gradient(to bottom,
        var(--copper) 0%, var(--copper-30) 50%, var(--copper-20) 100%);
    }
    .mq-steps .mq-row {
      display: grid; grid-template-columns: 72px 1fr;
      gap: 28px; align-items: flex-start;
      position: relative;
    }
    .mq-steps .mq-bub {
      width: 72px; height: 72px; border-radius: 50%;
      background: var(--bg);
      border: 1.5px solid var(--copper);
      display: flex; align-items: center; justify-content: center;
      font-family: var(--font-mono); font-weight: 700;
      font-size: 24px; color: var(--copper-light);
      letter-spacing: -0.02em;
      box-shadow: 0 0 0 6px var(--bg), 0 0 24px var(--copper-30);
    }
    .mq-steps .mq-rcard {
      padding: 24px 28px; border-radius: 20px;
      background: var(--surface-1);
      border: 1px solid var(--border-1);
    }
    .mq-steps .mq-rt { font-size: 26px; font-weight: 700;
                        letter-spacing: -0.015em; }
    .mq-steps .mq-rd { font-size: 18px; color: var(--fg-3);
                        font-weight: 400; line-height: 1.5;
                        margin-top: 8px; }

    /* ── Feature ─────────────────────────── */
    .mq-feature .mq-body { justify-content: space-between; }
    .mq-feature .mq-fmark {
      width: 120px; height: 120px;
      border-radius: 32px;
      background: linear-gradient(135deg, var(--copper), var(--teal));
      display: flex; align-items: center; justify-content: center;
      box-shadow: var(--glow-copper-lg);
      align-self: flex-start;
    }
    .mq-feature h1 { font-size: 88px; max-width: 780px; }
    .mq-feature h1 .accent { color: var(--copper-light); }
    .mq-feature .mq-fbody { font-size: 24px; color: var(--fg-2);
                             font-weight: 400; line-height: 1.5;
                             max-width: 780px; }
    .mq-feature .mq-metric {
      display: flex; align-items: stretch;
      align-self: flex-start;
      border-radius: 24px; overflow: hidden;
      border: 1px solid var(--copper-30);
      background: var(--copper-08);
      box-shadow: var(--glow-copper-md);
    }
    .mq-feature .mq-mv {
      padding: 24px 36px;
      font-family: var(--font-sans); font-weight: 800;
      font-size: 96px; line-height: 1;
      letter-spacing: -0.05em;
      background: linear-gradient(135deg, var(--copper-light), var(--copper));
      -webkit-background-clip: text; background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .mq-feature .mq-mldiv { width: 1px; background: var(--copper-20); }
    .mq-feature .mq-ml {
      padding: 0 32px;
      display: flex; flex-direction: column; justify-content: center;
      font-family: var(--font-mono); font-size: 16px;
      color: var(--copper-light); letter-spacing: 0.16em;
      text-transform: uppercase;
    }
    .mq-feature .mq-ml .sub { color: var(--fg-3); font-size: 13px;
                                margin-top: 6px; letter-spacing: 0.12em; }

    /* ── Quote ───────────────────────────── */
    .mq-quote-s .mq-body { justify-content: center; }
    .mq-quote-s .mq-qmark {
      font-family: var(--font-sans); font-weight: 800;
      font-size: 280px; line-height: 0.7;
      color: var(--copper); letter-spacing: -0.06em;
      margin-bottom: -40px;
      filter: drop-shadow(0 0 40px var(--copper-30));
    }
    .mq-quote-s .mq-q {
      font-size: 52px; line-height: 1.2; font-weight: 700;
      letter-spacing: -0.025em; max-width: 880px;
      color: var(--fg-1);
    }
    .mq-quote-s .mq-q .hl {
      background: linear-gradient(180deg, transparent 60%, var(--copper-30) 60%);
      padding: 0 2px;
    }
    .mq-quote-s .mq-attrib { display: flex; align-items: center; gap: 20px;
                              margin-top: 56px; }
    .mq-quote-s .mq-avatar {
      width: 72px; height: 72px; border-radius: 50%;
      background: linear-gradient(135deg, var(--copper), var(--teal));
      display: flex; align-items: center; justify-content: center;
      font-family: var(--font-sans); font-weight: 800;
      font-size: 28px; color: #1a0e07;
      box-shadow: 0 0 0 4px var(--bg), 0 0 0 5px var(--copper-30);
    }
    .mq-quote-s .mq-aname { font-size: 24px; font-weight: 700; }
    .mq-quote-s .mq-arole { font-family: var(--font-mono); font-size: 14px;
                              color: var(--fg-3); letter-spacing: 0.08em;
                              margin-top: 6px; }

    /* ── CTA ─────────────────────────────── */
    .mq-cta .mq-body { justify-content: center; align-items: flex-start; }
    .mq-cta h1 { font-size: 100px; max-width: 880px; margin: 28px 0 28px;
                  letter-spacing: -0.05em; }
    .mq-cta h1 .accent {
      background: linear-gradient(135deg, var(--copper-light), var(--copper));
      -webkit-background-clip: text; background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .mq-cta .mq-ctabody { font-size: 26px; color: var(--fg-3);
                          font-weight: 400; line-height: 1.45;
                          max-width: 700px; margin-bottom: 56px; }
    .mq-cta .mq-pill {
      display: inline-flex; align-items: center; gap: 20px;
      padding: 26px 40px; border-radius: var(--r-cta);
      background: linear-gradient(135deg, var(--copper-light), var(--copper));
      color: #1a0e07;
      font-size: 28px; font-weight: 700; letter-spacing: -0.015em;
      box-shadow: var(--glow-copper-xl);
    }
  `;
  document.head.appendChild(s);
})();

function MqBot({ index, total }) {
  return (
    <div className="mq-bot">
      <div className="mq-wm">
        <img src="assets/voxdonna-mark.png" alt="" />
        <span className="mq-wt">Vox<span>donna</span></span>
      </div>
      <div className="mq-counter">
        <span>{String(index + 1).padStart(2, '0')} / {String(total).padStart(2, '0')}</span>
        <div className="mq-bars">
          {Array.from({ length: total }).map((_, i) => (
            <div key={i} className={`mq-bar ${i <= index ? 'on' : ''}`} />
          ))}
        </div>
      </div>
    </div>
  );
}

function MarqueeSlide({ slide, index, total }) {
  const s = slide;
  let body, mod = '';

  switch (s.layout) {
    case 'cover':
      mod = 'mq-cover';
      body = (
        <>
          <div>
            <div className="mq-chip"><span className="mq-dot" />{s.eyebrow}</div>
            <h1 className="mq-h1" style={{ marginTop: 40 }}>
              {s.headline.map((line, i) => (
                <div key={i} className={i === s.headline.length - 1 ? 'l3' : ''}>{line}</div>
              ))}
            </h1>
          </div>
          <div className="mq-sub">{s.subhead}</div>
        </>
      );
      break;

    case 'section':
      mod = 'mq-section';
      body = (
        <>
          <div className="mq-part-ring">
            <div className="mq-part-num">{s.part.replace(/^Part /, '')}</div>
          </div>
          <div className="mq-part-l">{s.part}</div>
          <h1 className="mq-h1">{s.title}</h1>
          {s.kicker && <div className="mq-kicker">{s.kicker}</div>}
        </>
      );
      break;

    case 'stat':
      mod = 'mq-stat';
      body = (
        <>
          <div className="mq-chip"><span className="mq-dot" />SIGNAL / BY THE NUMBERS</div>
          <div className="mq-statwrap">
            <div className="mq-bignum" data-num={s.value}>
              {s.value}<span className="mq-unit">{s.unit}</span>
            </div>
          </div>
          <div className="mq-sublabel">{s.label}</div>
          <div className="mq-source">{s.source}</div>
        </>
      );
      break;

    case 'bullets':
      mod = 'mq-bullets';
      body = (
        <>
          <div className="mq-chip"><span className="mq-dot" />{s.eyebrow}</div>
          <h1 className="mq-h1">{s.headline}</h1>
          <div className="mq-list">
            {s.items.map((it, i) => (
              <div className="mq-it" key={i}>
                <div className="mq-itn">{it.n}</div>
                <div>
                  <div className="mq-itt">{it.t}</div>
                  <div className="mq-itd">{it.d}</div>
                </div>
              </div>
            ))}
          </div>
        </>
      );
      break;

    case 'compare':
      mod = 'mq-compare';
      body = (
        <>
          <div className="mq-chip"><span className="mq-dot" />{s.eyebrow}</div>
          <h1 className="mq-h1">{s.headline}</h1>
          <div className="mq-cols">
            <div className="mq-col">
              <div className="mq-cbadge">Before</div>
              <div className="mq-cname">{s.left.label}</div>
              <div className="mq-cquote">"{s.left.body.replace(/^"|"$/g, '')}"</div>
              <div className="mq-cfoot">{s.left.meta}</div>
            </div>
            <div className="mq-col is-right">
              <div className="mq-cbadge">After</div>
              <div className="mq-cname">{s.right.label}</div>
              <div className="mq-cquote">"{s.right.body.replace(/^"|"$/g, '')}"</div>
              <div className="mq-cfoot">{s.right.meta}</div>
            </div>
          </div>
        </>
      );
      break;

    case 'steps':
      mod = 'mq-steps';
      body = (
        <>
          <div className="mq-chip"><span className="mq-dot" />{s.eyebrow}</div>
          <h1 className="mq-h1">{s.headline}</h1>
          <div className="mq-track">
            {s.steps.map((it, i) => (
              <div className="mq-row" key={i}>
                <div className="mq-bub">{it.n}</div>
                <div className="mq-rcard">
                  <div className="mq-rt">{it.t}</div>
                  <div className="mq-rd">{it.d}</div>
                </div>
              </div>
            ))}
          </div>
        </>
      );
      break;

    case 'feature':
      mod = 'mq-feature';
      body = (
        <>
          <div>
            <div className="mq-fmark">
              <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="#1a0e07" strokeWidth="1.8">
                <path d="M13 2L3 14h7v8l10-12h-7l1-8z" strokeLinejoin="round" strokeLinecap="round" />
              </svg>
            </div>
            <div className="mq-chip" style={{ marginTop: 28 }}>{s.eyebrow}</div>
            <h1 className="mq-h1" style={{ marginTop: 24 }}>
              <span className="accent">{s.headline.split(' ')[0]}</span> {s.headline.split(' ').slice(1).join(' ')}
            </h1>
          </div>
          <div className="mq-fbody">{s.body}</div>
          <div className="mq-metric">
            <div className="mq-mv">{s.metric}</div>
            <div className="mq-mldiv" />
            <div className="mq-ml">
              {s.metricLabel}
              <span className="sub">Target &lt; 200ms · Status: passing</span>
            </div>
          </div>
        </>
      );
      break;

    case 'quote':
      mod = 'mq-quote-s';
      body = (
        <>
          <div className="mq-qmark">"</div>
          <div className="mq-q">{s.quote}</div>
          <div className="mq-attrib">
            <div className="mq-avatar">{s.attrib.charAt(0)}</div>
            <div>
              <div className="mq-aname">{s.attrib}</div>
              <div className="mq-arole">{s.role}</div>
            </div>
          </div>
        </>
      );
      break;

    case 'cta':
      mod = 'mq-cta';
      body = (
        <>
          <div className="mq-chip"><span className="mq-dot" />{s.eyebrow}</div>
          <h1 className="mq-h1">
            Hear Donna<br />handle <span className="accent">a real call.</span>
          </h1>
          <div className="mq-ctabody">{s.body}</div>
          <div className="mq-pill">
            {s.cta}
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M5 12h14M12 5l7 7-7 7" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
        </>
      );
      break;
  }

  // Glow placement varies by layout
  const showGlow = ['cover', 'section', 'stat', 'quote', 'cta', 'feature'].includes(s.layout);

  return (
    <div className={`mq-slide ${mod}`}>
      {showGlow && <div className="mq-glow tl" />}
      {showGlow && <div className="mq-glow br" />}
      <div className="mq-body">{body}</div>
      <MqBot index={index} total={total} />
    </div>
  );
}

window.MarqueeSlide = MarqueeSlide;
