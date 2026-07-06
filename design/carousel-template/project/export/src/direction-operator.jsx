// ============================================================
// Direction B — Operator
// ------------------------------------------------------------
// Mono-led, structured, spec-sheet aesthetic. JetBrains Mono for
// eyebrows / labels / metadata, Inter for content. Hairline grid,
// filename-style header, bracketed indices. The "engineering brief"
// mood — leans into Voxdonna's operator-first voice.
// ============================================================

(function injectOperatorStyles() {
  if (document.getElementById('op-styles')) return;
  const s = document.createElement('style');
  s.id = 'op-styles';
  s.textContent = `
    .op-slide {
      width: 1080px; height: 1080px;
      background: #000; color: var(--fg-1);
      font-family: var(--font-sans);
      position: relative; overflow: hidden;
      box-sizing: border-box;
    }
    .op-grid {
      position: absolute; inset: 0; pointer-events: none;
      background-image:
        linear-gradient(to right, var(--border-subtle) 1px, transparent 1px),
        linear-gradient(to bottom, var(--border-subtle) 1px, transparent 1px);
      background-size: 80px 80px;
      mask-image: radial-gradient(circle at center, #000 30%, transparent 78%);
      opacity: 0.6;
    }
    /* Top status bar */
    .op-top {
      position: absolute; top: 0; left: 0; right: 0; height: 64px;
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 56px; border-bottom: 1px solid var(--border-1);
      font-family: var(--font-mono); font-size: 14px;
      color: var(--fg-3); letter-spacing: 0.12em; text-transform: uppercase;
    }
    .op-top .op-dot { display: inline-block; width: 8px; height: 8px;
                       border-radius: 50%; background: var(--copper);
                       margin-right: 12px;
                       box-shadow: 0 0 12px var(--copper); }
    .op-fname { color: var(--fg-2); }
    .op-fname .op-slash { color: var(--copper); }
    .op-meta-r { display: flex; gap: 24px; color: var(--fg-3); }

    /* Body */
    .op-body { position: absolute; left: 0; right: 0;
                top: 64px; bottom: 88px;
                padding: 72px 80px;
                display: flex; flex-direction: column; }

    /* Bottom chrome */
    .op-bot {
      position: absolute; bottom: 0; left: 0; right: 0; height: 88px;
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 56px; border-top: 1px solid var(--border-1);
      background: linear-gradient(to top, rgba(193,127,89,0.04), transparent);
    }
    .op-wm { display: flex; align-items: center; gap: 12px; }
    .op-wm img { width: 28px; height: 28px; display: block; }
    .op-wm .op-wt { font-size: 20px; font-weight: 700; letter-spacing: -0.02em; }
    .op-wm .op-wt span { color: var(--copper); }
    .op-wm .op-tag { font-family: var(--font-mono); font-size: 12px;
                     color: var(--fg-3); letter-spacing: 0.14em;
                     padding: 4px 10px; border: 1px solid var(--border-1);
                     border-radius: 100px; text-transform: uppercase;
                     margin-left: 8px; }
    .op-counter { font-family: var(--font-mono); font-size: 18px;
                  color: var(--fg-2); letter-spacing: 0.12em; }
    .op-counter .op-cur { color: var(--copper); font-weight: 700; }

    .op-eye {
      font-family: var(--font-mono); font-size: 14px; font-weight: 600;
      letter-spacing: 0.22em; text-transform: uppercase;
      color: var(--copper);
      display: inline-flex; align-items: center; gap: 14px;
    }
    .op-eye::before { content: ""; display: inline-block; width: 32px;
                       height: 1px; background: var(--copper); }
    .op-h1 { font-family: var(--font-sans); font-weight: 700;
              letter-spacing: -0.03em; line-height: 1.05;
              color: var(--fg-1); }

    /* ── Cover ───────────────────────────── */
    .op-cover .op-body { justify-content: space-between; }
    .op-cover h1 { font-size: 88px; }
    .op-cover h1 .l2 { color: var(--copper); }
    .op-cover .op-sub { font-family: var(--font-mono); font-size: 18px;
                        color: var(--fg-3); letter-spacing: 0.04em;
                        line-height: 1.6; max-width: 720px; }
    .op-cover .op-card {
      border: 1px solid var(--border-1); border-radius: 16px;
      padding: 24px 28px; background: var(--surface-1);
      display: flex; gap: 28px; align-items: center;
      align-self: flex-start;
    }
    .op-cover .op-card .l { font-family: var(--font-mono); font-size: 12px;
                             color: var(--fg-3); letter-spacing: 0.18em;
                             text-transform: uppercase; }
    .op-cover .op-card .v { font-family: var(--font-mono); font-size: 18px;
                             color: var(--fg-1); margin-top: 4px; }
    .op-cover .op-card .div { width: 1px; height: 36px; background: var(--border-1); }

    /* ── Section ─────────────────────────── */
    .op-section .op-body { justify-content: center; }
    .op-section .op-part { font-family: var(--font-mono); font-size: 16px;
                            color: var(--copper); letter-spacing: 0.24em;
                            text-transform: uppercase; }
    .op-section .op-bracket { font-family: var(--font-mono); font-size: 220px;
                               font-weight: 500; color: var(--copper-20);
                               line-height: 0.8; letter-spacing: -0.08em;
                               margin: 32px 0; }
    .op-section h1 { font-size: 128px; letter-spacing: -0.04em; }
    .op-section .op-kicker { font-family: var(--font-mono); font-size: 18px;
                              color: var(--fg-3); letter-spacing: 0.04em;
                              line-height: 1.6; margin-top: 32px;
                              max-width: 640px; }

    /* ── Stat ────────────────────────────── */
    .op-stat .op-body { justify-content: center; }
    .op-stat .op-bignum { font-family: var(--font-mono); font-weight: 700;
                           font-size: 420px; line-height: 0.86;
                           letter-spacing: -0.06em;
                           color: var(--copper-light);
                           display: flex; align-items: flex-start;
                           text-shadow: 0 0 80px var(--copper-20); }
    .op-stat .op-unit { font-size: 200px; color: var(--copper);
                         margin-left: 8px; }
    .op-stat .op-sublabel { font-family: var(--font-sans); font-size: 36px;
                             font-weight: 500; line-height: 1.3;
                             color: var(--fg-1); letter-spacing: -0.01em;
                             max-width: 760px; margin-top: 40px; }
    .op-stat .op-tags { display: flex; gap: 12px; margin-top: 28px;
                         font-family: var(--font-mono); font-size: 14px;
                         color: var(--fg-3); letter-spacing: 0.06em; }
    .op-stat .op-tag { padding: 6px 14px; border: 1px solid var(--border-1);
                        border-radius: 100px; }

    /* ── Bullets ─────────────────────────── */
    .op-bullets h1 { font-size: 56px; margin: 16px 0 40px; max-width: 800px; }
    .op-bullets .op-grid2 { display: grid; grid-template-columns: 1fr 1fr;
                             gap: 20px 24px; flex: 1; }
    .op-bullets .op-it {
      border: 1px solid var(--border-1); border-radius: 16px;
      background: var(--surface-1); padding: 28px 28px 24px;
      display: flex; flex-direction: column; gap: 8px;
      position: relative;
    }
    .op-bullets .op-it::before {
      content: ""; position: absolute; top: 0; left: 24px; right: 24px;
      height: 1px; background: var(--copper-30);
    }
    .op-bullets .op-itn { font-family: var(--font-mono); font-size: 14px;
                           color: var(--copper); letter-spacing: 0.18em; }
    .op-bullets .op-itt { font-size: 24px; font-weight: 600;
                           letter-spacing: -0.015em; line-height: 1.2; }
    .op-bullets .op-itd { font-size: 17px; color: var(--fg-3);
                           font-weight: 300; line-height: 1.5; }

    /* ── Compare ─────────────────────────── */
    .op-compare h1 { font-size: 56px; margin: 16px 0 36px; }
    .op-compare .op-cols { display: grid; grid-template-columns: 1fr 1fr;
                            gap: 20px; flex: 1; }
    .op-compare .op-col { display: flex; flex-direction: column;
                           border: 1px solid var(--border-1); border-radius: 20px;
                           background: var(--surface-1); padding: 32px;
                           position: relative; }
    .op-compare .op-col.is-right { background: var(--copper-04);
                                     border-color: var(--border-copper); }
    .op-compare .op-bar { font-family: var(--font-mono); font-size: 12px;
                           letter-spacing: 0.18em; text-transform: uppercase;
                           color: var(--fg-3); margin-bottom: 12px;
                           display: flex; align-items: center;
                           justify-content: space-between; }
    .op-compare .op-status { padding: 4px 10px; border-radius: 100px;
                              background: rgba(255,80,80,0.08);
                              color: rgba(255,140,140,0.9); }
    .op-compare .is-right .op-status { background: var(--copper-12);
                                         color: var(--copper-light); }
    .op-compare .op-name { font-size: 28px; font-weight: 700;
                            letter-spacing: -0.02em; margin-bottom: 24px; }
    .op-compare .op-quote { font-size: 24px; line-height: 1.4;
                             color: var(--fg-1); font-weight: 400;
                             flex: 1; letter-spacing: -0.005em; }
    .op-compare .op-foot { font-family: var(--font-mono); font-size: 13px;
                            color: var(--fg-3); letter-spacing: 0.08em;
                            margin-top: 24px; padding-top: 20px;
                            border-top: 1px solid var(--border-1);
                            display: flex; justify-content: space-between; }
    .op-compare .is-right .op-foot { border-color: var(--copper-20); }

    /* ── Steps ───────────────────────────── */
    .op-steps h1 { font-size: 52px; margin: 16px 0 40px; max-width: 880px; }
    .op-steps .op-list { flex: 1; display: flex; flex-direction: column; }
    .op-steps .op-row {
      display: grid; grid-template-columns: 80px 1fr auto;
      gap: 32px; align-items: center;
      padding: 24px 0;
      border-top: 1px solid var(--border-1);
    }
    .op-steps .op-row:last-child { border-bottom: 1px solid var(--border-1); }
    .op-steps .op-rn { font-family: var(--font-mono); font-size: 36px;
                        font-weight: 500; color: var(--copper);
                        letter-spacing: -0.02em; }
    .op-steps .op-rt { font-size: 28px; font-weight: 600;
                        letter-spacing: -0.015em; }
    .op-steps .op-rd { font-size: 18px; color: var(--fg-3);
                        font-weight: 300; line-height: 1.45;
                        margin-top: 4px; }
    .op-steps .op-arrow { width: 32px; height: 32px;
                           border: 1px solid var(--border-copper);
                           border-radius: 50%;
                           display: flex; align-items: center;
                           justify-content: center; color: var(--copper); }

    /* ── Feature ─────────────────────────── */
    .op-feature .op-body { justify-content: center; }
    .op-feature .op-fhead { display: flex; align-items: flex-start; gap: 28px;
                             margin: 20px 0 36px; }
    .op-feature .op-fmark { width: 96px; height: 96px; flex-shrink: 0;
                             border: 1px solid var(--copper-30);
                             background: var(--copper-08);
                             border-radius: 24px;
                             display: flex; align-items: center;
                             justify-content: center;
                             box-shadow: var(--glow-copper-sm); }
    .op-feature h1 { font-size: 64px; max-width: 720px; }
    .op-feature .op-fbody { font-size: 24px; color: var(--fg-2);
                             font-weight: 300; line-height: 1.55;
                             max-width: 780px; }
    .op-feature .op-metric-card {
      margin-top: 56px; padding: 28px 36px;
      border: 1px solid var(--border-1); border-radius: 20px;
      background: var(--surface-1);
      display: grid; grid-template-columns: auto 1fr auto;
      align-items: center; gap: 36px;
    }
    .op-feature .op-mv { font-family: var(--font-mono); font-weight: 700;
                          font-size: 88px; color: var(--copper-light);
                          letter-spacing: -0.04em; line-height: 1; }
    .op-feature .op-ml { font-family: var(--font-mono); font-size: 14px;
                          color: var(--fg-3); letter-spacing: 0.18em;
                          text-transform: uppercase; }
    .op-feature .op-bar2 { width: 220px; height: 8px; border-radius: 100px;
                            background: var(--surface-3); position: relative;
                            overflow: hidden; }
    .op-feature .op-bar2::after { content: ""; position: absolute;
                                    left: 0; top: 0; bottom: 0;
                                    width: 72%;
                                    background: linear-gradient(90deg,
                                      var(--copper), var(--copper-light));
                                    border-radius: 100px; }

    /* ── Quote ───────────────────────────── */
    .op-quote-s .op-body { justify-content: center; }
    .op-quote-s .op-qbar { display: flex; align-items: center; gap: 14px;
                            font-family: var(--font-mono); font-size: 13px;
                            letter-spacing: 0.18em; text-transform: uppercase;
                            color: var(--copper); margin-bottom: 32px; }
    .op-quote-s .op-qbar::before { content: ""; width: 32px; height: 1px;
                                     background: var(--copper); }
    .op-quote-s .op-q { font-size: 44px; line-height: 1.3; font-weight: 500;
                         letter-spacing: -0.02em; max-width: 880px;
                         color: var(--fg-1); }
    .op-quote-s .op-q .op-mq { color: var(--copper); }
    .op-quote-s .op-attrib { display: flex; align-items: center; gap: 18px;
                              margin-top: 56px; padding: 20px 24px;
                              border: 1px solid var(--border-1); border-radius: 16px;
                              background: var(--surface-1);
                              align-self: flex-start; }
    .op-quote-s .op-avatar { width: 56px; height: 56px; border-radius: 14px;
                              background: linear-gradient(135deg, var(--copper),
                                          var(--teal));
                              display: flex; align-items: center;
                              justify-content: center;
                              font-family: var(--font-mono); font-weight: 700;
                              font-size: 22px; color: #1a0e07; }
    .op-quote-s .op-aname { font-size: 20px; font-weight: 600; }
    .op-quote-s .op-arole { font-family: var(--font-mono); font-size: 13px;
                              color: var(--fg-3); letter-spacing: 0.08em;
                              margin-top: 4px; }

    /* ── CTA ─────────────────────────────── */
    .op-cta .op-body { justify-content: center; }
    .op-cta h1 { font-size: 80px; max-width: 880px; margin: 24px 0 24px; }
    .op-cta h1 .accent { color: var(--copper); }
    .op-cta .op-ctabody { font-family: var(--font-mono); font-size: 18px;
                          color: var(--fg-3); letter-spacing: 0.04em;
                          line-height: 1.6; max-width: 720px;
                          margin-bottom: 56px; }
    .op-cta .op-url-card {
      display: flex; align-items: stretch;
      border: 1px solid var(--border-copper); border-radius: 20px;
      background: var(--copper-08); overflow: hidden;
      align-self: flex-start; box-shadow: var(--glow-copper-md);
    }
    .op-cta .op-url-l { padding: 28px 32px; }
    .op-cta .op-url-l .op-l { font-family: var(--font-mono); font-size: 12px;
                                color: var(--copper); letter-spacing: 0.2em;
                                text-transform: uppercase; }
    .op-cta .op-url-l .op-u { font-family: var(--font-mono); font-size: 28px;
                                color: var(--fg-1); margin-top: 6px;
                                letter-spacing: 0; }
    .op-cta .op-url-go {
      padding: 0 32px; background: var(--copper); color: #1a0e07;
      display: flex; align-items: center; gap: 12px;
      font-size: 20px; font-weight: 600; letter-spacing: -0.01em;
    }
  `;
  document.head.appendChild(s);
})();

function OpTop({ slide, index }) {
  const fname = `/post/${String(index + 1).padStart(2, '0')}-${slide.layout}.md`;
  return (
    <div className="op-top">
      <div className="op-fname">
        <span className="op-dot" />vox<span className="op-slash">·</span>donna
        <span style={{ color: 'var(--fg-3)', marginLeft: 20 }}>{fname}</span>
      </div>
      <div className="op-meta-r">
        <span>VOICE AI / 2026</span>
        <span style={{ color: 'var(--copper)' }}>● LIVE</span>
      </div>
    </div>
  );
}

function OpBot({ index, total }) {
  return (
    <div className="op-bot">
      <div className="op-wm">
        <img src={window.__resources.voxdonnaMark} alt="" />
        <span className="op-wt">Vox<span>donna</span></span>
        <span className="op-tag">@voxdonna</span>
      </div>
      <div className="op-counter">
        <span className="op-cur">{String(index + 1).padStart(2, '0')}</span>
        <span style={{ color: 'var(--fg-4)', margin: '0 8px' }}>—</span>
        <span>{String(total).padStart(2, '0')}</span>
      </div>
    </div>
  );
}

function OperatorSlide({ slide, index, total }) {
  const s = slide;
  let body, mod = '';

  switch (s.layout) {
    case 'cover':
      mod = 'op-cover';
      body = (
        <>
          <div>
            <div className="op-eye">{s.eyebrow}</div>
            <h1 className="op-h1" style={{ marginTop: 28 }}>
              {s.headline.map((line, i) => (
                <div key={i} className={i === s.headline.length - 1 ? 'l2' : ''}>{line}</div>
              ))}
            </h1>
          </div>
          <div>
            <div className="op-sub" style={{ marginBottom: 36 }}>{s.subhead}</div>
            <div className="op-card">
              <div>
                <div className="l">Issue</div>
                <div className="v">№ 014</div>
              </div>
              <div className="div" />
              <div>
                <div className="l">Read time</div>
                <div className="v">3 min</div>
              </div>
              <div className="div" />
              <div>
                <div className="l">Format</div>
                <div className="v">POV / Field note</div>
              </div>
            </div>
          </div>
        </>
      );
      break;

    case 'section':
      mod = 'op-section';
      body = (
        <>
          <div className="op-part">{s.part} —</div>
          <div className="op-bracket">[ {s.part.replace(/^Part /, '')} ]</div>
          <h1 className="op-h1">{s.title}</h1>
          {s.kicker && <div className="op-kicker">{s.kicker}</div>}
        </>
      );
      break;

    case 'stat':
      mod = 'op-stat';
      body = (
        <>
          <div className="op-eye">SIGNAL / BY THE NUMBERS</div>
          <div className="op-bignum" style={{ marginTop: 32 }}>
            {s.value}<span className="op-unit">{s.unit}</span>
          </div>
          <div className="op-sublabel">{s.label}</div>
          <div className="op-tags">
            <span className="op-tag">{s.source}</span>
          </div>
        </>
      );
      break;

    case 'bullets':
      mod = 'op-bullets';
      body = (
        <>
          <div className="op-eye">{s.eyebrow}</div>
          <h1 className="op-h1">{s.headline}</h1>
          <div className="op-grid2">
            {s.items.map((it, i) => (
              <div className="op-it" key={i}>
                <div className="op-itn">[ {it.n} ]</div>
                <div className="op-itt">{it.t}</div>
                <div className="op-itd">{it.d}</div>
              </div>
            ))}
          </div>
        </>
      );
      break;

    case 'compare':
      mod = 'op-compare';
      body = (
        <>
          <div className="op-eye">{s.eyebrow}</div>
          <h1 className="op-h1">{s.headline}</h1>
          <div className="op-cols">
            <div className="op-col">
              <div className="op-bar">
                <span>A · {s.left.label}</span>
                <span className="op-status">DROPPED</span>
              </div>
              <div className="op-name">Generic</div>
              <div className="op-quote">"{s.left.body.replace(/^"|"$/g, '')}"</div>
              <div className="op-foot">
                <span>{s.left.meta}</span>
                <span>FAIL</span>
              </div>
            </div>
            <div className="op-col is-right">
              <div className="op-bar">
                <span>B · {s.right.label}</span>
                <span className="op-status">PASS</span>
              </div>
              <div className="op-name" style={{ color: 'var(--copper-light)' }}>Donna</div>
              <div className="op-quote">"{s.right.body.replace(/^"|"$/g, '')}"</div>
              <div className="op-foot">
                <span>{s.right.meta}</span>
                <span>WIN</span>
              </div>
            </div>
          </div>
        </>
      );
      break;

    case 'steps':
      mod = 'op-steps';
      body = (
        <>
          <div className="op-eye">{s.eyebrow}</div>
          <h1 className="op-h1">{s.headline}</h1>
          <div className="op-list">
            {s.steps.map((it, i) => (
              <div className="op-row" key={i}>
                <div className="op-rn">{it.n}</div>
                <div>
                  <div className="op-rt">{it.t}</div>
                  <div className="op-rd">{it.d}</div>
                </div>
                <div className="op-arrow">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M5 12h14M12 5l7 7-7 7" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
              </div>
            ))}
          </div>
        </>
      );
      break;

    case 'feature':
      mod = 'op-feature';
      body = (
        <>
          <div className="op-eye">{s.eyebrow}</div>
          <div className="op-fhead">
            <div className="op-fmark">
              <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="var(--copper-light)" strokeWidth="1.5">
                <path d="M13 2L3 14h7v8l10-12h-7l1-8z" strokeLinejoin="round" />
              </svg>
            </div>
            <h1 className="op-h1">{s.headline}</h1>
          </div>
          <div className="op-fbody">{s.body}</div>
          <div className="op-metric-card">
            <div className="op-mv">{s.metric}</div>
            <div className="op-bar2" />
            <div>
              <div className="op-ml">{s.metricLabel}</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--fg-3)', marginTop: 6, letterSpacing: '0.08em' }}>Target: &lt; 200ms · Status: PASS</div>
            </div>
          </div>
        </>
      );
      break;

    case 'quote':
      mod = 'op-quote-s';
      body = (
        <>
          <div className="op-qbar">TESTIMONIAL / TRANSCRIPT</div>
          <div className="op-q">
            <span className="op-mq">"</span>{s.quote}<span className="op-mq">"</span>
          </div>
          <div className="op-attrib">
            <div className="op-avatar">{s.attrib.charAt(0)}</div>
            <div>
              <div className="op-aname">{s.attrib}</div>
              <div className="op-arole">{s.role}</div>
            </div>
          </div>
        </>
      );
      break;

    case 'cta':
      mod = 'op-cta';
      body = (
        <>
          <div className="op-eye">{s.eyebrow}</div>
          <h1 className="op-h1">Hear Donna<br /><span className="accent">handle a real call.</span></h1>
          <div className="op-ctabody">{s.body}</div>
          <div className="op-url-card">
            <div className="op-url-l">
              <div className="op-l">Open in browser</div>
              <div className="op-u">{s.cta}</div>
            </div>
            <div className="op-url-go">
              GO
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                <path d="M5 12h14M12 5l7 7-7 7" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
          </div>
        </>
      );
      break;
  }

  return (
    <div className={`op-slide ${mod}`}>
      <div className="op-grid" />
      <OpTop slide={slide} index={index} />
      <div className="op-body">{body}</div>
      <OpBot index={index} total={total} />
    </div>
  );
}

window.OperatorSlide = OperatorSlide;
