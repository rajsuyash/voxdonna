// ============================================================
// Direction A — Editorial
// ------------------------------------------------------------
// Restrained. Big Inter type, generous negative space, a single
// copper hairline as accent. The "Bloomberg / FT cover story"
// mood. Renders 10 layouts at 1080×1080.
// ============================================================

(function injectEditorialStyles() {
  if (document.getElementById('ed-styles')) return;
  const s = document.createElement('style');
  s.id = 'ed-styles';
  s.textContent = `
    .ed-slide {
      width: 1080px; height: 1080px;
      background: #000; color: var(--fg-1);
      font-family: var(--font-sans);
      position: relative; overflow: hidden;
      box-sizing: border-box;
    }
    .ed-body { position: absolute; inset: 96px 96px 168px 96px;
               display: flex; flex-direction: column; }
    .ed-eyebrow {
      font-family: var(--font-mono);
      font-size: 18px; font-weight: 600;
      letter-spacing: 0.2em; text-transform: uppercase;
      color: var(--copper);
    }
    .ed-h1 {
      font-family: var(--font-sans);
      font-weight: 700; letter-spacing: -0.035em;
      line-height: 0.98; color: var(--fg-1);
    }
    .ed-sub {
      font-family: var(--font-sans);
      font-weight: 300; font-size: 28px; line-height: 1.45;
      color: var(--fg-3); letter-spacing: -0.01em;
    }
    .ed-chrome {
      position: absolute; bottom: 56px; left: 96px; right: 96px;
      display: flex; justify-content: space-between; align-items: center;
      padding-top: 28px;
      border-top: 1px solid var(--border-1);
    }
    .ed-wm { display: flex; align-items: center; gap: 12px;
             font-size: 22px; font-weight: 700; letter-spacing: -0.02em; }
    .ed-wm img { width: 28px; height: 28px; display: block; }
    .ed-wm .ed-d { color: var(--copper); }
    .ed-counter { font-family: var(--font-mono); font-size: 16px;
                  color: var(--fg-3); letter-spacing: 0.14em; }

    /* ── Cover ───────────────────────────── */
    .ed-cover .ed-body { justify-content: space-between; }
    .ed-cover h1 { font-size: 104px; }
    .ed-cover .ed-sub { max-width: 720px; }
    .ed-cover .ed-rule { width: 64px; height: 2px; background: var(--copper);
                         margin: 32px 0 28px; }

    /* ── Section ─────────────────────────── */
    .ed-section .ed-body { justify-content: center; }
    .ed-section .ed-part { font-family: var(--font-mono); font-size: 18px;
                           color: var(--copper); letter-spacing: 0.24em;
                           text-transform: uppercase; margin-bottom: 32px; }
    .ed-section h1 { font-size: 156px; letter-spacing: -0.045em; }
    .ed-section .ed-kicker { font-size: 28px; color: var(--fg-3);
                             font-weight: 300; margin-top: 36px;
                             max-width: 640px; line-height: 1.4; }

    /* ── Stat ────────────────────────────── */
    .ed-stat .ed-body { justify-content: center; }
    .ed-stat .ed-bignum { font-family: var(--font-sans); font-weight: 700;
                          font-size: 380px; line-height: 0.86;
                          letter-spacing: -0.06em; color: var(--fg-1);
                          display: flex; align-items: flex-start; }
    .ed-stat .ed-unit { font-size: 180px; color: var(--copper);
                        margin-left: 12px; line-height: 1; }
    .ed-stat .ed-statlbl { font-size: 36px; font-weight: 400; line-height: 1.3;
                           color: var(--fg-1); max-width: 720px;
                           letter-spacing: -0.01em; margin-top: 40px; }
    .ed-stat .ed-source { font-family: var(--font-mono); font-size: 15px;
                          color: var(--fg-3); margin-top: 24px;
                          letter-spacing: 0.04em; }

    /* ── Bullets ─────────────────────────── */
    .ed-bullets h1 { font-size: 64px; margin: 20px 0 48px; max-width: 800px; }
    .ed-bullets .ed-items { display: flex; flex-direction: column; gap: 28px;
                            flex: 1; }
    .ed-bullets .ed-item { display: grid; grid-template-columns: 88px 1fr;
                           gap: 28px; padding-top: 24px;
                           border-top: 1px solid var(--border-1); }
    .ed-bullets .ed-n { font-family: var(--font-mono); font-size: 22px;
                        color: var(--copper); letter-spacing: 0.04em; }
    .ed-bullets .ed-t { font-size: 28px; font-weight: 600;
                        letter-spacing: -0.015em; line-height: 1.2; }
    .ed-bullets .ed-d { font-size: 22px; color: var(--fg-3); line-height: 1.45;
                        font-weight: 300; margin-top: 8px; max-width: 720px; }

    /* ── Compare ─────────────────────────── */
    .ed-compare h1 { font-size: 60px; margin: 20px 0 48px; }
    .ed-compare .ed-cols { display: grid; grid-template-columns: 1fr 1fr;
                           gap: 32px; flex: 1; }
    .ed-compare .ed-col { display: flex; flex-direction: column;
                          padding: 36px; border: 1px solid var(--border-1);
                          border-radius: 24px; background: var(--surface-1); }
    .ed-compare .ed-col.is-right { border-color: var(--border-copper);
                                    background: var(--copper-04); }
    .ed-compare .ed-collbl { font-family: var(--font-mono); font-size: 14px;
                             letter-spacing: 0.16em; text-transform: uppercase;
                             color: var(--fg-3); margin-bottom: 24px; }
    .ed-compare .is-right .ed-collbl { color: var(--copper); }
    .ed-compare .ed-quote { font-size: 28px; line-height: 1.4;
                            font-weight: 400; color: var(--fg-1);
                            letter-spacing: -0.01em; flex: 1; }
    .ed-compare .ed-meta { font-family: var(--font-mono); font-size: 14px;
                           color: var(--fg-3); letter-spacing: 0.08em;
                           text-transform: uppercase; margin-top: 28px;
                           padding-top: 20px; border-top: 1px dashed var(--border-1); }
    .ed-compare .is-right .ed-meta { color: var(--copper-light);
                                      border-color: var(--copper-20); }

    /* ── Steps ───────────────────────────── */
    .ed-steps h1 { font-size: 60px; margin: 20px 0 56px; }
    .ed-steps .ed-step { display: grid; grid-template-columns: 100px 1fr;
                         gap: 32px; padding: 28px 0;
                         border-top: 1px solid var(--border-1); }
    .ed-steps .ed-step:last-child { border-bottom: 1px solid var(--border-1); }
    .ed-steps .ed-n { font-family: var(--font-mono); font-size: 40px;
                      font-weight: 500; color: var(--copper);
                      letter-spacing: -0.02em; }
    .ed-steps .ed-t { font-size: 32px; font-weight: 600;
                      letter-spacing: -0.015em; }
    .ed-steps .ed-d { font-size: 22px; color: var(--fg-3); line-height: 1.45;
                      font-weight: 300; margin-top: 6px; max-width: 720px; }

    /* ── Feature ─────────────────────────── */
    .ed-feature .ed-body { justify-content: center; }
    .ed-feature .ed-fhead { display: flex; align-items: flex-start; gap: 32px;
                            margin: 24px 0 48px; }
    .ed-feature .ed-fmark { width: 88px; height: 88px; flex-shrink: 0;
                            border: 1px solid var(--border-copper);
                            border-radius: 20px;
                            display: flex; align-items: center;
                            justify-content: center; }
    .ed-feature h1 { font-size: 72px; max-width: 680px; }
    .ed-feature .ed-fbody { font-size: 26px; color: var(--fg-2);
                            line-height: 1.5; font-weight: 400;
                            max-width: 760px; letter-spacing: -0.005em; }
    .ed-feature .ed-metric { display: flex; align-items: baseline; gap: 24px;
                             margin-top: 64px; padding-top: 36px;
                             border-top: 1px solid var(--border-1); }
    .ed-feature .ed-mv { font-family: var(--font-sans); font-weight: 700;
                          font-size: 120px; color: var(--copper);
                          letter-spacing: -0.04em; line-height: 1; }
    .ed-feature .ed-ml { font-family: var(--font-mono); font-size: 16px;
                          color: var(--fg-3); letter-spacing: 0.14em;
                          text-transform: uppercase; }

    /* ── Quote ───────────────────────────── */
    .ed-quote-s .ed-body { justify-content: center; }
    .ed-quote-s .ed-mark { font-family: var(--font-sans); font-size: 200px;
                            line-height: 0.8; color: var(--copper);
                            margin-bottom: -28px; font-weight: 700; }
    .ed-quote-s .ed-q { font-size: 48px; line-height: 1.25; font-weight: 500;
                         letter-spacing: -0.02em; max-width: 880px; }
    .ed-quote-s .ed-attrib { display: flex; align-items: center; gap: 20px;
                              margin-top: 56px; padding-top: 28px;
                              border-top: 1px solid var(--border-1); }
    .ed-quote-s .ed-avatar { width: 64px; height: 64px; border-radius: 50%;
                              background: linear-gradient(135deg, var(--copper),
                                          var(--teal));
                              border: 1px solid var(--border-copper); }
    .ed-quote-s .ed-aname { font-size: 22px; font-weight: 600; }
    .ed-quote-s .ed-arole { font-family: var(--font-mono); font-size: 14px;
                              color: var(--fg-3); letter-spacing: 0.08em;
                              text-transform: uppercase; margin-top: 4px; }

    /* ── CTA ─────────────────────────────── */
    .ed-cta .ed-body { justify-content: center; }
    .ed-cta h1 { font-size: 92px; max-width: 880px; margin: 24px 0 32px; }
    .ed-cta .ed-ctabody { font-size: 26px; color: var(--fg-3);
                          font-weight: 300; line-height: 1.45;
                          max-width: 700px; margin-bottom: 64px; }
    .ed-cta .ed-pill { display: inline-flex; align-items: center; gap: 18px;
                       padding: 22px 36px; border-radius: var(--r-cta);
                       background: var(--copper); color: #1a0e07;
                       font-size: 24px; font-weight: 600;
                       letter-spacing: -0.01em; align-self: flex-start; }
    .ed-cta .ed-arrow { width: 24px; height: 24px; }
  `;
  document.head.appendChild(s);
})();

function EdWordmark() {
  return (
    <div className="ed-wm">
      <img src={window.__resources.voxdonnaMark} alt="" />
      <span>Vox<span className="ed-d">donna</span></span>
    </div>
  );
}

function EdChrome({ index, total }) {
  const c = `${String(index + 1).padStart(2, '0')} / ${String(total).padStart(2, '0')}`;
  return (
    <div className="ed-chrome">
      <EdWordmark />
      <span className="ed-counter">{c}</span>
    </div>
  );
}

function EditorialSlide({ slide, index, total }) {
  const s = slide;
  let body;
  let modClass = '';

  switch (s.layout) {
    case 'cover':
      modClass = 'ed-cover';
      body = (
        <>
          <div>
            <div className="ed-eyebrow">{s.eyebrow}</div>
            <div className="ed-rule" />
          </div>
          <div>
            <h1 className="ed-h1">
              {s.headline.map((line, i) => (
                <div key={i}>{i === s.headline.length - 1 ? <span style={{ color: 'var(--copper)' }}>{line}</span> : line}</div>
              ))}
            </h1>
            <div className="ed-sub" style={{ marginTop: 40 }}>{s.subhead}</div>
          </div>
        </>
      );
      break;

    case 'section':
      modClass = 'ed-section';
      body = (
        <>
          <div className="ed-part">{s.part}</div>
          <h1 className="ed-h1">{s.title}</h1>
          {s.kicker && <div className="ed-kicker">{s.kicker}</div>}
        </>
      );
      break;

    case 'stat':
      modClass = 'ed-stat';
      body = (
        <>
          <div className="ed-eyebrow" style={{ marginBottom: 28 }}>BY THE NUMBERS</div>
          <div className="ed-bignum">
            {s.value}<span className="ed-unit">{s.unit}</span>
          </div>
          <div className="ed-statlbl">{s.label}</div>
          <div className="ed-source">{s.source}</div>
        </>
      );
      break;

    case 'bullets':
      modClass = 'ed-bullets';
      body = (
        <>
          <div className="ed-eyebrow">{s.eyebrow}</div>
          <h1 className="ed-h1">{s.headline}</h1>
          <div className="ed-items">
            {s.items.map((it, i) => (
              <div className="ed-item" key={i}>
                <div className="ed-n">{it.n}</div>
                <div>
                  <div className="ed-t">{it.t}</div>
                  <div className="ed-d">{it.d}</div>
                </div>
              </div>
            ))}
          </div>
        </>
      );
      break;

    case 'compare':
      modClass = 'ed-compare';
      body = (
        <>
          <div className="ed-eyebrow">{s.eyebrow}</div>
          <h1 className="ed-h1">{s.headline}</h1>
          <div className="ed-cols">
            <div className="ed-col">
              <div className="ed-collbl">{s.left.label}</div>
              <div className="ed-quote">"{s.left.body.replace(/^"|"$/g, '')}"</div>
              <div className="ed-meta">{s.left.meta}</div>
            </div>
            <div className="ed-col is-right">
              <div className="ed-collbl">{s.right.label}</div>
              <div className="ed-quote">"{s.right.body.replace(/^"|"$/g, '')}"</div>
              <div className="ed-meta">{s.right.meta}</div>
            </div>
          </div>
        </>
      );
      break;

    case 'steps':
      modClass = 'ed-steps';
      body = (
        <>
          <div className="ed-eyebrow">{s.eyebrow}</div>
          <h1 className="ed-h1">{s.headline}</h1>
          <div>
            {s.steps.map((it, i) => (
              <div className="ed-step" key={i}>
                <div className="ed-n">{it.n}</div>
                <div>
                  <div className="ed-t">{it.t}</div>
                  <div className="ed-d">{it.d}</div>
                </div>
              </div>
            ))}
          </div>
        </>
      );
      break;

    case 'feature':
      modClass = 'ed-feature';
      body = (
        <>
          <div className="ed-eyebrow">{s.eyebrow}</div>
          <div className="ed-fhead">
            <div className="ed-fmark">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--copper-light)" strokeWidth="1.5">
                <path d="M13 2L3 14h7v8l10-12h-7l1-8z" strokeLinejoin="round" />
              </svg>
            </div>
            <h1 className="ed-h1">{s.headline}</h1>
          </div>
          <div className="ed-fbody">{s.body}</div>
          <div className="ed-metric">
            <div className="ed-mv">{s.metric}</div>
            <div className="ed-ml">{s.metricLabel}</div>
          </div>
        </>
      );
      break;

    case 'quote':
      modClass = 'ed-quote-s';
      body = (
        <>
          <div className="ed-mark">"</div>
          <div className="ed-q">{s.quote}</div>
          <div className="ed-attrib">
            <div className="ed-avatar" />
            <div>
              <div className="ed-aname">{s.attrib}</div>
              <div className="ed-arole">{s.role}</div>
            </div>
          </div>
        </>
      );
      break;

    case 'cta':
      modClass = 'ed-cta';
      body = (
        <>
          <div className="ed-eyebrow">{s.eyebrow}</div>
          <h1 className="ed-h1">{s.headline}</h1>
          <div className="ed-ctabody">{s.body}</div>
          <a className="ed-pill">
            {s.cta}
            <svg className="ed-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M5 12h14M12 5l7 7-7 7" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </a>
        </>
      );
      break;
  }

  return (
    <div className={`ed-slide ${modClass}`}>
      <div className="ed-body">{body}</div>
      <EdChrome index={index} total={total} />
    </div>
  );
}

window.EditorialSlide = EditorialSlide;
