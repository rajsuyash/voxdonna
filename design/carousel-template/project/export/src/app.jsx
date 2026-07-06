// ============================================================
// app.jsx — wires the 3 directions into a DesignCanvas
// ============================================================

const { useState, useEffect } = React;

function DirectionRow({ id, title, subtitle, RenderComponent, slides }) {
  return (
    <DCSection id={id} title={title} subtitle={subtitle}>
      {slides.map((slide, i) => (
        <DCArtboard
          key={i}
          id={`${id}-${i + 1}`}
          label={`${String(i + 1).padStart(2, '0')} · ${slide.layout}`}
          width={1080}
          height={1080}
        >
          <RenderComponent slide={slide} index={i} total={slides.length} />
        </DCArtboard>
      ))}
    </DCSection>
  );
}

function App() {
  const slides = window.CAROUSEL.slides;

  return (
    <DesignCanvas>
      <DCSection
        id="readme"
        title="Voxdonna Carousel Template"
        subtitle={`Three directions · 1080×1080 · ${slides.length} slides each · LinkedIn + Instagram ready`}
      >
        <DCArtboard
          id="readme-card"
          label="How to use this template"
          width={1080}
          height={1080}
        >
          <Readme />
        </DCArtboard>
      </DCSection>

      <DirectionRow
        id="editorial"
        title="A · Editorial"
        subtitle="Restrained. Big Inter type, a single copper hairline, generous whitespace. The Bloomberg / FT cover-story mood."
        RenderComponent={EditorialSlide}
        slides={slides}
      />

      <DirectionRow
        id="operator"
        title="B · Operator"
        subtitle="Mono-led, structured, spec-sheet aesthetic. Filename header, bracketed indices, hairline grid. Leans into Voxdonna's operator-first voice."
        RenderComponent={OperatorSlide}
        slides={slides}
      />

      <DirectionRow
        id="marquee"
        title="C · Marquee"
        subtitle="Bold, graphic, premium. 800-weight display type, copper glows, gradient accents. The brand-campaign mood."
        RenderComponent={MarqueeSlide}
        slides={slides}
      />
    </DesignCanvas>
  );
}

// ── Readme slide ───────────────────────────────────────────
function Readme() {
  return (
    <div style={{
      width: 1080, height: 1080, background: '#000',
      color: 'var(--fg-1)', fontFamily: 'var(--font-sans)',
      padding: 80, boxSizing: 'border-box',
      display: 'flex', flexDirection: 'column', gap: 28,
      position: 'relative', overflow: 'hidden',
    }}>
      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: 16, fontWeight: 600,
        letterSpacing: '0.2em', textTransform: 'uppercase',
        color: 'var(--copper)',
      }}>HANDOFF / README</div>

      <h1 style={{
        fontSize: 64, fontWeight: 700, letterSpacing: '-0.035em',
        lineHeight: 1.0, margin: 0, maxWidth: 880,
      }}>How to ship a carousel<br />with this template.</h1>

      <div style={{ fontSize: 20, color: 'var(--fg-3)', lineHeight: 1.5,
                     fontWeight: 300, maxWidth: 880, marginTop: 4 }}>
        Three visual directions are laid out below. Pick one, swap the content,
        export to JPG or PDF. The whole template is a single HTML file plus
        three direction renderers.
      </div>

      <div style={{
        display: 'grid', gridTemplateColumns: 'auto 1fr',
        gap: '20px 28px', marginTop: 24, alignItems: 'baseline',
      }}>
        {[
          ['01', 'Edit content', <>Open <code style={codeS}>slide-data.js</code> and rewrite the <code style={codeS}>CAROUSEL.slides</code> array. Keep the <code style={codeS}>layout</code> keys — each one maps to a designed layout in every direction.</>],
          ['02', 'Pick a direction', <>In the URL, add <code style={codeS}>?only=editorial</code>, <code style={codeS}>?only=operator</code>, or <code style={codeS}>?only=marquee</code> to view a single direction at full size, one slide per page.</>],
          ['03', 'Export to JPG', <>With <code style={codeS}>?only=X</code> active, each slide is a separate <code style={codeS}>&lt;section&gt;</code>. Screenshot each one at 1080×1080 — that's your Instagram-ready set.</>],
          ['04', 'Export to PDF', <>From the same <code style={codeS}>?only=X</code> view, print to PDF. The print stylesheet emits one 1080×1080 page per slide — LinkedIn document-carousel ready.</>],
        ].map(([n, t, d]) => (
          <React.Fragment key={n}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 22, fontWeight: 500,
              color: 'var(--copper)', letterSpacing: '-0.02em',
            }}>{n}</div>
            <div>
              <div style={{ fontSize: 22, fontWeight: 600,
                             letterSpacing: '-0.015em', marginBottom: 4 }}>{t}</div>
              <div style={{ fontSize: 17, color: 'var(--fg-3)',
                             lineHeight: 1.5, fontWeight: 300 }}>{d}</div>
            </div>
          </React.Fragment>
        ))}
      </div>

      <div style={{
        marginTop: 'auto', paddingTop: 28,
        borderTop: '1px solid var(--border-1)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <img src={window.__resources.voxdonnaMark} style={{ width: 28, height: 28 }} alt="" />
          <span style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em' }}>
            Vox<span style={{ color: 'var(--copper)' }}>donna</span>
          </span>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 12,
            color: 'var(--fg-3)', letterSpacing: '0.14em',
            padding: '4px 10px', border: '1px solid var(--border-1)',
            borderRadius: 100, textTransform: 'uppercase', marginLeft: 8,
          }}>Carousel template · v1</span>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 14,
                       color: 'var(--fg-3)', letterSpacing: '0.14em' }}>
          1080 × 1080
        </div>
      </div>
    </div>
  );
}

const codeS = {
  fontFamily: 'var(--font-mono)',
  fontSize: '0.9em',
  background: 'var(--surface-4)',
  padding: '2px 8px',
  borderRadius: 4,
  color: 'var(--copper-light)',
};

// ── Filter mode: ?only=editorial|operator|marquee renders one direction
//    as plain stacked slides (for screenshotting / print-to-PDF).
function FilterMode({ direction }) {
  const slides = window.CAROUSEL.slides;
  const Render = {
    editorial: window.EditorialSlide,
    operator: window.OperatorSlide,
    marquee: window.MarqueeSlide,
  }[direction];

  if (!Render) return <div style={{ color: '#fff', padding: 40 }}>Unknown direction: {direction}</div>;

  return (
    <div className="export-stack">
      {slides.map((slide, i) => (
        <section className="export-slide" key={i} data-screen-label={`${String(i + 1).padStart(2, '0')} ${slide.layout}`}>
          <Render slide={slide} index={i} total={slides.length} />
        </section>
      ))}
    </div>
  );
}

const params = new URLSearchParams(window.location.search);
const only = params.get('only');

const root = ReactDOM.createRoot(document.getElementById('root'));
if (only) {
  root.render(<FilterMode direction={only} />);
} else {
  root.render(<App />);
}
