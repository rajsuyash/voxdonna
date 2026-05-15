#!/usr/bin/env python3
"""
Patch demos.html: add a 'Copy share link' button to every demo card.
- Adds data-slug to each <article class="demo-card" ...>
- Injects a copy-link button in each card header
- Adds CSS for .demo-card-share
- Adds a clipboard JS handler
Idempotent: safe to re-run.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMOS = json.loads((ROOT / "scripts" / "demos.json").read_text())

# Apply slug overrides (must match build-shareable-demos.py)
OVERRIDES = {"order-status-amp-eta-tracking": "order-status-eta-tracking"}
for d in DEMOS:
    d["slug"] = OVERRIDES.get(d["slug"], d["slug"])

ID_TO_SLUG = {d["agent_id"]: d["slug"] for d in DEMOS}

demos_html = ROOT / "demos.html"
text = demos_html.read_text()

# 1) Add data-slug to each <article> by agent_id
def patch_article(m):
    agent_id = m.group(1)
    slug = ID_TO_SLUG.get(agent_id)
    if not slug:
        return m.group(0)
    if 'data-slug=' in m.group(0):  # already patched
        return m.group(0)
    return m.group(0).replace(
        f'data-agent-id="{agent_id}"',
        f'data-agent-id="{agent_id}" data-slug="{slug}"',
    )

text = re.sub(
    r'<article class="demo-card" data-agent-id="([^"]+)"[^>]*>',
    patch_article,
    text,
)

# 2) Inject share button into each demo-card-header (after lang span)
# Insert ONCE per card. Use a marker class to detect already-patched cards.
SHARE_BUTTON_HTML = """\
        <button type="button" class="demo-card-share" aria-label="Copy share link">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/></svg>
          <span>Copy link</span>
        </button>
"""

def patch_header(m):
    header = m.group(0)
    if "demo-card-share" in header:  # already patched
        return header
    # Insert button right after the lang span's closing </span>
    return re.sub(
        r'(<span class="demo-card-lang">[^<]+</span>)',
        r'\1\n' + SHARE_BUTTON_HTML.rstrip(),
        header,
        count=1,
    )

text = re.sub(
    r'<div class="demo-card-header">[\s\S]+?</div>',
    patch_header,
    text,
)

# 3) Add CSS for .demo-card-share (insert before .demo-card-title rule)
SHARE_CSS = """
    .demo-card-share {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: transparent;
      border: 1px solid rgba(255,255,255,0.1);
      color: rgba(255,255,255,0.55);
      padding: 5px 10px;
      border-radius: 999px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      letter-spacing: 0.04em;
      cursor: pointer;
      transition: border-color 0.2s, color 0.2s, background 0.2s;
    }
    .demo-card-share svg { width: 12px; height: 12px; }
    .demo-card-share:hover {
      border-color: rgba(193,127,89,0.5);
      color: var(--copper-light);
      background: rgba(193,127,89,0.06);
    }
    .demo-card-share.copied {
      border-color: rgba(92,184,92,0.6);
      color: #5cb85c;
      background: rgba(92,184,92,0.08);
    }
"""
if ".demo-card-share" not in text:
    text = text.replace(
        "    .demo-card-title {",
        SHARE_CSS + "    .demo-card-title {",
    )

# 4) Add JS clipboard handler at the bottom of the existing per-card script
SHARE_JS = """
    // Copy-share-link handler (added by scripts/add-share-links.py)
    document.querySelectorAll('.demo-card-share').forEach(function(btn) {
      btn.addEventListener('click', function(ev) {
        ev.stopPropagation();
        const card = btn.closest('.demo-card');
        const slug = card && card.getAttribute('data-slug');
        if (!slug) return;
        const url = 'https://voxdonna.com/demo/' + slug + '.html';
        const fallbackLabel = btn.querySelector('span');
        const origLabel = fallbackLabel ? fallbackLabel.textContent : '';
        function flash(msg) {
          if (fallbackLabel) fallbackLabel.textContent = msg;
          btn.classList.add('copied');
          setTimeout(function() {
            if (fallbackLabel) fallbackLabel.textContent = origLabel;
            btn.classList.remove('copied');
          }, 1800);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(url).then(function() { flash('Copied!'); })
            .catch(function() { window.prompt('Copy this link:', url); });
        } else {
          window.prompt('Copy this link:', url);
        }
      });
    });
"""

if "Copy-share-link handler" not in text:
    text = text.replace(
        "    });\n  </script>\n</body>",
        "    });\n" + SHARE_JS + "  </script>\n</body>",
    )

demos_html.write_text(text)
print(f"Patched demos.html with {len(ID_TO_SLUG)} share-link buttons.")
