/* Claude Enterprise Training — shared runtime.
   Loaded by every page. Owns: org config, markdown rendering, progress state. */

(function (global) {
  'use strict';

  var SLUG_RE = /^[a-z0-9-]{1,40}$/;
  var DEFAULT_ORG = '_template';

  /* ---------------- url + org ---------------- */

  function param(name) {
    return new URLSearchParams(location.search).get(name) || '';
  }

  function orgSlug() {
    var s = param('org').toLowerCase();
    return SLUG_RE.test(s) ? s : DEFAULT_ORG;
  }

  function version() {
    // Cache-bust content fetches with the same stamp the HTML asset refs carry.
    var tag = document.querySelector('script[src*="app.js?v="]');
    var m = tag && tag.getAttribute('src').match(/\?v=([\w.]+)/);
    return m ? m[1] : 'dev';
  }

  function getJSON(url) {
    return fetch(url + (url.indexOf('?') > -1 ? '&' : '?') + 'v=' + version()).then(function (r) {
      if (!r.ok) throw new Error(url + ' -> ' + r.status);
      return r.json();
    });
  }

  function getText(url) {
    return fetch(url + '?v=' + version()).then(function (r) {
      if (!r.ok) throw new Error(url + ' -> ' + r.status);
      return r.text();
    });
  }

  function hexToRgba(hex, alpha) {
    var h = String(hex || '').replace('#', '');
    if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
    if (!/^[0-9a-fA-F]{6}$/.test(h)) return null;
    var n = parseInt(h, 16);
    return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + alpha + ')';
  }

  function applyBrand(org) {
    var root = document.documentElement.style;
    if (hexToRgba(org.accent, 1)) {
      root.setProperty('--accent', org.accent);
      root.setProperty('--accent-soft', hexToRgba(org.accent, 0.12));
      root.setProperty('--accent-line', hexToRgba(org.accent, 0.28));
      root.setProperty('--accent-light', org.accentLight || org.accent);
    }
    document.title = org.companyName + ' — Claude Enterprise Training';

    document.querySelectorAll('[data-brand-name]').forEach(function (el) {
      el.textContent = org.companyName;
    });
    document.querySelectorAll('[data-brand-logo]').forEach(function (el) {
      if (org.logo) { el.src = org.logo; el.alt = org.companyName; el.hidden = false; }
      else { el.remove(); }
    });
  }

  /* ---------------- markdown ---------------- */

  function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function slugify(s) {
    return s.toLowerCase().replace(/<[^>]*>/g, '').replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '').slice(0, 60);
  }

  // Ported from blog-post.html and extended: fenced code blocks, full HTML
  // escaping (the guide is full of literal <example> / <system> XML tags that
  // would otherwise be swallowed by the browser), and heading anchors.
  function mdToHtml(md, opts) {
    opts = opts || {};
    var headings = [];
    var seenIds = {};
    var fences = [];
    var inline = [];

    // 1. Pull fenced code out before anything else touches it.
    var html = md.replace(/```([\w-]*)\n([\s\S]*?)```/g, function (_, lang, code) {
      fences.push('<pre><code class="lang-' + escapeHtml(lang) + '">' +
        escapeHtml(code.replace(/\n$/, '')) + '</code></pre>');
      return '\u0001F' + (fences.length - 1) + '\u0001';
    });

    // 2. Everything left is prose — escape it, then build markup on top.
    html = escapeHtml(html);

    html = html.replace(/`([^`\n]+)`/g, function (_, code) {
      inline.push('<code>' + code + '</code>');
      return '\u0001I' + (inline.length - 1) + '\u0001';
    });

    html = html
      .replace(/^#### (.+)$/gm, function (_, t) { return '<h4>' + t + '</h4>'; })
      // h2 and h3 share one pass so headings land in document order, and ids are
      // de-duplicated — repeated headings across a module would break ToC links.
      .replace(/^(#{2,3}) (.+)$/gm, function (_, hashes, t) {
        var level = hashes.length;
        var base = slugify(t) || 'section';
        var id = base, n = 2;
        while (seenIds[id]) { id = base + '-' + n++; }
        seenIds[id] = true;
        headings.push({ level: level, text: t, id: id });
        return '<h' + level + ' id="' + id + '">' + t + '</h' + level + '>';
      })
      .replace(/^# (.+)$/gm, '<h1>$1</h1>')
      .replace(/^---$/gm, '<hr>')
      .replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/(^|[\s(])\*([^*\n]+)\*(?=[\s.,;:)]|$)/g, '$1<em>$2</em>')
      .replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1">')
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" rel="noopener">$1</a>')
      .replace(/^&gt; (.*)$/gm, '<blockquote>$1</blockquote>');

    html = html.replace(/(^\|.+\|\n?)+/gm, function (table) {
      var rows = table.trim().split('\n');
      if (rows.length < 2) return table;
      var out = '<div class="table-scroll"><table>', head = true;
      rows.forEach(function (row) {
        if (/^\|[\s\-:|]+\|$/.test(row.trim())) { head = false; return; }
        var cells = row.trim().replace(/^\||\|$/g, '').split('|');
        var tag = head ? 'th' : 'td';
        out += '<tr>' + cells.map(function (c) {
          return '<' + tag + '>' + c.trim() + '</' + tag + '>';
        }).join('') + '</tr>';
      });
      return out + '</table></div>';
    });

    html = html.replace(/(^[-*] .+\n?)+/gm, function (block) {
      return '<ul>' + block.trim().split('\n').map(function (l) {
        return '<li>' + l.replace(/^[-*] /, '') + '</li>';
      }).join('') + '</ul>';
    });

    html = html.replace(/(^\d+\. .+\n?)+/gm, function (block) {
      return '<ol>' + block.trim().split('\n').map(function (l) {
        return '<li>' + l.replace(/^\d+\. /, '') + '</li>';
      }).join('') + '</ol>';
    });

    html = html.split('\n\n').map(function (block) {
      block = block.trim();
      if (!block) return '';
      if (block.charAt(0) === '<' || block.charAt(0) === '\u0001') return block;
      return '<p>' + block.replace(/\n/g, '<br>') + '</p>';
    }).join('\n');

    html = html.replace(/<\/blockquote>\s*<blockquote>/g, '<br>');
    html = html.replace(/\u0001I(\d+)\u0001/g, function (_, i) { return inline[+i]; });
    html = html.replace(/\u0001F(\d+)\u0001/g, function (_, i) { return fences[+i]; });

    if (opts.headings) opts.headings.push.apply(opts.headings, headings);
    return html;
  }

  /* ---------------- progress ---------------- */

  function stateKey(slug) { return 'vd-train:' + slug; }

  function loadState(slug) {
    try {
      var raw = localStorage.getItem(stateKey(slug));
      var s = raw ? JSON.parse(raw) : null;
      if (s && typeof s === 'object') {
        s.done = Array.isArray(s.done) ? s.done : [];
        s.sections = s.sections && typeof s.sections === 'object' ? s.sections : {};
        return s;
      }
    } catch (e) { /* corrupt or disabled storage — start clean */ }
    return { trainee: null, done: [], sections: {}, exam: null };
  }

  function saveState(slug, state) {
    try { localStorage.setItem(stateKey(slug), JSON.stringify(state)); }
    catch (e) { /* private mode / quota — session-only progress is acceptable */ }
  }

  // Best-effort mirror to the server. Training must never block on the network,
  // so every failure here is swallowed; localStorage stays the source of truth.
  function sync(slug, action, state) {
    if (!state.trainee || !state.trainee.id) return Promise.resolve(null);
    return fetch('api/progress.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        org: slug,
        action: action,
        trainee: state.trainee,
        done: state.done,
        sections: state.sections,
        exam: state.exam
      })
    }).then(function (r) { return r.ok ? r.json() : null; })
      .catch(function () { return null; });
  }

  function newId() {
    if (global.crypto && global.crypto.randomUUID) return global.crypto.randomUUID();
    return 'id-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
  }

  /* ---------------- shared view helpers ---------------- */

  function requiredModules(org, manifest) {
    if (Array.isArray(org.modules) && org.modules.length) {
      return org.modules.filter(function (id) {
        return manifest.modules.some(function (m) { return m.id === id; });
      });
    }
    var path = manifest.paths[org.learningPath] || manifest.paths['certification'];
    return path.modules.slice();
  }

  function moduleById(manifest, id) {
    return manifest.modules.filter(function (m) { return m.id === id; })[0] || null;
  }

  function pct(done, total) {
    return total ? Math.round((done / total) * 100) : 0;
  }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function link(page, slug, extra) {
    return page + '?org=' + encodeURIComponent(slug) + (extra || '');
  }

  function boot() {
    var slug = orgSlug();
    return getJSON('orgs/' + slug + '.json')
      .catch(function () { return getJSON('orgs/' + DEFAULT_ORG + '.json'); })
      .then(function (org) {
        org.slug = org.slug || slug;
        applyBrand(org);
        return getJSON('content/manifest.json').then(function (manifest) {
          return { slug: org.slug, org: org, manifest: manifest, state: loadState(org.slug) };
        });
      });
  }

  global.Train = {
    boot: boot, param: param, orgSlug: orgSlug, version: version,
    getJSON: getJSON, getText: getText, mdToHtml: mdToHtml, escapeHtml: escapeHtml,
    loadState: loadState, saveState: saveState, sync: sync, newId: newId,
    requiredModules: requiredModules, moduleById: moduleById,
    pct: pct, el: el, link: link, slugify: slugify
  };
})(window);
