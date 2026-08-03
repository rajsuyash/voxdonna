/* Claude Enterprise Training — shared runtime.
   Loaded by every page. Owns: org config, markdown rendering, progress state. */

(function (global) {
  'use strict';

  var SLUG_RE = /^[a-z0-9-]{1,40}$/;
  var DAY = 86400000;
  var DEFAULT_ORG = 'demo';   // slug-legal so the default surface records like any client

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


  /* ---------------- syntax highlighting ---------------- */

  // Deliberately small: comments, strings, numbers, keywords. No CDN, no library.
  // Bare fences — which is what the guide's 30 ASCII diagrams use — get nothing.
  var KEYWORDS = {
    bash: 'if then else fi for in do done while case esac function return export local echo curl npm npx pip git sudo cd ls cat sed awk grep source set unset',
    python: 'def class return import from as if elif else for while try except finally with lambda yield async await pass raise in not and or None True False self print',
    javascript: 'const let var function return if else for while class new async await import export from try catch finally throw typeof instanceof this null undefined true false',
    typescript: 'const let var function return if else for while class new async await import export from interface type enum implements extends public private readonly null undefined true false',
    json: 'true false null',
    php: 'function return if else elseif foreach for while class new public private protected static echo require include use namespace try catch finally throw null true false array'
  };
  var ALIAS = { js: 'javascript', ts: 'typescript', sh: 'bash', shell: 'bash', py: 'python',
                yaml: 'bash', yml: 'bash', jsonc: 'json', console: 'bash' };
  var HASH_COMMENT = { bash: 1, python: 1 };

  function highlight(escaped, lang) {
    var key = ALIAS[lang] || lang;
    if (!KEYWORDS[key]) return escaped;

    var comment = HASH_COMMENT[key] ? '#[^\\n]*' : '\\/\\/[^\\n]*|\\/\\*[\\s\\S]*?\\*\\/';
    var re = new RegExp(
      '(' + comment + ')' +
      '|("(?:[^"\\\\\\n]|\\\\.)*"|\'(?:[^\'\\\\\\n]|\\\\.)*\')' +
      '|\\b(\\d+(?:\\.\\d+)?)\\b' +
      '|\\b(' + KEYWORDS[key].split(' ').join('|') + ')\\b', 'g');

    return escaped.replace(re, function (m, c, str, num, kw) {
      if (c) return '<span class="t-c">' + c + '</span>';
      if (str) return '<span class="t-s">' + str + '</span>';
      if (num) return '<span class="t-n">' + num + '</span>';
      if (kw) return '<span class="t-k">' + kw + '</span>';
      return m;
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
  var CITE_RE = /\(((?:Anthropic|docs\.anthropic\.com|anthropic\.com)[^()]{0,90})\)/g;

  function mdToHtml(md, opts) {
    opts = opts || {};
    var headings = [];
    var seenIds = opts.seenIds || {};
    var fences = [];
    var inline = [];
    var blocks = [];

    // 1. Callout / exercise blocks the build emitted. Bodies render recursively
    //    so they can hold their own lists, code, and emphasis.
    var html = md.replace(/^:::(\w+)(?:[ \t]+([^\n]*))?\n([\s\S]*?)\n:::[ \t]*$/gm,
      function (_, kind, title, body) {
        var head = title ? '<div class="cal-h">' + escapeHtml(title.trim()) + '</div>' : '';
        blocks.push('<aside class="cal cal-' + escapeHtml(kind) + '">' + head +
          mdToHtml(body.trim(), { seenIds: seenIds }) + '</aside>');
        return '\u0001B' + (blocks.length - 1) + '\u0001';
      });

    // 2. Pull fenced code out before anything else touches it.
    html = html.replace(/```([\w-]*)\n([\s\S]*?)```/g, function (_, lang, code) {
      var body = escapeHtml(code.replace(/\n$/, ''));
      var label = lang || 'text';
      fences.push(
        '<figure class="code"><figcaption class="code-bar"><span>' + escapeHtml(label) +
        '</span><button type="button" class="code-copy" data-copy>Copy</button></figcaption>' +
        '<pre><code>' + highlight(body, lang) + '</code></pre></figure>');
      return '\u0001F' + (fences.length - 1) + '\u0001';
    });

    // 3. Everything left is prose — escape it, then build markup on top.
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
      .replace(/^&gt; (.*)$/gm, '<blockquote>$1</blockquote>')
      // 332 source citations: keep every one, but stop them shouting mid-sentence.
      .replace(CITE_RE, function (_, body) { return '<span class="cite">' + body + '</span>'; })
      .replace(/\u26a0/g, '<span class="flag" title="Volatile \u2014 verify before quoting">\u26a0</span>');

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
    html = html.replace(/\u0001B(\d+)\u0001/g, function (_, i) { return blocks[+i]; });

    if (opts.headings) opts.headings.push.apply(opts.headings, headings);
    return html;
  }

  // One delegated listener per container serves every code block's Copy button.
  function wireCopy(container) {
    container.addEventListener('click', function (e) {
      var btn = e.target.closest && e.target.closest('[data-copy]');
      if (!btn) return;
      var code = btn.closest('.code').querySelector('code');
      var text = code ? code.textContent : '';
      var done = function () {
        btn.textContent = 'Copied';
        setTimeout(function () { btn.textContent = 'Copy'; }, 1600);
      };
      if (global.navigator.clipboard) {
        global.navigator.clipboard.writeText(text).then(done, function () { btn.textContent = 'Failed'; });
      } else {
        var ta = document.createElement('textarea');
        ta.value = text; document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); done(); } catch (err) { btn.textContent = 'Failed'; }
        document.body.removeChild(ta);
      }
    });
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
        s.review = s.review && typeof s.review === 'object' ? s.review : {};
        return s;
      }
    } catch (e) { /* corrupt or disabled storage — start clean */ }
    return { trainee: null, done: [], sections: {}, review: {}, exam: null };
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
        review: state.review,
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

  function moduleOfLesson(manifest, lessonId) {
    for (var i = 0; i < manifest.modules.length; i++) {
      var m = manifest.modules[i];
      for (var j = 0; j < m.lessons.length; j++) {
        if (m.lessons[j].id === lessonId) return { module: m, lesson: m.lessons[j], index: j };
      }
    }
    return null;
  }

  // The assigned curriculum, flattened into one ordered lesson walk.
  function lessonWalk(org, manifest) {
    var out = [];
    requiredModules(org, manifest).forEach(function (id) {
      var m = moduleById(manifest, id);
      if (!m) return;
      m.lessons.forEach(function (l) { out.push({ module: m, lesson: l }); });
    });
    return out;
  }

  function isDone(state, lessonId) { return state.done.indexOf(lessonId) > -1; }

  function moduleProgress(state, module) {
    var done = module.lessons.filter(function (l) { return isDone(state, l.id); }).length;
    return { done: done, total: module.lessons.length };
  }

  /* ---------------- spaced repetition ---------------- */

  // A miss schedules tomorrow; each later correct recall walks the interval
  // ladder. Clearing the last interval retires the question from the queue.
  function scheduleReview(state, questionNumber, correct, manifest, now) {
    var steps = (manifest.review && manifest.review.intervalDays) || [1, 3, 7, 21];
    var key = String(questionNumber);
    var entry = state.review[key];
    var t = now || Date.now();

    if (!correct) {
      state.review[key] = { step: 0, due: t + steps[0] * DAY };
      return;
    }
    if (!entry) return;                        // never missed — nothing to reinforce
    var step = (entry.step || 0) + 1;
    if (step >= steps.length) { delete state.review[key]; return; }
    state.review[key] = { step: step, due: t + steps[step] * DAY };
  }

  function dueQuestions(state, now) {
    var t = now || Date.now();
    var review = state.review || {};
    return Object.keys(review)
      .filter(function (k) { return (review[k].due || 0) <= t; })
      .map(Number)
      .sort(function (a, b) { return a - b; });
  }

  /* ---------------- view helpers ---------------- */

  function pct(done, total) {
    return total ? Math.round((done / total) * 100) : 0;
  }

  function fmtMinutes(total) {
    if (!total) return '0 min';
    return total >= 60 ? (total / 60).toFixed(1) + ' h' : total + ' min';
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
    highlight: highlight, wireCopy: wireCopy,
    moduleOfLesson: moduleOfLesson, lessonWalk: lessonWalk,
    isDone: isDone, moduleProgress: moduleProgress,
    scheduleReview: scheduleReview, dueQuestions: dueQuestions, fmtMinutes: fmtMinutes,
    loadState: loadState, saveState: saveState, sync: sync, newId: newId,
    requiredModules: requiredModules, moduleById: moduleById,
    pct: pct, el: el, link: link, slugify: slugify
  };
})(window);
