#!/usr/bin/env node
/*
 * Keep blog.html's "Latest" card pointing at the newest post, per language.
 *
 * The three featured cards were hand-written once and nothing has updated them since:
 * publish-blog-post.js inserts a listing card and a sitemap entry, but never touches
 * the featured block, so "Latest" sat six months behind the grid directly under it.
 * This derives each card from the newest post's own frontmatter instead.
 *
 *   node scripts/refresh-blog-featured.js            # report, write nothing
 *   node scripts/refresh-blog-featured.js --write
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const WRITE = process.argv.includes('--write');
const LANGS = ['en', 'fr', 'it'];
const BADGE = { en: 'Latest', fr: 'Dernier', it: 'Ultimo' };
const READ = { en: n => `${n} min read`, fr: n => `${n} min de lecture`, it: n => `${n} min di lettura` };
const LOCALE = { en: 'en-US', fr: 'fr-FR', it: 'it-IT' };

function frontmatter(file) {
  const raw = fs.readFileSync(file, 'utf8');
  const m = raw.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!m) return null;
  const out = {};
  for (const line of m[1].split('\n')) {
    const kv = line.match(/^(\w+):\s*"?(.*?)"?\s*$/);
    if (kv) out[kv[1]] = kv[2];
  }
  return out.date && out.title ? out : null;
}

// "12 mars 2026" / "12 mar 2026" / "Mar 12, 2026" — match what each card already used
function humanDate(iso, lang) {
  const d = new Date(iso + 'T00:00:00Z');
  if (isNaN(d)) return iso;
  const opts = { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' };
  return new Intl.DateTimeFormat(LOCALE[lang], opts).format(d);
}

const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function newest(lang) {
  const dir = path.join(ROOT, 'blog', lang);
  if (!fs.existsSync(dir)) return null;
  const posts = fs.readdirSync(dir).filter(f => f.endsWith('.md')).map(f => {
    const fm = frontmatter(path.join(dir, f));
    return fm && { slug: f.replace(/\.md$/, ''), ...fm };
  }).filter(Boolean);
  if (!posts.length) return null;
  posts.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
  return posts[0];
}

let changed = 0, checked = 0;
let html = fs.readFileSync(path.join(ROOT, 'blog.html'), 'utf8');

for (const lang of LANGS) {
  const p = newest(lang);
  if (!p) { console.log(`  ${lang}: no dated posts`); continue; }
  checked++;

  // the whole card, so href, title, description and meta can never drift apart
  const re = new RegExp(
    `(<a class="blog-featured-card blog-item" data-lang="${lang}"[^>]*href=")([^"]*)("[^>]*>)` +
    `([\\s\\S]*?)(</a>)`);
  const m = html.match(re);
  if (!m) { console.log(`  ${lang}: featured card not found — markup changed?`); continue; }

  const href = `/blog/${lang}/${p.slug}.html`;
  if (!fs.existsSync(path.join(ROOT, 'blog', lang, `${p.slug}.html`))) {
    console.log(`  ${lang}: ${p.slug}.html not built yet — run build-blog-static.js first`);
    continue;
  }

  let inner = m[4];
  inner = inner.replace(/(<div class="blog-featured-badge">)[^<]*(<\/div>)/, `$1${BADGE[lang]}$2`);
  inner = inner.replace(/(<h2>)[\s\S]*?(<\/h2>)/, `$1${esc(p.title)}$2`);
  inner = inner.replace(/(<p>)[\s\S]*?(<\/p>)/, `$1${esc(p.description || '')}$2`);
  inner = inner.replace(
    /(<div class="blog-featured-meta">)[\s\S]*?(<\/div>)/,
    `$1\n        <span>${esc(p.category || '')}</span>\n` +
    `        <span>${humanDate(p.date, lang)}</span>\n` +
    `        <span>${READ[lang](p.readingTime || '')}</span>\n      $2`);

  const rebuilt = m[1] + href + m[3] + inner + m[5];
  if (rebuilt !== m[0]) {
    html = html.replace(m[0], rebuilt);
    changed++;
    console.log(`  ${lang}: ${m[2]}\n      -> ${href}  (${p.date})`);
  } else {
    console.log(`  ${lang}: already current (${p.slug}, ${p.date})`);
  }
}

if (changed && WRITE) {
  fs.writeFileSync(path.join(ROOT, 'blog.html'), html);
  // re-read what was written, so a bad splice is caught here and not in a browser
  const back = fs.readFileSync(path.join(ROOT, 'blog.html'), 'utf8');
  const cards = (back.match(/<a class="blog-featured-card blog-item"/g) || []).length;
  if (cards !== LANGS.length) {
    console.error(`FAIL: ${cards} featured cards after write, expected ${LANGS.length}`);
    process.exit(1);
  }
}
console.log(`\n${changed} of ${checked} card(s) ${WRITE && changed ? 'updated' : 'would change'}`);
