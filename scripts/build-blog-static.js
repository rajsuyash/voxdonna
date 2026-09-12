#!/usr/bin/env node
/**
 * Pre-render every blog post to a static HTML file.
 *
 * Why: blog-post.html builds the article in the browser, so a crawler that does
 * not run JavaScript sees 13 words and a canonical pointing at the blog index.
 * This writes blog/<lang>/<slug>.html with the article already in the HTML,
 * its own title, description, canonical, hreflang set and BlogPosting schema.
 *
 * The markdown converter is taken from blog-post.html itself, so the static
 * output matches what readers see today. Run: node scripts/build-blog-static.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SITE = 'https://voxdonna.com';
const LANGS = ['en', 'fr', 'it'];
const LANG_LABEL = { en: 'EN', fr: 'FR', it: 'IT' };

const tpl = fs.readFileSync(path.join(ROOT, 'blog-post.html'), 'utf8');

// Reuse the site's own converter rather than a second implementation.
const fnStart = tpl.indexOf('function mdToHtml');
const fnEnd = tpl.indexOf('// Render article from inline data');
if (fnStart < 0 || fnEnd < 0) throw new Error('cannot locate mdToHtml/parseFrontmatter in blog-post.html');
const { mdToHtml, parseFrontmatter } = new Function(
  tpl.slice(fnStart, fnEnd) + '\nreturn { mdToHtml: mdToHtml, parseFrontmatter: parseFrontmatter };')();

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

function postUrl(lang, slug) { return `${SITE}/blog/${lang}/${slug}.html`; }

function prettyDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return '';
  return `${MONTHS[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`;
}

/** Make relative links work from /blog/<lang>/ by rooting them. */
function rootRelative(html) {
  return html.replace(/(href|src)="(?!https?:|\/\/|\/|#|mailto:|tel:|data:|javascript:)([^"]+)"/g,
    (m, attr, url) => `${attr}="/${url}"`);
}

function buildPage(lang, slug, raw, siblings) {
  const { meta, body } = parseFrontmatter(raw);
  const title = meta.title || slug;
  const desc = meta.description || `Voxdonna AI article on ${title}`;
  const url = postUrl(lang, slug);
  const img = `${SITE}/og-image.png`;
  let h = tpl;

  // Strip the client-side renderer: it would overwrite the static article.
  h = h.replace('  <script src="blog-data.js"></script>\n', '');
  const sStart = h.indexOf('  <script>\n    // Parse query params');
  const sEnd = h.indexOf('</script>', sStart);
  if (sStart < 0 || sEnd < 0) throw new Error('cannot locate the renderer script');
  h = h.slice(0, sStart) + h.slice(sEnd + '</script>\n'.length);

  // Head
  h = h.replace('<html lang="en">', `<html lang="${lang}">`);
  h = h.replace(/<title>[^<]*<\/title>/, `<title>${esc(title)} — Voxdonna</title>`);
  h = h.replace(/<meta name="description" content="[^"]*">/, `<meta name="description" content="${esc(desc)}">`);
  h = h.replace(/(<link rel="canonical" id="canonical-tag" href=")[^"]*(")/, `$1${url}$2`);
  for (const L of LANGS) {
    const re = new RegExp(`(<link rel="alternate" id="hreflang-${L}" hreflang="${L}" href=")[^"]*(">)`);
    h = siblings[L]
      ? h.replace(re, `$1${postUrl(L, slug)}$2`)
      : h.replace(re, '');
  }
  h = h.replace(/(<link rel="alternate" id="hreflang-default" hreflang="x-default" href=")[^"]*(">)/,
    `$1${postUrl(siblings.en ? 'en' : lang, slug)}$2`);
  h = h.replace(/(<meta property="og:url" content=")[^"]*(" id="og-url">)/, `$1${url}$2`);
  h = h.replace(/(<meta property="og:title" content=")[^"]*(" id="og-title">)/, `$1${esc(title)}$2`);
  h = h.replace(/(<meta property="og:description" content=")[^"]*(" id="og-description">)/, `$1${esc(desc)}$2`);
  h = h.replace(/(<meta name="twitter:title" content=")[^"]*(" id="tw-title">)/, `$1${esc(title)}$2`);
  h = h.replace(/(<meta name="twitter:description" content=")[^"]*(" id="tw-description">)/, `$1${esc(desc)}$2`);

  const articleLd = {
    '@context': 'https://schema.org', '@type': 'BlogPosting',
    headline: title, description: desc, image: img, url,
    datePublished: meta.date || '', dateModified: meta.date || '', inLanguage: lang,
    author: { '@type': 'Organization', name: 'Voxdonna AI' },
    publisher: { '@type': 'Organization', name: 'Voxdonna AI',
      logo: { '@type': 'ImageObject', url: `${SITE}/favicon/apple-touch-icon.png` } },
    mainEntityOfPage: { '@type': 'WebPage', '@id': url },
    keywords: meta.keywords || '', articleSection: meta.category || 'Voice AI',
  };
  const crumbLd = {
    '@context': 'https://schema.org', '@type': 'BreadcrumbList',
    itemListElement: [
      { '@type': 'ListItem', position: 1, name: 'Home', item: `${SITE}/` },
      { '@type': 'ListItem', position: 2, name: 'Blog', item: `${SITE}/blog.html` },
      { '@type': 'ListItem', position: 3, name: title, item: url },
    ],
  };
  const ldBlock = `<script type="application/ld+json" id="article-ld">${JSON.stringify(articleLd)}</script>\n`
    + `  <script type="application/ld+json" id="breadcrumb-ld">${JSON.stringify(crumbLd)}</script>`;
  h = h.replace(/<script type="application\/ld\+json" id="article-ld">[\s\S]*?<\/script>/, ldBlock);

  // Language switcher, static
  const sw = LANGS.filter((L) => siblings[L]).map((L) =>
    `<a class="lang-btn${L === lang ? ' active' : ''}" href="${postUrl(L, slug).replace(SITE, '')}">${LANG_LABEL[L]}</a>`).join('');
  h = h.replace(/(<div[^>]*id="langSwitch"[^>]*>)([\s\S]*?)(<\/div>)/, `$1${sw}$3`);

  // Article
  const dateStr = prettyDate(meta.date);
  const hero = '<div class="article-hero"><div class="article-meta">'
    + (meta.category ? `<span class="article-category">${esc(meta.category)}</span>` : '')
    + (dateStr ? `<span class="article-date">${dateStr}</span>` : '')
    + (meta.readingTime ? `<span class="article-dot"></span><span class="article-read-time">${esc(meta.readingTime)} min read</span>` : '')
    + `</div><h1>${esc(title)}</h1>`
    + (meta.description ? `<p class="article-desc">${esc(meta.description)}</p>` : '')
    + '</div><div class="article-divider"></div>';
  // A few posts are authored as raw HTML and ship their own hero and H1.
  // Adding ours on top would duplicate both, so use theirs.
  const bringsOwnHero = /^\s*<div class="article-hero"/.test(body);
  const article = (bringsOwnHero ? '' : hero)
    + `<div class="article-content">${mdToHtml(body)}</div>`
    + '<div class="article-footer"><div class="article-footer-inner">'
    + '<a href="/blog.html" class="back-link"><svg viewBox="0 0 24 24"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> All articles</a>'
    + '</div></div>';
  h = h.replace(/<div id="articleContent">[\s\S]*?<\/div>\n/, `<div id="articleContent">${article}</div>\n`);

  return rootRelative(h);
}

// ---- run
const written = [];
const index = {};
for (const lang of LANGS) {
  const dir = path.join(ROOT, 'blog', lang);
  if (!fs.existsSync(dir)) continue;
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.md'))) {
    (index[f.replace(/\.md$/, '')] ||= {})[lang] = true;
  }
}
for (const lang of LANGS) {
  const dir = path.join(ROOT, 'blog', lang);
  if (!fs.existsSync(dir)) continue;
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.md'))) {
    const slug = f.replace(/\.md$/, '');
    const raw = fs.readFileSync(path.join(dir, f), 'utf8');
    const out = path.join(dir, `${slug}.html`);
    fs.writeFileSync(out, buildPage(lang, slug, raw, index[slug]), 'utf8');
    written.push(`blog/${lang}/${slug}.html`);
  }
}
console.log(`wrote ${written.length} static posts`);
fs.writeFileSync(path.join(ROOT, 'scripts', '.blog-static-manifest.json'),
  JSON.stringify({ generated: new Date().toISOString(), pages: written }, null, 1));
