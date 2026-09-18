#!/usr/bin/env node
/*
 * Voxdonna blog publisher — turns a markdown file into a fully published post.
 *
 * Given an existing  blog/<lang>/<slug>.md  (frontmatter + markdown body), this script:
 *   1. validates the frontmatter,
 *   2. inserts a listing card into blog.html (so the post shows in the index),
 *   3. adds a <url> entry to sitemap.xml (SEO),
 *   4. (optional) git add + commit + push  ->  Hostinger webhook auto-deploys.
 *
 * The post itself renders straight from the .md file via blog-post.html's fetch fallback,
 * so NO edit to the 615 KB blog-data.js is needed.
 *
 * Usage:
 *   node scripts/publish-blog-post.js <slug> [--lang en] [--dry-run] [--publish]
 *
 *   --dry-run   print what would change, write nothing
 *   --publish   after editing, git commit + push (default: just edit files for review)
 *
 * Example:
 *   node scripts/publish-blog-post.js whatsapp-ai-jewellery-concierge --publish
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
const slug = args.find(a => !a.startsWith('--'));
const lang = (args[args.indexOf('--lang') + 1] && args.includes('--lang')) ? args[args.indexOf('--lang') + 1] : 'en';
const DRY = args.includes('--dry-run');
const PUBLISH = args.includes('--publish');

if (!slug) { console.error('ERROR: pass a slug.  e.g. node scripts/publish-blog-post.js my-post-slug'); process.exit(1); }

const mdPath = path.join(ROOT, 'blog', lang, `${slug}.md`);
if (!fs.existsSync(mdPath)) { console.error(`ERROR: ${path.relative(ROOT, mdPath)} not found. Create the markdown file first.`); process.exit(1); }

// ---- parse frontmatter ----
const raw = fs.readFileSync(mdPath, 'utf8');
const fm = raw.match(/^---\s*\n([\s\S]*?)\n---/);
if (!fm) { console.error('ERROR: no --- frontmatter --- block at top of the .md file.'); process.exit(1); }
const meta = {};
fm[1].split('\n').forEach(line => {
  const m = line.match(/^(\w+):\s*(.*)$/);
  if (m) meta[m[1]] = m[2].trim().replace(/^["']|["']$/g, '');
});
const required = ['title', 'description', 'date', 'category', 'readingTime'];
const missing = required.filter(k => !meta[k]);
if (missing.length) { console.error(`ERROR: frontmatter missing: ${missing.join(', ')}`); process.exit(1); }

const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const niceDate = (() => {
  const d = new Date(meta.date + 'T00:00:00Z');
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
})();

// ---- 1) listing card for blog.html ----
const card =
`    <a class="blog-card blog-item" data-lang="${lang}" href="/blog/${lang}/${slug}.html">
      <div class="blog-card-meta">
        <span class="blog-card-category">${esc(meta.category)}</span>
        <span class="blog-card-date">${niceDate}</span>
      </div>
      <h3>${esc(meta.title)}</h3>
      <p class="blog-excerpt">${esc(meta.description)}</p>
      <div class="blog-card-footer">
        <span class="blog-read-time">${meta.readingTime} min read</span>
        <div class="blog-arrow"><svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg></div>
      </div>
    </a>`;

// ---- 2) sitemap entry ----
// Static path, not blog-post.html?post=... — every other blog entry in the sitemap
// uses the static form and the query-string form 301s to it, so the old template put
// a redirecting URL in the sitemap. hreflang is emitted only for translations that
// actually exist on disk; declaring fr/it for an English-only post points Google at 404s.
const langsPresent = ['en', 'fr', 'it'].filter(l =>
  fs.existsSync(path.join(ROOT, 'blog', l, `${slug}.md`)));
const alts = langsPresent.map(l =>
  `<xhtml:link rel="alternate" hreflang="${l}" href="https://voxdonna.com/blog/${l}/${slug}.html"/>`).join('');
const xdefault = langsPresent.includes('en')
  ? `<xhtml:link rel="alternate" hreflang="x-default" href="https://voxdonna.com/blog/en/${slug}.html"/>` : '';
const sm = `  <url><loc>https://voxdonna.com/blog/${lang}/${slug}.html</loc><lastmod>${meta.date}</lastmod><changefreq>monthly</changefreq><priority>0.7</priority>${langsPresent.length > 1 ? alts + xdefault : ''}</url>`;

// ---- apply edits ----
const blogHtmlPath = path.join(ROOT, 'blog.html');
const sitemapPath = path.join(ROOT, 'sitemap.xml');
let blogHtml = fs.readFileSync(blogHtmlPath, 'utf8');
let sitemap = fs.existsSync(sitemapPath) ? fs.readFileSync(sitemapPath, 'utf8') : null;
let sitemapChanged = false;

const already = blogHtml.includes(`/blog/${lang}/${slug}.html"`);
if (already) {
  console.log(`NOTE: a card for "${slug}" (${lang}) already exists in blog.html — skipping card insert.`);
} else {
  // insert as the newest card: right before the first existing card of this language
  const anchor = blogHtml.match(new RegExp(`[ \\t]*<a class="blog-card blog-item" data-lang="${lang}"`));
  if (!anchor) { console.error(`ERROR: could not find an existing data-lang="${lang}" card to anchor against.`); process.exit(1); }
  blogHtml = blogHtml.slice(0, anchor.index) + card + '\n\n' + blogHtml.slice(anchor.index);
}

if (sitemap) {
  if (sitemap.includes(`post=${slug}&amp;lang=en`)) {
    console.log(`NOTE: sitemap already has "${slug}" — skipping.`);
  } else {
    // the sitemap moved to static /blog/<lang>/<slug>.html entries; anchoring on the
    // retired blog-post.html?post= form matched nothing and silently skipped every insert
    const smAnchor = sitemap.search(/[ \t]*<url>\s*\n?\s*<loc>https:\/\/voxdonna\.com\/blog\/(en|fr|it)\//);
    if (smAnchor >= 0) {
      sitemap = sitemap.slice(0, smAnchor) + sm + '\n' + sitemap.slice(smAnchor);
      sitemapChanged = true;
    } else if (sitemap.includes('</urlset>')) {
      sitemap = sitemap.replace('</urlset>', sm + '\n</urlset>');
      sitemapChanged = true;
    } else {
      console.log('NOTE: could not place the <url> entry in sitemap.xml — add it manually.');
    }
  }
}

console.log(`\nPost:     ${meta.title}`);
console.log(`Slug:     ${slug}   Lang: ${lang}   Date: ${meta.date} (${niceDate})`);
console.log(`Category: ${meta.category}   Reading time: ${meta.readingTime} min`);
console.log(`URL:      https://voxdonna.com/blog/${lang}/${slug}.html`);

if (DRY) {
  console.log('\n--- [dry-run] listing card that WOULD be inserted into blog.html ---\n');
  console.log(card);
  console.log('\n--- [dry-run] sitemap entry that WOULD be inserted ---\n');
  console.log(sm);
  console.log('\n(dry-run: no files written)');
  process.exit(0);
}

fs.writeFileSync(blogHtmlPath, blogHtml);
if (sitemap) fs.writeFileSync(sitemapPath, sitemap);
console.log('\n\u2713 Updated blog.html' + (sitemapChanged ? ' + sitemap.xml' : '') +
            (sitemap && !sitemapChanged ? '  (sitemap unchanged)' : ''));

if (PUBLISH) {
  try {
    execSync(`git -C "${ROOT}" add "blog/${lang}/${slug}.md" blog.html sitemap.xml`, { stdio: 'inherit' });
    execSync(`git -C "${ROOT}" commit -m "blog: publish ${slug} (${lang})"`, { stdio: 'inherit' });
    execSync(`git -C "${ROOT}" push origin main`, { stdio: 'inherit' });
    console.log('\n✓ Pushed to main — Hostinger webhook will deploy in ~15s.');
    console.log(`  Verify: https://voxdonna.com/blog-post.html?post=${slug}&lang=${lang}`);
  } catch (e) { console.error('git step failed:', e.message); process.exit(1); }
} else {
  console.log('\nNext: review the diff, then commit & push (or re-run with --publish):');
  console.log(`  git add blog/${lang}/${slug}.md blog.html sitemap.xml && git commit -m "blog: ${slug}" && git push origin main`);
}
