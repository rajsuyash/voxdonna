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
`    <a class="blog-card blog-item" data-lang="${lang}" href="blog-post.html?post=${slug}&lang=${lang}">
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
const sm = `  <url><loc>https://voxdonna.com/blog-post.html?post=${slug}&amp;lang=en</loc><lastmod>${meta.date}</lastmod><changefreq>monthly</changefreq><priority>0.7</priority><xhtml:link rel="alternate" hreflang="en" href="https://voxdonna.com/blog-post.html?post=${slug}&amp;lang=en"/><xhtml:link rel="alternate" hreflang="fr" href="https://voxdonna.com/blog-post.html?post=${slug}&amp;lang=fr"/><xhtml:link rel="alternate" hreflang="it" href="https://voxdonna.com/blog-post.html?post=${slug}&amp;lang=it"/></url>`;

// ---- apply edits ----
const blogHtmlPath = path.join(ROOT, 'blog.html');
const sitemapPath = path.join(ROOT, 'sitemap.xml');
let blogHtml = fs.readFileSync(blogHtmlPath, 'utf8');
let sitemap = fs.existsSync(sitemapPath) ? fs.readFileSync(sitemapPath, 'utf8') : null;

const already = blogHtml.includes(`post=${slug}&lang=${lang}"`);
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
    const smAnchor = sitemap.search(/[ \t]*<url><loc>https:\/\/voxdonna\.com\/blog-post\.html/);
    if (smAnchor >= 0) sitemap = sitemap.slice(0, smAnchor) + sm + '\n' + sitemap.slice(smAnchor);
    else console.log('NOTE: no blog <url> anchor in sitemap.xml — skipped sitemap (add manually).');
  }
}

console.log(`\nPost:     ${meta.title}`);
console.log(`Slug:     ${slug}   Lang: ${lang}   Date: ${meta.date} (${niceDate})`);
console.log(`Category: ${meta.category}   Reading time: ${meta.readingTime} min`);
console.log(`URL:      https://voxdonna.com/blog-post.html?post=${slug}&lang=${lang}`);

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
console.log('\n✓ Updated blog.html' + (sitemap ? ' + sitemap.xml' : ''));

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
