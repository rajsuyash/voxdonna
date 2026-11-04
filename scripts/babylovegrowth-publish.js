#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const escape = value => value.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const field = value => String(value).replace(/[\r\n\x00-\x1f]/g, ' ').replace(/"/g, '”');

function writeArticle(root, article) {
  const {id, slug, lang, title, description, html, image} = article;
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug) || slug.length > 160 || !['en','fr','it'].includes(lang)
      || !/^[a-zA-Z0-9_-]{1,100}$/.test(id) || ![title, description, html, image].every(v => typeof v === 'string')) {
    throw new Error('Invalid normalized article');
  }
  const relative = `blog/${lang}/${slug}.md`;
  const mdPath = path.join(root, relative);
  const source = fs.existsSync(mdPath) ? fs.readFileSync(mdPath, 'utf8') : '';
  if (source && (!source.includes('\nsource: babylovegrowth\n') || !source.includes(`\nsourceId: ${id}\n`))) {
    throw new Error('Slug belongs to an existing article');
  }
  if (fs.readFileSync(path.join(root, '.htaccess'), 'utf8').includes(`${slug}\\.html`)) throw new Error('Slug is retired');
  for (const f of fs.readdirSync(path.join(root, 'blog', lang)).filter(f => f.endsWith('.md'))) {
    if (f !== `${slug}.md` && fs.readFileSync(path.join(root, 'blog', lang, f), 'utf8').includes(`\nsourceId: ${id}\n`)) {
      throw new Error('Changing an existing article slug requires a redirect');
    }
  }
  const hash = crypto.createHash('sha256').update(JSON.stringify(article)).digest('hex');
  const date = source.match(/^date: (\d{4}-\d{2}-\d{2})$/m)?.[1] || new Date().toISOString().slice(0, 10);
  const modified = source.includes(`\nsourceHash: ${hash}\n`)
    ? source.match(/^dateModified: (.+)$/m)?.[1] || date : new Date().toISOString().slice(0, 10);
  const minutes = Math.max(1, Math.ceil(html.replace(/<[^>]*>/g, ' ').split(/\s+/).length / 200));
  const meta = {title: field(title), description: field(description), date, dateModified: modified,
    category: 'AI for Business', readingTime: minutes, source: 'babylovegrowth', sourceId: id, sourceHash: hash, heroImage: field(image)};
  const markdown = '---\n' + Object.entries(meta).map(([k,v]) => `${k}: ${v}`).join('\n') + '\n---\n' + html + '\n';
  const url = `https://voxdonna.com/blog/${lang}/${slug}.html`;
  const start = `<!-- babylovegrowth:${lang}/${slug} -->`;
  const end = '<!-- /babylovegrowth -->';
  const card = `${start}\n<a class="blog-card blog-item" data-lang="${lang}" href="/blog/${lang}/${slug}.html">
<div class="blog-card-meta"><span class="blog-card-category">AI for Business</span><span class="blog-card-date">${date}</span></div>
<h3>${escape(title)}</h3><p class="blog-excerpt">${escape(description)}</p>
<div class="blog-card-footer"><span class="blog-read-time">${minutes} min read</span></div></a>\n${end}`;
  const indexPath = path.join(root, 'blog.html');
  let index = fs.readFileSync(indexPath, 'utf8');
  if (index.includes(start)) {
    const from = index.indexOf(start), to = index.indexOf(end, from);
    if (to === -1) throw new Error('Incomplete blog listing marker');
    index = index.slice(0, from) + card + index.slice(to + end.length);
  } else {
    const anchor = index.indexOf(`<a class="blog-card blog-item" data-lang="${lang}"`);
    if (anchor === -1) throw new Error('Missing language listing anchor');
    index = index.slice(0, anchor) + card + '\n' + index.slice(anchor);
  }
  const sitemapPath = path.join(root, 'sitemap.xml');
  let sitemap = fs.readFileSync(sitemapPath, 'utf8');
  if (!sitemap.includes('</urlset>')) throw new Error('Invalid sitemap');
  sitemap = sitemap.replace(/\s*<url>[\s\S]*?<\/url>/g, entry => entry.includes(`<loc>${url}</loc>`) ? '' : entry);
  sitemap = sitemap.replace('</urlset>', `<url><loc>${url}</loc><lastmod>${modified}</lastmod></url>\n</urlset>`);
  fs.writeFileSync(mdPath, markdown);
  fs.writeFileSync(indexPath, index);
  fs.writeFileSync(sitemapPath, sitemap);
  return {relative, url, hash};
}

async function publish(root, key, article) {
  const env = {...process.env, GIT_SSH_COMMAND: `ssh -i ${key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes`, GIT_TERMINAL_PROMPT: '0'};
  if (!/^\/[a-zA-Z0-9_./-]+$/.test(key)) throw new Error('Invalid key path');
  const git = (...args) => execFileSync('/usr/bin/git', args, {cwd: root, env, timeout: 12000, encoding: 'utf8', stdio: ['ignore','pipe','pipe']}).trim();
  let result;
  for (let attempt = 0; attempt < 2; attempt++) {
    // This disposable checkout is owned exclusively by the webhook, under its PHP lock.
    git('fetch', 'origin', 'main');
    git('reset', '--hard', 'origin/main');
    result = writeArticle(root, article);
    execFileSync(process.execPath, ['scripts/build-blog-static.js', result.relative], {cwd: root, timeout: 10000, stdio: 'pipe'});
    const files = [result.relative, result.relative.replace(/\.md$/, '.html'), 'blog.html', 'sitemap.xml'];
    const rendered = fs.readFileSync(path.join(root, files[1]), 'utf8');
    if (!rendered.includes(`<!-- babylovegrowth:${result.hash} -->`)) throw new Error('Render verification failed');
    for (const match of rendered.matchAll(/<script type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/g)) JSON.parse(match[1]);
    execFileSync('/usr/bin/php', ['-r', '$d=new DOMDocument();if(!$d->load($argv[1], LIBXML_NONET)){exit(1);}', path.join(root, 'sitemap.xml')], {timeout: 5000, stdio: 'pipe'});
    git('add', '--', ...files);
    if (git('diff', '--cached', '--name-only') === '') break;
    git('-c', 'user.name=VoxDonna Publisher', '-c', 'user.email=publisher@voxdonna.com', 'commit', '-m', `blog: publish ${article.slug} via BabyLoveGrowth`);
    try { git('push', 'origin', 'HEAD:main'); break; }
    catch (error) { if (attempt === 1) throw error; }
  }
  // A successful commit is not proof that Hostinger deployed it.
  for (let i = 0; i < 6; i++) {
    try {
      // Node fetch reserves Wasm memory that Hostinger's PHP workers cannot allocate.
      const html = execFileSync('/usr/bin/curl', ['--fail', '--silent', '--show-error', '--max-time', '4', `${result.url}?blg=${result.hash}`],
        {timeout: 5000, maxBuffer: 4000000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe']});
      if (html.includes(`<!-- babylovegrowth:${result.hash} -->`)) {
        return {success: true, link: result.url};
      }
    } catch (_) { /* The next bounded probe handles a transient network error. */ }
    await new Promise(resolve => setTimeout(resolve, 1500));
  }
  throw new Error('Committed article is not live yet; retry is safe');
}

module.exports = {writeArticle};
if (require.main === module) {
  const input = fs.readFileSync(0, 'utf8');
  publish(process.argv[2], process.argv[3], JSON.parse(input))
    .then(result => process.stdout.write(JSON.stringify(result)))
    .catch(error => { console.error(new Date().toISOString(), error.message); process.exitCode = 1; });
}
