# Voxdonna Blog — Publishing SOP (for humans & the Hermes agent)

This is the complete, repeatable procedure to publish a blog post to **voxdonna.com**.
A new post is **3 files + 1 push**. There is a script that does steps 2–4 for you.

---

## How the blog works (architecture)

- **Repo:** `github.com/rajsuyash/voxdonna.git` (branch `main`). Local: `…/Websites/voxdonnaantigravity`.
- **Stack:** static HTML/CSS/JS, no build step.
- **A post = one markdown file** at `blog/<lang>/<slug>.md` with YAML frontmatter + markdown body.
  Languages: `en`, `fr`, `it`. English-only is fine.
- **`blog-post.html?post=<slug>&lang=<lang>`** renders a post. It looks the post up in `blog-data.js`
  first and, if not found, **fetches `blog/<lang>/<slug>.md` directly**. So the `.md` file alone is
  enough to publish — **you do NOT need to touch the 615 KB `blog-data.js`.**
- **`blog.html`** is the index. Its post cards are hardcoded, so a new post needs a card added here
  to appear in the listing.
- **`sitemap.xml`** has one `<url>` per post (SEO). Add an entry for each new post.
- **Deploy:** push to `main` → GitHub webhook → `deploy.php` on Hostinger → `git pull`. Live in ~15s.
- **Brand voice:** ground every post in **`SOUL.md`** (the Donna Paulsen persona, 7 voice rules,
  do/don't examples). Read it before writing.

---

## The fast path (recommended — one command)

1. **Write the markdown file** → `blog/en/<slug>.md` with this frontmatter:

   ```markdown
   ---
   title: "Your Headline Here"
   description: "1–2 sentence summary. Also used as the listing-card excerpt and meta description."
   date: "2026-06-26"            # YYYY-MM-DD
   category: "Manufacturing"      # short label shown on the card
   readingTime: "8"               # whole minutes, number as string
   keywords: "comma, separated, seo, keywords"
   ---

   # Your Headline Here

   First paragraph…

   ## A Section

   Body in standard markdown: ## / ### headings, **bold**, lists, > quotes, and | tables |.
   ```

   - **slug** = lowercase, hyphenated, no spaces (it becomes the URL). Keep it stable forever.
   - Supported markdown: headings, paragraphs, bold, bullet/numbered lists, blockquotes, tables.

2. **Run the publisher** (adds the listing card + sitemap entry, then commits & pushes):

   ```bash
   cd "…/Websites/voxdonnaantigravity"
   node scripts/publish-blog-post.js <slug> --publish
   ```

   - Drop `--publish` to edit the files but **not** push (review first).
   - Add `--dry-run` to preview the generated card/sitemap without writing anything.
   - Re-running is safe — it skips a card/sitemap entry that already exists.

3. **Verify** (give the webhook ~15s):

   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" "https://voxdonna.com/blog/en/<slug>.md"
   open "https://voxdonna.com/blog-post.html?post=<slug>&lang=en"
   ```

That's it. The post is live and listed.

---

## The manual path (if not using the script)

Do the same three edits by hand, then push:

1. Create `blog/en/<slug>.md` (frontmatter + body, as above).
2. In **`blog.html`**, insert this card as the first card right after
   `<!-- EN — sorted by date desc, featured excluded -->`:

   ```html
       <a class="blog-card blog-item" data-lang="en" href="blog-post.html?post=<slug>&lang=en">
         <div class="blog-card-meta">
           <span class="blog-card-category">CATEGORY</span>
           <span class="blog-card-date">June 26, 2026</span>
         </div>
         <h3>TITLE</h3>
         <p class="blog-excerpt">DESCRIPTION</p>
         <div class="blog-card-footer">
           <span class="blog-read-time">8 min read</span>
           <div class="blog-arrow"><svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg></div>
         </div>
       </a>
   ```
3. In **`sitemap.xml`**, add (right before the first existing `blog-post.html` `<url>`):

   ```xml
     <url><loc>https://voxdonna.com/blog-post.html?post=<slug>&amp;lang=en</loc><lastmod>2026-06-26</lastmod><changefreq>monthly</changefreq><priority>0.7</priority><xhtml:link rel="alternate" hreflang="en" href="https://voxdonna.com/blog-post.html?post=<slug>&amp;lang=en"/><xhtml:link rel="alternate" hreflang="fr" href="https://voxdonna.com/blog-post.html?post=<slug>&amp;lang=fr"/><xhtml:link rel="alternate" hreflang="it" href="https://voxdonna.com/blog-post.html?post=<slug>&amp;lang=it"/></url>
   ```
4. Commit & push:
   ```bash
   git add blog/en/<slug>.md blog.html sitemap.xml && git commit -m "blog: publish <slug>" && git push origin main
   ```

---

## Translations (optional)

For `fr` / `it`, create `blog/fr/<slug>.md` and `blog/it/<slug>.md` (same slug, translated body), and run
the script once per language (`--lang fr`, `--lang it`). The language switcher on the post page uses the
same slug across languages.

---

## Gotchas

- **Cache:** a brand-new slug has no cache, so it appears immediately. If you ever **edit an existing**
  post, Hostinger's CDN may serve the old `.md` for a while — change is still live, just bump/cache-bust or
  wait. New posts are unaffected.
- **Keep the slug permanent** — it's the URL and is in the sitemap; renaming breaks links.
- **Don't edit `blog-data.js`** — it's a legacy bundle; the `.md` fetch path is the supported one.
- **`scripts/` and this file** are tooling/docs; they don't affect the live site.

---

## Ready-to-paste task for the Hermes agent

> **Task: publish a Voxdonna blog post.**
> Repo: `…/Websites/voxdonnaantigravity` (GitHub `rajsuyash/voxdonna.git`, branch `main`).
> 1. Read `SOUL.md` and match the Donna brand voice.
> 2. Write the article to `blog/en/<slug>.md` with frontmatter keys `title, description, date (YYYY-MM-DD),
>    category, readingTime, keywords` followed by the markdown body. Pick a stable lowercase-hyphen slug.
> 3. Run `node scripts/publish-blog-post.js <slug> --publish` from the repo root.
> 4. Wait ~15s, then confirm `https://voxdonna.com/blog-post.html?post=<slug>&lang=en` returns 200 and the
>    card shows on `https://voxdonna.com/blog.html`. Report the live URL.
> Constraints: English unless told otherwise; never edit `blog-data.js`; keep the slug permanent.
