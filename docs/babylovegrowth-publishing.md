# BabyLoveGrowth publishing

Endpoint: `POST https://voxdonna.com/babylovegrowth.php`.

Authenticate using `Authorization: Bearer <secret>` (or `X-API-Key`). The secret and repository key live outside the web root in `~/domains/voxdonna.com/babylovegrowth/`. Never commit them. `config.json` contains `secret`, `node`, `repo`, `sshKey`; absolute paths point to the private Node installation, disposable checkout and repository-specific deploy key.

The receiver validates the payload, sanitizes `content_html` using an HTML allowlist, removes executable markup, and passes normalized content to the publisher under an exclusive lock. English, French and Italian are supported. It rejects existing unrelated slugs and slug changes for an already-published article ID. Titles and descriptions are plain text; line breaks and straight double quotes are normalized for the existing frontmatter reader.

The publisher fetches current main into its dedicated checkout, writes the source article, renders only that page with the existing template, updates the blog listing and sitemap, validates JSON-LD and XML, and commits/pushes those four paths. A rejected push is rebuilt once on fresh main. The existing deployment webhook delivers the commit. Success is returned only after the public page contains its expected content hash. The JSON response includes the live URL. Retries are safe; changed content updates the same article. Other source files and locally edited workspaces are never used as the publishing checkout.

## Operations

- Log: `~/domains/voxdonna.com/babylovegrowth/publisher.log`.
- For a failure, inspect this log and `~/domains/voxdonna.com/deploy.log`, then retry the article in BabyLoveGrowth.
- A transient error or concurrent request returns 503. BabyLoveGrowth retries three times. A sustained outage requires republishing from its dashboard; there is no background queue.
- Turn off **Automatically Publish** in BabyLoveGrowth to pause incoming articles. Removing the private config disables the endpoint. Revoke the dedicated GitHub deploy key to disable repository writes.
- The provider UI recommends five seconds, while its detailed webhook docs allow 120 seconds. This implementation waits for deployment; verify its actual delivery timeout during connection acceptance.
- Images remain on the provider CDN. No new image hosting or content fact-checking service is included. Provider-supplied scripts/JSON-LD are discarded; the site generates its own article and breadcrumb schema. The existing FAQ extractor accepts Markdown FAQ headings, so provider HTML FAQ sections do not automatically receive FAQ schema.

## Verification

`php -l babylovegrowth.php`

`node --check scripts/babylovegrowth-publish.js`

`node --check scripts/build-blog-static.js`

`node --test scripts/test-babylovegrowth.cjs`

Tests cover HTML sanitization, malformed inputs, metadata/script escaping, literal dollar signs, duplicate delivery, updates, slug ownership, JSON-LD/XML and HTTP authentication. A real provider delivery and live page inspection are separate acceptance checks. No project-wide type checker or linter is configured for these PHP/vanilla JavaScript scripts.
