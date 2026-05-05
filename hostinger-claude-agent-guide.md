# Programmatically Controlling Hostinger Shared Hosting — A Field Guide for Claude Agents

> Lessons learned the hard way while shipping `voxdonna.com`. If you are a Claude agent given access to a Hostinger shared hosting account, read this first. It will save you 4+ hours of trial and error.

---

## TL;DR — What you can and cannot do

| Capability | Status | How |
|---|---|---|
| SSH into the server | ✅ Yes | Custom port (usually `65002`), password auth |
| Run shell commands via SSH | ✅ Yes | But `exec/shell_exec/system/passthru/popen` are disabled in PHP |
| Run `git` on the server | ✅ Yes | `/usr/bin/git` is installed |
| Set up cron jobs | ⚠️ UI only | `crontab` command is **not available** via SSH; must use hPanel Cron Jobs UI |
| Auto-deploy from GitHub | ✅ Yes | **Use a PHP webhook receiver** with `proc_open` (NOT exec) |
| Hostinger's built-in "Deploy" feature | ❌ Broken | It runs `git status` only — never fetches changes |
| Run a long-lived Node/Python service | ❌ No | Shared hosting, no daemons |
| Manage DNS / subdomains via API | ❌ No public API | hPanel UI only |
| Upload files via SCP/SFTP | ✅ Yes | Same SSH credentials |
| Use Hostinger's CDN | ✅ Auto | But aggressive caching — see "Cache busting" below |

---

## 1. SSH Access

### Connection details

Hostinger shared hosting SSH is **not** on port 22. It's typically on **65002** with password auth (no SSH key per default).

```
Host:     <server-ip>           # e.g. 92.112.189.106 (lookup via `dig +short <yourdomain>`)
Port:     65002
User:     u<numeric-id>          # e.g. u649993053
Password: <hPanel password>      # often the same as hPanel login
```

Find these in **hPanel → Hosting → Manage → Advanced → SSH Access**. Copy the user, host, port. The password is set there too.

### Recommended local pattern: store creds in `.env`, gitignore it

```bash
# .env (gitignored — never commit)
SSH_HOST=92.112.189.106
SSH_PORT=65002
SSH_USER=u649993053
SSH_PASSWORD=<password>
WEB_ROOT=~/domains/<your-domain>/public_html/
```

Then connect with `sshpass`:

```bash
source .env
sshpass -p "$SSH_PASSWORD" ssh -p $SSH_PORT -o StrictHostKeyChecking=no $SSH_USER@$SSH_HOST "ls ~/domains/"
```

⚠️ **macOS:** `sshpass` is not built in. Install via Homebrew: `brew install sshpass` (or use `brew install hudochenkov/sshpass/sshpass` if the formula is unavailable).

### Common gotcha: SSH lockout after rapid retries

Hostinger throttles SSH login attempts. If you fail auth 3+ times in 60 seconds, the server returns `Permission denied (publickey,password)` for the next ~10 minutes — even with the correct password.

**If you see repeated "Permission denied" failures, stop, wait 10 minutes, try again.** Do not keep hammering — you'll extend the lockout.

### Server filesystem layout

```
~/                                  # u649993053's home
├── domains/
│   ├── <yourdomain.com>/
│   │   ├── public_html/            # webroot for the apex domain
│   │   ├── deploy.log              # webhook deploy log (if you set one up)
│   │   └── deploy_secret.txt       # webhook HMAC secret (chmod 600, outside webroot)
│   └── <subdomain.yourdomain.com>/
│       └── public_html/            # webroot for the subdomain (separate from apex)
└── public_html                     # legacy default webroot — usually a symlink
```

**Critical**: each subdomain is its **own webroot**. Files written to `~/domains/voxdonna.com/public_html/` are NOT served from `schedule.voxdonna.com/`. You need `~/domains/schedule.voxdonna.com/public_html/`.

---

## 2. PHP `disable_functions` — the trap that wastes hours

Hostinger shared hosting **disables most shell-spawning PHP functions** for security. The default `disable_functions` includes:

```
exec, shell_exec, system, passthru, popen, proc_get_status, escapeshellarg, escapeshellcmd
```

`proc_open` is **enabled** (this is the one you can use).

### What this means

If you write a webhook deploy script using `exec("git pull")` it will fail silently with:

```
PHP Warning: exec() has been disabled for security reasons
```

### The pattern that actually works on Hostinger

```php
function run_cmd(array $argv, string $cwd): array {
    $desc = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $proc = proc_open($argv, $desc, $pipes, $cwd);
    if (!is_resource($proc)) return [127, '', 'proc_open failed'];
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $rc = proc_close($proc);
    return [$rc, $stdout, $stderr];
}

// Call git via absolute path — $PATH may not be set under PHP-FPM
[$rc, $out, $err] = run_cmd(['/usr/bin/git', 'fetch', 'origin', 'main'], $repoDir);
```

Pass commands as **arrays of strings** (not concatenated shell strings). This sidesteps the disabled `escapeshell*` functions and is safer anyway.

---

## 3. GitHub → Hostinger Auto-Deploy

### Don't use Hostinger's built-in Git deploy

Hostinger has a **"Git" tab** in hPanel where you can connect a repo. It promises auto-deploy. It is **broken**: clicking "Deploy" runs `git status`, never `git fetch`. You will see your changes live only if you manually SSH in.

### Don't use GitHub Actions with SSH

GitHub Actions runners have their IPs blocked by Hostinger's SSH firewall. Build minutes will burn while connections time out:

```
dial tcp 92.112.189.106:65002: i/o timeout
```

### Do use a PHP webhook receiver

Drop this at `~/domains/<yourdomain>/public_html/deploy.php`. Then in GitHub: **Settings → Webhooks → Add webhook → URL: `https://<yourdomain>/deploy.php`, content type `application/json`, secret = a long random string, events: just `push`**.

```php
<?php
// GitHub webhook receiver — pulls latest main on push.
// Reads HMAC secret from ../deploy_secret.txt (outside web root, NOT in git).

$secretFile = __DIR__ . '/../deploy_secret.txt';
$logFile    = __DIR__ . '/../deploy.log';

header('Content-Type: text/plain');

if (!is_readable($secretFile)) { http_response_code(500); echo "secret file missing\n"; exit; }
$secret = trim(file_get_contents($secretFile));

$payload   = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_HUB_SIGNATURE_256'] ?? '';
$expected  = 'sha256=' . hash_hmac('sha256', $payload, $secret);
if (!hash_equals($expected, $signature)) { http_response_code(403); echo "bad signature\n"; exit; }

$event = $_SERVER['HTTP_X_GITHUB_EVENT'] ?? '';
if ($event === 'ping') { echo "pong\n"; exit; }
if ($event !== 'push') { http_response_code(202); echo "ignored event: $event\n"; exit; }

function run_cmd(array $argv, string $cwd): array {
    $desc = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($argv, $desc, $pipes, $cwd);
    if (!is_resource($proc)) return [127, '', 'proc_open failed'];
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    return [proc_close($proc), $stdout, $stderr];
}

$repoDir = __DIR__;
$git     = '/usr/bin/git';

[$rc1, $o1, $e1] = run_cmd([$git, 'fetch', 'origin', 'main'], $repoDir);
if ($rc1 === 0) {
    [$rc2, $o2, $e2] = run_cmd([$git, 'reset', '--hard', 'origin/main'], $repoDir);
    $rc = $rc2;
} else {
    $rc = $rc1;
}

[$_, $headOut] = run_cmd([$git, 'rev-parse', '--short', 'HEAD'], $repoDir);
$head = trim($headOut);

$line = '[' . gmdate('Y-m-d H:i:s') . "] rc=$rc head=$head\n$o1$e1$o2$e2---\n";
@file_put_contents($logFile, $line, FILE_APPEND);

if ($rc !== 0) { http_response_code(500); echo "deploy failed rc=$rc\n"; exit; }
echo "deployed $head\n";
```

### Setup steps

```bash
# 1. SSH in, init the repo in the webroot
sshpass -p "$SSH_PASSWORD" ssh -p $SSH_PORT $SSH_USER@$SSH_HOST <<'EOF'
cd ~/domains/<yourdomain>/public_html
git init
git remote add origin https://github.com/<owner>/<repo>.git
# Use a Deploy Key (read-only SSH key registered at GitHub → repo Settings → Deploy keys)
git fetch origin main
git reset --hard origin/main
EOF

# 2. Create the secret on the server (outside webroot)
SECRET=$(openssl rand -hex 32)
sshpass -p "$SSH_PASSWORD" ssh -p $SSH_PORT $SSH_USER@$SSH_HOST \
    "echo '$SECRET' > ~/domains/<yourdomain>/deploy_secret.txt && chmod 600 ~/domains/<yourdomain>/deploy_secret.txt"

# 3. Add deploy.php to the repo, push, and webhook fires the first deploy
# 4. Add the webhook in GitHub with the same $SECRET
```

### Push-to-deploy latency

After pushing to `main`, the webhook fires within ~2s and the deploy completes in ~8–12s. So **expect ~10–15s end-to-end** before changes are live.

### LiteSpeed bot detection can intercept the webhook

Hostinger uses LiteSpeed Cache + bot challenges. Occasionally the GitHub webhook hits a `Bot Verification` reCAPTCHA page and fails. You'll see the request returning HTML containing `<title>Bot Verification</title>` instead of `pong` / `deployed <hash>`.

**Mitigation:** the webhook still fires on the next push. If urgent, manually `git pull` via SSH.

---

## 4. The webhook didn't fire — diagnostic checklist

When `curl https://<yourdomain>` doesn't show your latest commit:

```bash
# 1. Confirm GitHub successfully delivered the webhook
gh api repos/<owner>/<repo>/hooks/<id>/deliveries | jq '.[0]'

# 2. Check the deploy log on the server
sshpass -p "$SSH_PASSWORD" ssh -p $SSH_PORT $SSH_USER@$SSH_HOST \
    "tail -30 ~/domains/<yourdomain>/deploy.log"

# 3. Compare local vs server commit hash
git rev-parse --short HEAD                  # local
sshpass ... ssh ... "cd ~/domains/<yourdomain>/public_html && git rev-parse --short HEAD"

# 4. If server is behind, force a manual pull
sshpass ... ssh ... "cd ~/domains/<yourdomain>/public_html && git pull origin main"
```

---

## 5. Aggressive Caching — the silent bug factory

### Static assets are cached for 7 days by default

Hostinger sets `Cache-Control: public, max-age=604800` on `.js`, `.css`, `.png`, etc. by default. **HTML is not cached aggressively** (`x-hcdn-cache-status: DYNAMIC`).

This means: when you push an `index.html` referencing `i18n.js`, browsers fetch the new HTML but **reuse the cached `i18n.js` for up to 7 days**. New translations / functions don't show up.

### Fix: cache-bust on every change

Change `<script src="i18n.js"></script>` to `<script src="i18n.js?v=20260505"></script>` and bump the version string on every edit to that file. The browser sees a new URL and re-fetches.

For automation, use git short hash:
```bash
GIT_HASH=$(git rev-parse --short HEAD)
sed -i "s|i18n\.js?v=[a-f0-9]*|i18n.js?v=$GIT_HASH|g" index.html
```

### CDN cache for HTML

Even though HTML is `DYNAMIC`, there's a small edge cache (~30s typically). After a deploy, `curl 'https://<yourdomain>/?cb='$(date +%s)` to bypass it during testing.

---

## 6. DNS — the user's router lies to them

### Hostinger DNS is on `pixel/byte.dns-parking.com`

Subdomains created via hPanel **don't always auto-create the right DNS records**. Verify with:

```bash
dig +short <subdomain>.<yourdomain> @8.8.8.8        # Google DNS (authoritative truth)
dig +short <subdomain>.<yourdomain> @1.1.1.1        # Cloudflare
dig +short <subdomain>.<yourdomain>                 # System / router DNS
```

If the first two return your Hostinger IP but the third returns something else (a CNAME to a previous host, for example), **the user's router/ISP is caching stale DNS** — not your fault, not a server bug.

### Common stale-cache fix sequence

1. macOS DNS flush: `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`
2. If that doesn't help: in System Settings → Network → Wi-Fi → Details → DNS, change DNS to `1.1.1.1` and `8.8.8.8` (drag above the router IP)
3. Chrome internal DNS: `chrome://net-internals/#dns` → Clear host cache

### Subdomain creation via hPanel

You **must** use the UI: hPanel → Domains → Subdomains → Create New. There is no public API for this.

⚠️ When you migrate a subdomain off another service (e.g. TidyCal custom domain) onto Hostinger, you have to manually delete the old `CNAME` record in DNS Zone Editor. Hostinger won't do it for you, and a CNAME and A record cannot coexist for the same name.

---

## 7. `.gitignore` and binary files

### Defaults you'll regret

A typical `.gitignore` includes `*.mp4` and `*.pdf`. If you need to commit a specific media file (a video for an About section, for instance), add an exception:

```gitignore
.DS_Store
.claude/
*.mp4
!video/intro.mp4               # exception: this one IS tracked
*.pdf
.env
```

### File size

GitHub rejects files > 100 MB and warns on > 50 MB. Hostinger has no per-file limit but has a total disk quota. For media > 10 MB consider Cloudflare Stream / Bunny CDN instead of bundling in the repo.

---

## 8. Things that work but require the UI (no API)

| Action | Where in hPanel |
|---|---|
| Create / delete subdomains | Domains → Subdomains |
| Edit DNS records | Domains → DNS Zone Editor |
| Manage SSL certificates | Hosting → Manage → Security → SSL |
| Set up cron jobs | Hosting → Manage → Advanced → Cron Jobs |
| File Manager (web UI) | Files → File Manager |
| Connect a Git repo (broken) | Hosting → Manage → Advanced → Git |
| View access / error logs | Hosting → Manage → Advanced → Access/Error Logs |
| Phpinfo() / PHP config | Hosting → Manage → Advanced → PHP Configuration |

For the Claude agent: **if the user asks you to do any of the above, you cannot. Tell them which hPanel screen to open and what to click.** Don't pretend you have access.

---

## 9. Permissions & PHP versions

- Default file permissions: `644` for files, `755` for directories. PHP needs read access; Apache/LiteSpeed needs execute on directories.
- PHP version: configurable per-domain at hPanel → PHP Configuration. Default is usually the latest stable (PHP 8.x).
- `php_value` directives in `.htaccess` work for memory_limit, max_execution_time, upload_max_filesize.
- Symbolic links from `public_html` outside the webroot are blocked by LiteSpeed for security.

---

## 10. Patterns that don't work — don't waste time trying them

| Attempt | Why it fails |
|---|---|
| `crontab -e` over SSH | `crontab` is not in PATH, exits with `command not found`. Use hPanel Cron Jobs UI. |
| `node app.js` long-running daemon | No `screen`/`tmux` allowed; SSH session ends, process dies. Shared hosting doesn't support daemons. |
| GitHub Actions SSH deploy | Hostinger blocks Actions IPs on SSH port. Use webhook instead. |
| `exec("git pull")` in PHP | `exec` is in `disable_functions`. Use `proc_open`. |
| Hostinger's "Deploy" button on Git tab | Runs `git status`, not `git fetch`. Build a webhook. |
| `sudo` anything | No sudo on shared hosting. |
| Installing packages via `apt`/`yum` | No package manager access. Pre-installed binaries only (`/usr/bin/git`, `/usr/bin/curl`, `/usr/bin/php`). |
| Listening on a custom port | All inbound traffic must hit the LiteSpeed webserver on 80/443. |
| Running `npm install` for backend deps | `npm` is installed but you can't keep a Node process running. Only useful for build steps that produce static output. |

---

## 11. Useful commands cheatsheet

```bash
# Set $B variable for short ssh-via-sshpass calls
B='sshpass -p "$SSH_PASSWORD" ssh -p $SSH_PORT -o StrictHostKeyChecking=no $SSH_USER@$SSH_HOST'
source .env

# Check what's installed
$B 'which git php node npm python3 composer'

# Server commit hash
$B "cd ~/domains/<yourdomain>/public_html && git rev-parse --short HEAD"

# Tail deploy log
$B "tail -30 ~/domains/<yourdomain>/deploy.log"

# Manually pull on server
$B "cd ~/domains/<yourdomain>/public_html && git fetch origin main && git reset --hard origin/main"

# Disk usage
$B "du -sh ~/domains/*/public_html/"

# PHP info
$B "php -i | grep -iE 'disable_functions|memory_limit|upload_max'"

# Check what PHP version each domain uses
$B 'cat ~/.htaccess 2>/dev/null; cat ~/domains/*/public_html/.htaccess 2>/dev/null | head -20'

# Manually upload a single file via scp
sshpass -p "$SSH_PASSWORD" scp -P $SSH_PORT local-file.html \
    $SSH_USER@$SSH_HOST:~/domains/<yourdomain>/public_html/
```

---

## 12. Verification checklist before declaring "deployed"

After every push, verify with all four:

```bash
# 1. GitHub has the commit
git rev-parse --short HEAD

# 2. Server has the same commit
sshpass ... ssh ... "cd ~/domains/<yourdomain>/public_html && git rev-parse --short HEAD"

# 3. The live site serves new content (cache-busted curl)
curl -s "https://<yourdomain>/?cb=$(date +%s)" | grep "<expected-text>"

# 4. Cache headers look right
curl -sI "https://<yourdomain>/<changed-file>" | grep -iE "cache-control|x-hcdn-cache"
```

If any of those four disagree, you have a problem. Don't tell the user "it's deployed" until all four match.

---

## 13. Specific bug stories from this project (for pattern recognition)

### "It works on curl but not in my browser"

→ Aggressive `Cache-Control` on `i18n.js`. Cache-bust query string fixes it.

### "I deployed but voxdonna.com still shows old content"

→ User's local DNS resolver was caching the old IP from a previous host. `dig +short @8.8.8.8` showed correct IP, but their router DNS lied. Fix: change Mac DNS to `1.1.1.1` directly.

### "Webhook deployed but my push didn't"

→ Two consecutive pushes can race; second webhook can fire before first finishes its `git reset --hard`. Symptom: both pushes succeed in GitHub, but only the older commit is on the server. Fix: manual `git pull` via SSH, or accept the 5–10s race window and re-push.

### "GitHub webhook returns HTML, not 'deployed <hash>'"

→ LiteSpeed bot challenge intercepted the request. Webhook delivery failed. Will retry on next push, or trigger a manual webhook redelivery via GitHub Settings → Webhooks → Recent Deliveries → Redeliver.

### "PHP exec works on my local machine but fails on Hostinger"

→ `disable_functions` blocks it. Refactor to `proc_open`.

### "I can SSH but `crontab` says command not found"

→ Hostinger removed it from PATH. Use hPanel → Cron Jobs UI.

### "I created a subdomain in hPanel but it doesn't resolve"

→ Either DNS hasn't propagated (wait 5–15 min), or the old TidyCal/external CNAME is still in the DNS Zone Editor and conflicting with the new A record. Delete the CNAME manually.

---

## 14. When to give up and ask the user

Anything in the hPanel-only column (DNS, subdomains, cron, SSL, file manager) → **stop and ask the user to click**. Don't spin in retry loops trying to script it. There's no API.

Anything related to billing, account upgrades, or plan changes → **always ask the user**. Don't touch.

Destructive operations (`rm -rf`, `chmod 000`, dropping databases) → **always ask the user first**, even if they previously said "do whatever". Permission scope expires per-action on hPanel.

---

## 15. The one rule that saves the most time

**Always cache-bust JS/CSS/JSON references in HTML when you change the source files.** Hostinger's `max-age=604800` means anything you don't bust will look broken to the user for up to 7 days. They will not realize it's a cache issue. They will tell you "your code doesn't work." It's the cache.

```html
<!-- Bad: stale for up to 7 days -->
<script src="app.js"></script>

<!-- Good: bumped on every change -->
<script src="app.js?v=20260505"></script>
```

A simple shell hook before push:
```bash
TODAY=$(date +%Y%m%d)
sed -i.bak -E "s|(\.js|\.css|\.json)\?v=[0-9]+|\1?v=$TODAY|g" index.html
rm index.html.bak
```

---

*Last updated: 2026-05-05. Source of truth: a real deployment of voxdonna.com on Hostinger Premium Web Hosting.*
