# Claude Enterprise Training — train.voxdonna.com

White-labelled, self-paced training portal built from
`guide claude enterprise agent.final.md`. Unlisted (`noindex`), one branded
portal per client company.

## Spin up a new client

```bash
python3 scripts/new-training-org.py "Acme Corp"
python3 scripts/new-training-org.py "Acme Corp" --path developer --accent '#3b82f6'
python3 scripts/new-training-org.py "Acme Corp" --modules part-04,part-12,part-13
```

Writes `train/orgs/acme-corp.json` plus `train/orgs/acme-corp/` for a logo. Drop
a `logo.png` in there and re-run with `--force` to pick it up. Commit, push, and
the portal is live at `https://train.voxdonna.com/acme-corp/`.

Everything in that JSON is editable by hand afterwards: company name, accent
colours, learning path or explicit module list, hero copy, certificate wording
and signatory.

**Learning paths:** `new-user`, `knowledge-worker`, `prompt-engineer`,
`developer`, `admin`, `certification` (all 23 modules). `--modules` overrides the
path with an explicit list.

## Regenerate content after editing the guide

```bash
python3 scripts/build-training-content.py            # rebuild + cache-bust
python3 scripts/build-training-content.py --check    # validate only
node scripts/test-train-render.mjs                   # renderer + quiz self-check
```

The build splits the guide into 23 module files, parses Appendix B into
`content/quiz.json` (100 questions with the answer key), strips that key out of
the browsable Appendix B, and stamps `?v=<git-hash>` on every asset reference —
Hostinger caches static files for 7 days, so skipping this ships stale JS.

## Run it locally

No PHP on macOS by default; use the official image:

```bash
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/app -w /app -p 8099:8099 \
  php:8.2-cli php -S 0.0.0.0:8099 -t /app/train
open http://localhost:8099/?org=demo
```

Trainee records land in `../train-data/` (gitignored). For the admin roster,
write a passcode there first:

```bash
mkdir -p train-data && printf 'some-passcode' > train-data/admin_secret.txt
chmod 600 train-data/admin_secret.txt
open http://localhost:8099/admin.html
```

## Layout

| Path | What it is |
|---|---|
| `index.html` | Enrolment, progress, curriculum, reference library |
| `module.html` | Reader with sticky ToC + inline 10-question section check |
| `exam.html` | Certification exam, scoped to the assigned path |
| `certificate.html` | Printable A4 landscape certificate |
| `verify.html` | Public certificate lookup by ID |
| `admin.html` | Roster + scores per org, CSV export, passcode-gated |
| `app.js` / `app.css` | Shared runtime and design tokens (DESIGN.md) |
| `content/` | Generated — do not hand-edit |
| `orgs/` | One JSON per client |
| `api/` | PHP endpoints; `_store.php` is helpers only and refuses direct requests |

## Server data

`~/domains/voxdonna.com/train-data/` — outside every webroot, never in git.

- `<slug>.json` — trainees for that org (name, email, progress, exam)
- `certs.json` — certificate ID → holder, company, score
- `admin_secret.txt` — roster passcode, `chmod 600`
- `ratelimit.json` — per-IP throttle state

## Pass mark

80% overall with no section below 6/10 — the bar the guide itself sets. A
path-scoped exam keeps the same 80% ratio over its own question count.
