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

## How the content is structured

The guide is packed into **62 lessons of ~5 minutes** across 23 modules rather than
served as 23 long reads — long-form e-learning completes at 20–30%, short modules
at 80%+, and Mayer's segmenting principle holds up in meta-analysis. Lessons never
split a section; a section too long to be a lesson is sub-split at `####`.

Four modules are reference tools rather than linear reading, and render as
searchable browsers instead of prose:

| Module | Becomes | Items |
|---|---|---|
| Part 17 | pitfall cards, filterable by category | 100 mistake → fix pairs |
| Part 20 | prompt library, searchable + copyable | 102 prompts |
| Appendix A | glossary + FAQ with A–Z jump | 46 terms, 33 questions |
| Appendix C | printable cheat-sheet cards | 9 sheets |

The build also promotes authored conventions into explicit `:::` blocks the
renderer styles — 33 `#### Try it` exercises become task callouts. Citations
`(Anthropic Docs, Aug 2026)` and `⚠` volatility markers get quiet inline
treatment rather than being lost in the prose.

**Recall checks.** The 100 exam questions map to 10 of the 23 modules; those are
distributed across their lessons and run inline at the end. Lessons outside those
modules deliberately have **no quiz** — inventing exam content about Anthropic's
products risks teaching things that aren't true. Authoring the missing ~130
questions is a follow-up that needs human review.

**Review queue.** A missed question returns after 1 day, then 3, 7, and 21 on each
correct recall, then retires. State lives in `localStorage`, mirrors to the server,
and surfaces on the home page only when something is actually due.

## Regenerate content after editing the guide

```bash
python3 scripts/build-training-content.py            # rebuild + cache-bust
python3 scripts/build-training-content.py --check    # validate only
node scripts/test-train-render.mjs                   # renderer + quiz self-check
```

The build packs the guide into `content/lessons/*.md`, parses Appendix B into
`content/quiz.json` (100 questions with the answer key), strips that key out of
the browsable appendix, emits `prompts.json` / `mistakes.json` / `glossary.json` /
`sheets.json` for the browsers, and stamps `?v=<git-hash>` on every asset
reference — Hostinger caches static files for 7 days, so skipping this ships
stale JS. Every count is asserted; the build fails rather than shipping a
half-parsed library.

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
| `module.html` | Lesson reader with a sticky lesson rail + inline recall check; renders the browser view for reference modules |
| `review.html` | Spaced-repetition session over questions that are due |
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
