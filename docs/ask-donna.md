# Ask Donna live voice oracle

Verified implementation record: 2026-11-06.

Voice hero above the homepage hero on https://voxdonna.com. A visitor talks to Donna, she collects a lead, then emails a plan, shows demos or sends them to the booking page. Internal doc: `docs/` is 404'd by `.htaccess` (line 31).

Verified against origin/main b628135. `cd oracle-relay && node --test`: 101 tests, 101 pass, 0 fail (2026-11-06).

## Implementation

### Front end (static, no build)

- Markup in `index.html` (`<section class="donna-hero" data-relay="">`, ~line 3418). Code in `assets/donna/`: `hero.js` (UI, lead form, navigation), `engine.js` (relay or mock transport), `audio.js` (mic capture, PCM playback), `soundform.js`, `donna-hero.css`.
- Cache-buster is a `?v=` query on the CSS and hero.js tags (`index.html` ~lines 2903-2904) and on the `audio.js` import in `engine.js`. Currently `20261106g`. Bump it on every front-end change; the assets are cached.
- Engine choice is in `engine.js` `connect()`: `?engine=mock` runs a scripted conversation with no network; anything else uses the relay. (The header comment in `engine.js` says mock is the default. The code says relay is. Trust the code.) Default relay URL is the `DEFAULT_RELAY` constant in `engine.js`; `?relay=` overrides it.
- GA4 events: `oracle_open` on first open, `generate_lead` (method `ask_donna`) after the lead POST succeeds. Mock sessions never send `generate_lead` or POST the lead.

### Relay (Cloud Run)

- Service `oracle-relay`, project `voxdonna-oracle`, region `us-central1`, min 0 / max 3 instances. Node 22, `ws`, `pdfkit`, `google-auth-library` (`oracle-relay/Dockerfile`, `package.json`).
- Public access: the service is deployed with `--no-invoker-iam-check`, because the org's domain-restricted sharing blocks `allUsers`. Reported at deploy time, not visible in the repo: `oracle-relay/README.md` still shows `--allow-unauthenticated`. Browsers get in through a signed one-time ticket (`POST /ticket`, origin allow-list, per-IP rate limit; `server.mjs` 180-197) then a WebSocket at `/live` (`server.mjs` 202-220).
- Voice: Gemini Live on Vertex, model `gemini-3.8-live` at `us-central1` (`server.mjs` `loadConfig`, 17-60). Female voice via `speechConfig.voiceConfig.prebuiltVoiceConfig.voiceName`, default `Kore`, `languageCode` default `en-US` (`session.mjs` 246-261). Both overridable with `VOICE_NAME` and `VOICE_LANGUAGE`.
- Auth to Vertex is Cloud Run's runtime identity (ADC). No key files.
- Hard session cap `MAX_SESSION_SECONDS` 300, then a wrap-up prompt and `CAP_GRACE_SECONDS` 8.

### Conversation flow (`oracle-relay/instructions.md`)

- Donna leads. Every reply ends with one clear question (lines 4-8). The only exceptions are the navigate line and the final line after `finish_intake`.
- Intake order (lines 26-32): name, work email (spelled out and read back before saving), company, website, industry, problem (dig once if vague, never twice), monthly volume.
- Ending (lines 35-46): one-line take grounded only in what they said, then one question: email a 3-page automation plan, show a live demo, or book a call, "pick one or more".
- `finish_intake({next: ["plan"|"demo"|"call", ...]})` (`tools.mjs` 91-105, 130-158). Requires name, email, problem saved. The action follows: plan email, navigate to `demos`, or navigate to `book_meeting` (the TidyCal discovery-call link, `tools.mjs` 14). Demo plus call together goes to booking only. A later "also send the plan" is honoured once (`planSent`).
- Navigate only when asked. `handleToolCall` rejects `navigate` while intake is in progress unless the visitor's last turn matches an intent-word regex (`tools.mjs` 43-47, 125-127). It is a keyword heuristic, not intent detection (see Known gaps).
- Field validation (`tools.mjs` `validateField`, 25-41): max 300 chars (problem 1500), email regex, placeholder rejection (`n/a`, `none`, `unknown`, `tbd`, `anonymous`, and similar), and a Latin-script requirement for name, company and industry so the Latin PDF font never gets Devanagari. The model is told to transliterate and retry.

### Silence handling (`session.mjs`)

- Speech-based timer, armed only after Donna's turn completes and cleared by any visitor speech, text, field edit, or Donna starting to speak (57-71).
- `SILENCE_SECONDS` 10: first expiry sends a bracketed system note so Donna asks "still there?" in one line. Then `SILENCE_GRACE_SECONDS` 8 more before the session ends with reason `silence`.
- `IDLE_SECONDS` 45: frame-based backstop (51-55), reset on client audio or text frames.
- Browser caption on `silence`: "Call ended after 10 seconds of quiet. Tap to talk again." (`hero.js` 385). The "10 seconds" text is hard-coded and does not follow `SILENCE_SECONDS`; the real time to hang up is about 18 seconds (10 + 8).

### Resume after reload

- `hero.js` keeps the form in `sessionStorage` key `donna.lead.v1` (lines 39-44).
- On WebSocket open the browser sends `{type: "resume", fields}` as its first frame. The relay holds the upstream setup for up to 400 ms (`RESUME_WAIT_MS`) so the frame can arrive, validates each field again, seeds the lead, and tells the model to greet by name and continue with the next missing field (`session.mjs` 82-89, 177-187).
- If everything is saved the greeting says to ask whether anything needs changing, then finish.

### Navigation UX (`hero.js` 263-361)

- "Taking you there in 3…" countdown with a "Stay here" button.
- The relay emits `listening` right after a tool call, before Donna speaks. The countdown therefore waits for a `speaking` then `listening` transition so she finishes her sentence. If no speech starts within `NAV_SPEECH_WAIT_MS` (2500) it starts anyway.

### Lead capture to the team

- On `intake_complete` the browser POSTs `{lead, next, hp:""}` to `/oracle-lead.php` (`hero.js` 183-196).
- `oracle-lead.php`: honeypot, field validation, 5 per hour per IP counted from the last 200 lines of the log (`RATE_LIMIT_PER_HOUR`, lines 38, 90-100), appends a JSON line to `.oracle-leads.jsonl`, then `mail()`s hello@ with subject `[Ask Donna · plan+call] Company — Name` (the tag lists the chosen `next` values). The `.jsonl` file is blocked by the extension rule in `.htaccess` (line 41). Mail failure does not lose the lead; it is already on disk.

### Plan pipeline

1. `finish_intake` with `plan` makes the session call `postLead` (`tools.mjs` 167-180). It POSTs `{sessionId, submittedAt, lead}` to `LEAD_WEBHOOK_URL`, which points at the relay's own `/plan`, with header `x-oracle-signature` = hex HMAC-SHA256 of the raw body using `TICKET_SECRET`. 60 second timeout. Failures are logged, never thrown into the session.
2. `POST /plan` (`server.mjs` 143-171): body limit 20 KB, signature check with `timingSafeEqual` (401 on mismatch), lead re-validated (400), 503 if `RESEND_API_KEY` is unset, then caps: 3 per email per UTC day and `MAX_PLANS_PER_DAY` (default 100) globally. Both caps are in memory per instance. 429 when hit.
3. `plan.mjs` `generatePlan`: Vertex `gemini-3.8-flash` (`PLAN_MODEL`) at location `global` (`PLAN_LOCATION`), `responseSchema` where each pick's `id` is an enum of `catalogue.json` ids, `maxOutputTokens` 8192, `thinkingConfig.thinkingLevel: "low"`, 20 second timeout.
4. `validatePlan` (88-112) accepts the output only if: exactly 3 distinct catalogue ids, valid effort bands, length caps, no banned words, no vendor or tool names (denylist), no links or `@`, and every digit run appears in the visitor's own words. Otherwise `fallbackPlan`: deterministic keyword scoring over the catalogue plus a default trio. The server fills titles and URLs from the catalogue; the model supplies only ids and prose.
5. `pdf.mjs`: PDFKit with bundled Inter (`oracle-relay/fonts`, OFL). Glyphs the font lacks are swapped out. The committed layout is 2 pages (`pdf.mjs` line 17).
6. `mail.mjs`: Resend, from `VoxDonna <hello@send.voxdonna.com>`, reply-to hello@voxdonna.com, bcc hello@voxdonna.com, PDF attached. If any step after the cap was taken fails, the cap is refunded and the response is 502 `plan_failed`.
7. Logs `plan_sent` with `sessionId`, `source` (llm or fallback), `bytes`, `ms`. No PII. Fallback reasons are logged as `plan_fallback` (`vertex_<status>`, `finish_<reason>`, `bad_json`, or a validation reason).

### Secrets and environment

- Secret Manager: `oracle-ticket-secret` (mounted as `TICKET_SECRET`, signs tickets and the webhook) and `oracle-resend-key` (mounted as `RESEND_API_KEY`). Names only here; values never go in the repo or this doc. `RESEND_API_KEY` mounting is not in `oracle-relay/README.md`; the name is from the deploy.
- Env read by `loadConfig`: `TICKET_SECRET` (required), `GCP_PROJECT`, `GCP_LOCATION`, `LIVE_MODEL`, `AUTH_MODE`, `PORT`, `ALLOWED_ORIGINS`, `MAX_SESSION_SECONDS`, `IDLE_SECONDS`, `SILENCE_SECONDS`, `SILENCE_GRACE_SECONDS`, `VOICE_NAME`, `VOICE_LANGUAGE`, `CAP_GRACE_SECONDS`, `MAX_CONCURRENT`, `LEAD_WEBHOOK_URL`, `PLAN_MODEL`, `PLAN_LOCATION`, `RESEND_API_KEY`, `MAX_PLANS_PER_DAY`, `TRUST_PROXY`, `UPSTREAM_URL`. Table in `oracle-relay/README.md` lines 38-60.
- Privacy page lists Vertex AI (US, `us-central1`) and Resend as processors (`privacy.html` ~lines 528-529). Audio is not stored by VoxDonna.

## Run and verify

Relay tests (no network, fake upstream and fake fetch):

    cd oracle-relay && node --test

2026-11-06 result: 101 tests, 101 pass, 0 fail.

Front end without the relay: open the homepage with `?engine=mock`.

No project-wide type checker or linter is configured.

Verified live on 2026-11-06:

- A signed `/plan` request delivered an LLM-generated PDF to a real inbox, not spam.
- A forged signature returned 401.
- A silent session ended after about 21 seconds (10 + 8 plus connect time).
- A resume trace continued at the website field.
- A text-driven full flow ended with "Book a call": `intake_complete ["call"]`, then `navigate book_meeting`.

Not verified live: see Known gaps.

## Operations

- Site: push to `main`; Hostinger webhook deploys in about 10 seconds.
- Relay, from `oracle-relay/`:

      gcloud run deploy oracle-relay --source . --project=voxdonna-oracle --region=us-central1 --account=suyash@voxdonna.com --max-instances=3 --build-service-account=projects/voxdonna-oracle/serviceAccounts/oracle-build@voxdonna-oracle.iam.gserviceaccount.com --quiet

  Existing settings (env vars, secrets, `--no-invoker-iam-check`) carry over between deploys. The Dockerfile copies files by name, so a new `.mjs` module must be added to its `COPY` line.
- Logs are JSON lines: `session_start`, `session_end` (`reason`, `durationMs`, `intakeComplete`, `usage`), `lead_webhook`, `plan_sent`, `plan_fallback`, `plan_failed`, `upstream_closed`, `upstream_error`. Audio, transcripts, emails and tokens are never logged.
- Leads: `.oracle-leads.jsonl` on Hostinger plus the hello@ mail.

## Known gaps

- The plan and demo choice paths were not traced live after the new ending flow. Only the call path was.
- Donna promises a "3-page automation plan" (`instructions.md` line 38) but the committed PDF is 2 pages (`pdf.mjs` line 17, `mail.mjs` body text). The 3-page layout is built but uncommitted, pending the owner's approval. Until it ships, the spoken promise and the PDF disagree.
- Plan caps are in memory per instance, so the real ceiling is up to 3x with three instances. Move the counters to Firestore if abused (`server.mjs` 102-103).
- A `<no speech detected>` transcription artefact can show as a caption. Not filtered yet; no code in the repo handles it.
- When demo and call are both chosen, Donna goes to booking only.
- The navigate guard is a keyword heuristic: it can let through an intake answer that contains "website" or "call", and block a request with none of the words.
- The silence caption hard-codes "10 seconds".
- The Resend key was exposed in chat during setup and must be rotated.
- No budget alert yet on `voxdonna-oracle` (a 2,000 rupee alert is planned).
- `catalogue.json` effort bands need owner review.
- Privacy page says Resend processing "may include the United States"; the actual Resend region is unverified.
- hello@ bcc delivery on plan emails is unconfirmed.
- An unused Developer API key, `oracle-live-prod`, should be deleted.

## Lessons

| # | Finding | Status |
| --- | --- | --- |
| 1 | Vertex Gemini flash text models returned 404 at `us-central1` and worked at location `global` (host `aiplatform.googleapis.com`). Local calls with user credentials need the header `x-goog-user-project`. | Verified |
| 2 | Thinking tokens count against `maxOutputTokens`. The plan JSON was truncated, `JSON.parse` threw, and every plan silently fell back. Fix: `maxOutputTokens` 8192, `thinkingLevel` low, and log `finishReason` and `bad_json` as fallback reasons so it cannot hide again. | Verified |
| 3 | The browser mic streams silence frames continuously, so an audio-frame idle timer never fires. Key silence off transcribed speech. A hard hang-up mid-form felt broken, so it is nudge first, then a grace window. | Verified |
| 4 | The relay emits `listening` right after a tool call, before the model speaks. Any UI action tied to "Donna finished" must wait for a `speaking` then `listening` transition. | Verified |
| 5 | Prompt rules alone did not stop the Live model calling `navigate` mid-intake. A server-side intent-word guard on the visitor's last turn did. | Verified |
| 6 | The Live model fills placeholders ("N/A") and native-script values (Devanagari) that break a Latin PDF font. Reject them in the server-side tool validator, not only in the prompt. | Verified |
| 7 | LLM grounding for the plan: the model picks only catalogue enum ids, the server fills titles and URLs, any digit must exist in the visitor's words, and any failure falls back to a deterministic plan. | Verified |
| 8 | A secret existing is not the secret being valid. The first stored Resend secret was the literal placeholder; only a real API call showed it. Curly quotes in a pasted shell command broke it and exposed the key in chat. | Verified |
| 9 | Org policy blocks service-account keys, so Vertex calls stay on Cloud Run's runtime identity. Hostinger PHP cannot call Vertex, which is why plan generation lives in the relay. | Verified |
| 10 | Plan generation is a separate HTTP request to the relay's own `/plan`, so it does not depend on the voice WebSocket staying open. This is the design reason. Whether Cloud Run keeps CPU after the socket closes was not measured separately. | Design rationale, unmeasured |
| 11 | Local `main` was diverged and dirty, so all work was done in git worktrees cut from `origin/main`. | Verified |
