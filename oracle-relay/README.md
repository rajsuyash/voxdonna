# oracle-relay

WebSocket relay between website visitors and Vertex AI Gemini Live (speech-to-speech). It authenticates to Vertex with its Cloud Run runtime identity (ADC, scope `cloud-platform`), keeps Donna's instructions and tools private, and enforces limits.

Browser contract v1: `POST /ticket` then WebSocket `/live?ticket=...`. `GET /health` for health (`/healthz` also works locally, but Cloud Run's front end reserves paths ending in `z`, so use `/health` on the live URL).
`wsUrl` returned by `/ticket` is the full ready-to-use URL including the ticket. The relay also accepts a client that appends `?ticket=` again.

## Client -> relay frames

`audio {data}`, `text {text}`, `field_edit {field, value}`, `stop`, and `resume {fields}`.

`resume` is honoured only as the very first client frame (later ones are ignored). Each field is validated like a `save_field` value (invalid ones are dropped), the lead is seeded, a `field` event is echoed per seeded field, and the greeting turn carries a system note listing what is already saved so Donna does not re-ask. The relay holds the upstream setup for up to 400 ms after connect waiting for it; any other first frame releases it immediately. `name`, `company` and `industry` must contain Latin letters (the model is told to transliterate and retry); the PDF font cannot render other scripts.

## Plan email (`POST /plan`)

Server-to-server, not browser: authenticated by `X-Oracle-Signature` (same HMAC as the lead webhook), not by Origin. Body limit 20 KB. Flow: validate lead, ask Vertex for a 3-pick plan from `catalogue.json` (JSON schema output, 20s timeout), validate it (catalogue ids, banned words, no vendor names, no invented numbers), fall back to a deterministic keyword plan on any failure, render a 2-page PDF (`pdf.mjs`, Inter in `fonts/`, OFL), email it via Resend. Responses: 200 `{ok, source: llm|fallback}`, 401 bad signature, 400 bad lead, 413, 429 cap, 503 `mail_not_configured`, 502 send failed.

Real Vertex run locally: `AUTH_MODE=adc` with `gcloud auth application-default login` (or `GOOGLE_APPLICATION_CREDENTIALS`), `GCP_PROJECT`, optional `PLAN_MODEL`.

## Run locally (no Google, fake upstream)

```bash
npm install
npm test
# fake Vertex on a port, then the relay pointed at it
node -e "import('./test/fake-upstream.mjs').then(async m=>{const f=await m.startFakeUpstream();console.log(f.url);setInterval(()=>{},1e6)})"
PORT=8080 TICKET_SECRET=dev AUTH_MODE=none TRUST_PROXY=0 UPSTREAM_URL=ws://127.0.0.1:<fake-port>/ws node server.mjs
curl localhost:8080/health
curl -X POST -H 'Origin: http://localhost:8792' localhost:8080/ticket
```

## Environment

| Var | Default | Notes |
|---|---|---|
| `TICKET_SECRET` | required | HMAC key for tickets and the lead webhook signature. Server refuses to start without it. |
| `PORT` | 8080 | |
| `GCP_PROJECT` / `GCP_LOCATION` / `LIVE_MODEL` | `voxdonna-oracle` / `us-central1` / `gemini-3.8-live` | Region must be us-central1. |
| `UPSTREAM_URL` | Vertex `LlmBidiService/BidiGenerateContent` | Override for tests. |
| `AUTH_MODE` | `adc` | `none` skips the bearer token (fake upstream only). |
| `ALLOWED_ORIGINS` | voxdonna.com, www.voxdonna.com, 127.0.0.1:8792, localhost:8792 | Comma list. Used for CORS, `/ticket` and the WS upgrade. |
| `MAX_SESSION_SECONDS` | 300 | Cap: wrap-up text turn, then `ended:"cap"` after `CAP_GRACE_SECONDS`. |
| `CAP_GRACE_SECONDS` | 8 | |
| `IDLE_SECONDS` | 45 | Backstop: no client audio/text frames -> `ended:"idle"` (a live mic streams frames, so `SILENCE_SECONDS` is what normally fires). |
| `SILENCE_SECONDS` | 10 | Visitor silent this long after Donna finishes a turn (incl. the greeting) -> a nudge (see `SILENCE_GRACE_SECONDS`), not an immediate end. Not running while Donna speaks or calls a tool; reset by visitor speech (input transcription), a `text` frame or a `field_edit`. |
| `SILENCE_GRACE_SECONDS` | 8 | After `SILENCE_SECONDS` of quiet the relay first sends Donna a nudge turn ("ask if they are still there"; one per silence episode). If the visitor is still silent this long after the nudge (restarted when Donna's nudge turn completes) -> `ended:"silence"`. Any visitor speech/text/field edit resets to the first stage. |
| `VOICE_NAME` | `Kore` | Gemini prebuilt voice (`speechConfig.voiceConfig.prebuiltVoiceConfig.voiceName`). Female options include Kore, Aoede, Leda, Zephyr. |
| `VOICE_LANGUAGE` | `en-US` | `speechConfig.languageCode`. |
| `MAX_CONCURRENT` | 20 | Per instance; extra upgrades get 503. |
| `LEAD_WEBHOOK_URL` | unset | Gets `{sessionId, submittedAt, lead}` with `X-Oracle-Signature` = hex HMAC-SHA256 of the raw body using `TICKET_SECRET`. 60s timeout (plan generation + email happen behind it), failures logged only. Point it at this relay's own `/plan`. |
| `PLAN_MODEL` | `gemini-3.8-flash` | Vertex model id for the "what to automate first" plan (`generateContent`). |
| `PLAN_LOCATION` | `global` | Vertex location for plan generation only. `global` uses host `aiplatform.googleapis.com`; any other value uses `<location>-aiplatform.googleapis.com`. The Live API stays on `us-central1`. Requests send `x-goog-user-project: <GCP_PROJECT>`. |
| `RESEND_API_KEY` | unset | Needed for `POST /plan`; without it `/plan` returns 503 `mail_not_configured`. Sends from `hello@send.voxdonna.com`, bcc `hello@voxdonna.com`. |
| `MAX_PLANS_PER_DAY` | 100 | Global daily cap on plan emails (UTC day). Per-email cap is fixed at 3/day. Both in memory per instance (up to 3x with `--max-instances=3`). |
| `TRUST_PROXY` | on | Client IP = last `X-Forwarded-For` entry (the one Cloud Run appends). Set `0` when not behind a proxy. |

## Deploy (Cloud Run, not run by this repo)

```bash
gcloud run deploy oracle-relay \
  --source . \
  --region=us-central1 \
  --service-account=<sa>@voxdonna-oracle.iam.gserviceaccount.com \
  --min-instances=0 --max-instances=3 --concurrency=20 --timeout=600 --session-affinity \
  --allow-unauthenticated \
  --set-env-vars=GCP_PROJECT=voxdonna-oracle,GCP_LOCATION=us-central1 \
  --set-secrets=TICKET_SECRET=oracle-ticket-secret:latest
```

- The service account needs `roles/aiplatform.user`. No key file is used.
- `--timeout=600` must stay above `MAX_SESSION_SECONDS` + `CAP_GRACE_SECONDS`.
- Public access is intended (browsers call it); tickets, origin allow-list and rate limits are the gate.
- Multi-instance ceiling: ticket reuse set, per-IP ticket limits and `MAX_CONCURRENT` are in memory per instance, so with `--max-instances=3` the effective limits can be up to 3x.

## Logs

JSON lines: `session_start`, `session_end` (`reason`, `durationMs`, `usage` from Gemini `usageMetadata`, `intakeComplete`), `lead_webhook`, `plan_sent` (`sessionId`, `source`, `bytes`, `ms`), `plan_fallback` (`reason`), `plan_failed`, `upstream_closed`, `upstream_error`. Audio, transcripts, emails and tokens are never logged.
