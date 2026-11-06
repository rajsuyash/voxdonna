# oracle-relay

WebSocket relay between website visitors and Vertex AI Gemini Live (speech-to-speech). It authenticates to Vertex with its Cloud Run runtime identity (ADC, scope `cloud-platform`), keeps Donna's instructions and tools private, and enforces limits.

Browser contract v1: `POST /ticket` then WebSocket `/live?ticket=...`. `GET /health` for health (`/healthz` also works locally, but Cloud Run's front end reserves paths ending in `z`, so use `/health` on the live URL).
`wsUrl` returned by `/ticket` is the full ready-to-use URL including the ticket. The relay also accepts a client that appends `?ticket=` again.

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
| `IDLE_SECONDS` | 45 | No client audio/text frames -> `ended:"idle"`. |
| `MAX_CONCURRENT` | 20 | Per instance; extra upgrades get 503. |
| `LEAD_WEBHOOK_URL` | unset | Gets `{sessionId, submittedAt, lead}` with `X-Oracle-Signature` = hex HMAC-SHA256 of the raw body using `TICKET_SECRET`. 5s timeout, failures logged only. |
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

JSON lines: `session_start`, `session_end` (`reason`, `durationMs`, `usage` from Gemini `usageMetadata`, `intakeComplete`), `lead_webhook`, `upstream_closed`, `upstream_error`. Audio, transcripts, emails and tokens are never logged.
