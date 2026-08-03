### Section 4 — Files, Vision & Data

**Q31.** Which file type requires "code execution and file creation" to be enabled before uploading to claude.ai?
A) PDF
B) CSV
C) XLSX
D) DOCX

**Q32.** What are the current chat-upload limits on claude.ai (as of 2026 — recently raised)?
A) 30 MB per file, 5 files per chat
B) 500 MB per file, up to 20 files per chat
C) 100 MB per file, 10 files per chat
D) 1 GB per file, unlimited count

**Q33.** How does Claude process a 450-page PDF uploaded to chat?
A) Full text + visual analysis of every page
B) Text only — PDFs from 101 to 1000 pages are processed text-only
C) It is rejected
D) Only the first 100 pages are read

**Q34.** Which set of image formats is supported for upload?
A) JPEG, PNG, GIF, WebP
B) JPEG, PNG, TIFF, BMP
C) PNG, HEIC, RAW, WebP
D) Any format under 5 MB

**Q35.** Which vision task is documented as a limitation of Claude?
A) Reading charts in a PDF
B) Identifying or naming a person in an image
C) Describing a UI screenshot
D) Transcribing legible printed text

**Q36.** What applies to images analyzed by Claude 4.7-and-later models?
A) They are capped at 1568 px like older models
B) A high-resolution vision tier (max long edge 2576 px, up to 4784 visual tokens) applies automatically
C) Vision requires a separate paid add-on
D) Only the first frame of GIFs is unsupported

**Q37.** A user uploads a .pptx file expecting Claude to read the slides. What happens?
A) Claude reads text and images from the slides
B) PPTX is not a supported upload type; Claude can create .pptx via code execution, but cannot ingest it as a native upload
C) Claude converts it to PDF automatically
D) Only Enterprise plans can upload PPTX

**Q38.** In the claude.ai code-execution sandbox, what is the default network posture by plan?
A) Network fully open on all plans
B) On by default with an approved-domain list for Free/Pro/Max; off by default for Team/Enterprise
C) Off for all plans with no override
D) Network only for Enterprise

**Q39.** Can Claude generate a photorealistic image from a text prompt?
A) Yes, on Max plans
B) No — Claude does not generate or edit raster images; it produces SVG, Mermaid, charts, and interactive visuals via Artifacts/code
C) Yes, via the Files API
D) Only in Claude Design

**Q40.** A legal team must review a 90-page scanned contract with dense tables. Which approach fits documented behavior?
A) Upload it — PDFs of 100 pages or fewer get both text and visual (image/chart) analysis
B) Split it into 10-page chunks because the limit is 30 pages
C) Convert it to audio first
D) It cannot be processed because it is scanned

---

### Section 5 — Connectors & Integrations

**Q41.** Technically, what is a Claude connector?
A) A browser extension
B) A (usually remote) MCP server exposing tools/resources/prompts that Claude discovers dynamically
C) A Zapier-only webhook
D) A local plugin compiled into the app

**Q42.** From where does Claude reach remote connector servers?
A) The user's local machine
B) Anthropic's cloud infrastructure — endpoints behind VPNs, firewalls, or IP allowlists may fail
C) The user's browser only
D) A regional edge device

**Q43.** When did Anthropic launch the Connectors Directory, and which builders were among the first additions?
A) July 14, 2025 — including Notion, Canva, Figma, Socket, and Prisma
B) May 1, 2025 — including Jira and Zapier
C) January 26, 2026 — including Slack
D) April 2026 — including Spotify

**Q44.** What did the original "Integrations" launch (May 1, 2025) include?
A) 10 launch partners such as Atlassian (Jira/Confluence), Zapier, Intercom, Asana, Square, Sentry, PayPal, Linear, Plaid, and Cloudflare
B) Only Google Workspace
C) 800+ connectors
D) Local desktop extensions only

**Q45.** What can Claude do with a connected Gmail account?
A) Send email on your behalf
B) Search, read, and summarize threads and create drafts — but not send
C) Read attachments natively
D) Delete messages

**Q46.** A user's effective permission through a connector equals:
A) Whatever the MCP server allows
B) The intersection of the user's source-system permissions, granted OAuth scopes, the MCP tool design, and Claude-side admin/user controls
C) The org admin's permissions
D) Unrestricted access to the connected system

**Q47.** What are "MCP Apps" (launched January 26, 2026)?
A) Anthropic's mobile apps
B) Interactive tools — an open MCP extension rendering live UI inside Claude, with launch apps including Amplitude, Asana, Box, Canva, Figma, and Slack
C) A deprecated SSE transport
D) A billing tier

**Q48.** What is required before Claude can use the Microsoft 365 connector in a Team/Enterprise org?
A) Only the end user signs in
B) The org Owner enables the connector, an Entra Global Administrator grants tenant-wide admin consent, and users connect individually
C) A Microsoft Copilot license
D) Nothing — it is on by default

**Q49.** How many custom remote MCP connectors can a Free-plan user add (per 2026 documentation)?
A) Zero
B) One
C) Five
D) Unlimited

**Q50.** Is web search implemented as an MCP connector?
A) Yes, listed in the directory
B) No — web search is a built-in Anthropic-managed capability, not an MCP connector
C) Yes, but only on Enterprise
D) Only via the Brave connector

---

### Section 6 — MCP & API

**Q51.** Which three participants does MCP define?
A) Producer, consumer, broker
B) Host, client, server
C) Frontend, backend, database
D) User, model, tool

**Q52.** What are the two current standard MCP transports?
A) WebSocket and gRPC
B) stdio and Streamable HTTP
C) HTTP+SSE and WebSocket
D) TCP and UDP

**Q53.** Which headers does every Claude API request require?
A) `Authorization: Bearer` and `anthropic-version`
B) `x-api-key`, `anthropic-version`, and `Content-Type: application/json`
C) `x-api-key` only
D) `api-key` and `x-request-id`

**Q54.** Which parameter is required in every Messages API request body?
A) `temperature`
B) `max_tokens`
C) `system`
D) `stream`

**Q55.** In MCP, what distinguishes the three server primitives (tools, resources, prompts)?
A) Their latency
B) The control plane — tools are model-controlled, resources are host/application-controlled, prompts are user-controlled
C) Their transport
D) Their cost

**Q56.** What discount does the Batch API provide, and within what time are results delivered?
A) 25% off; 1 hour
B) 50% off input and output tokens; results within 24 hours (most under 1 hour)
C) 50% off input only; 48 hours
D) Free; 1 week

**Q57.** What are the prompt-caching TTL options and their price multipliers?
A) 1 minute (1x) or 1 day (3x)
B) 5-minute write at 1.25x base input, 1-hour write at 2x, cache reads at 0.1x
C) 5-minute only, at 0.5x
D) Unlimited TTL at 1x

**Q58.** A streaming API client checks only the HTTP status code for errors. What can it miss?
A) Nothing — status codes cover all errors
B) `overloaded_error` delivered as an in-stream error event after the connection opens with HTTP 200
C) 401 errors
D) Cache invalidation events

**Q59.** Your on-call runbook says "retry 429s immediately and treat 529s as client bugs." What correction is needed?
A) None — that is correct
B) 429 is your rate-limit problem (respect `retry-after`); 529 is Anthropic-wide overload — retry 529 with capped exponential backoff plus jitter
C) Swap them: 429 is Anthropic's fault
D) Neither is retryable

**Q60.** Which statement about the official MCP Registry is accurate (as of July 2026)?
A) It is a GA, fully vetted security guarantee for listed servers
B) It is still in Preview; a listing does not itself prove security, uptime, or quality — pin versions and verify publishers
C) It was shut down in 2026
D) It requires Enterprise membership to publish

---
