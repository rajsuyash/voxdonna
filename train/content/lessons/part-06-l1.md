In the first half of this chapter you learned how conversations, Projects, and Artifacts structure your work in Claude. This second half goes deeper into the capabilities that turn Claude from a chat partner into a working analyst: uploading and processing files, understanding images, running real code against your data, searching and researching the web, and — the biggest shift of 2026 — delegating multi-step work to agentic features such as Routines and Cowork. Each section starts with the fundamentals and builds to the practices enterprise power users rely on. Limits and plan gates are noted as of August 2026 — verify volatile details against current Anthropic documentation.

---

### 5.9 File Uploads: What Claude Accepts and How It Processes It

The fastest way to make Claude useful is to hand it your actual documents. Drag files into the chat composer (or use the attachment icon) and Claude reads them as part of your conversation.

#### Supported file types

| Category | Types | Notes |
|---|---|---|
| Documents | PDF, DOCX, TXT, MD, HTML, ODT, RTF, EPUB | Text extraction; PDFs get special tiered handling (below) |
| Data | CSV, TSV, JSON, XLSX | **XLSX requires "code execution and file creation" to be enabled** in your account (Claude Help Center, "Upload files to Claude") |
| Images | JPEG, PNG, GIF, WebP | Up to 8000 × 8000 pixels |
| Code | Any code file | Treated as plain text |

**Not supported as uploads:** PowerPoint (.pptx), ZIP archives, video, and audio files. Claude can *create* .pptx files via code execution, but cannot ingest them — convert slides to PDF first. For audio/video, transcribe externally (or use voice dictation, covered later) and upload the text (Claude Help Center, Aug 2026).

#### Limits (as of August 2026 — verify; these changed during 2026)

| Limit | Value |
|---|---|
| File size (chat uploads) | **500 MB per file** — raised from the long-standing 30 MB cap during 2026; older guides still cite 30 MB |
| Files per chat | Up to **20 files** (paid plans); third-party comparisons report ~5 per chat on Free |
| Image dimensions | Up to 8000 × 8000 px; 20 images per message |
| PDF length | Up to 1000 pages |
| Project knowledge files | 30 MB per file, unlimited count, total must fit the context window (RAG expands effective capacity ~10×) |
| API Files API (Beta) | 500 MB per file, server-side persistence via `file_id` |

> **Caveat — the 30 MB / 500 MB conflict.** Anthropic's code-execution help article still states a 30 MB maximum per file *for uploads and downloads passing through the code-execution sandbox*, while the upload article states 500 MB for chat attachments generally. Read this as: chat attachments up to 500 MB; files moved into (or created by) the sandbox capped at 30 MB. Two official pages are not fully reconciled — verify if your workflow depends on it.

#### How PDFs are processed: the three tiers

PDF handling is tiered by page count, and the tier determines whether Claude *sees* your document or merely *reads* it (Claude Help Center):

1. **1–100 pages:** Claude analyzes **both text and visual elements** — images, charts, and graphics on each page.
2. **101–1000 pages:** Claude processes **text only**; charts and figures are not analyzed.
3. **Over 1000 pages:** upload rejected ("file is too large"). Split the document.

Practical implications: keep visually rich documents (annual reports, design decks exported to PDF) under 100 pages when the charts matter. For long text-only documents, split by chapter and use a Project so Claude can draw on all parts. When referencing pages, use the page numbers **as shown in the PDF viewer**, not the numbers printed on the page. For non-PDF documents, note that extraction is text-only — embedded images inside a DOCX are not read.

:::exercise Try it: file triage
1. Export any slide deck as PDF (if over 100 pages, split it) and upload it to a new chat.
2. Ask: "Summarize the argument of this document in five bullets, then list every claim supported by a chart, citing the PDF page number."
3. Upload a CSV alongside it and ask Claude to reconcile the two ("Does the data support the claim on page 12?"). Observe which file types trigger the code-execution environment.
:::

---

### 5.10 Vision: Images, OCR, Charts, and Design Review

Claude's vision capability lets it interpret images you upload — photographs, screenshots, scanned pages, diagrams — and reason about them in natural language.

#### What vision does well

- **Document and screenshot understanding:** reading dense pages, forms, and UI screenshots. On Claude 4.7-and-later models, a high-resolution vision tier processes images up to a 2576 px long edge (about 3.75 MP), marketed for computer use, screenshot understanding, and dense documents (platform.claude.com vision docs).
- **Charts and diagrams:** extracting trends, axes, and approximate values from plots; explaining flowcharts, architecture diagrams, and Mermaid sources.
- **UI analysis and design review:** a documented workflow is to paste a screenshot and ask Claude to first describe the UI elements, then infer the user journey, then propose UX improvements. Anthropic Labs' **Claude Design** (Research Preview, Apr 2026; Pro/Max/Team/Enterprise), powered by Opus 4.7, extends this — it reads design files to extract fonts, colors, and components and produces interactive prototypes and wireframes (support.claude.com; third-party corroboration).

#### OCR and handwriting

Claude performs optical character recognition (OCR) — converting text in images to machine-readable text — as part of vision. On printed and typed documents, third-party benchmarks put accuracy at roughly 95% or better. Handwriting is harder: an independent 2026 benchmark measured Claude Sonnet 4.6 vision at about **11% word error rate (WER)** on standard handwritten English prose — competitive with general cloud OCR but well behind dedicated handwriting-OCR tools (~1% WER) (handwritingocr.com, 2026; independent benchmark, not Anthropic-published). Roboflow's July 2026 OCR benchmark ranked Claude Fable 5 highest among tested models at 94.0%. Treat these numbers as directional third-party measurements.

**Known limitations (official):** Claude can err or hallucinate on low-quality, rotated, or very small images (under ~200 px); object counting is approximate; it cannot identify people in images, cannot judge whether an image is AI-generated, and should not be used to interpret complex diagnostic scans such as CT or MRI (platform.claude.com vision docs).

**Getting the best results:**

1. Use clear images, at least 1000 × 1000 px; avoid heavy JPEG compression on text.
2. Place images **before** the text of your prompt.
3. Crop or pre-resize; if you send many images, keep each under ~2000 px per dimension.
4. For handwriting, tell Claude the context ("this is a doctor's referral note from 1987") — context materially improves transcription.

:::exercise Try it: OCR reality check
1. Photograph or scan a page containing a table and a short handwritten note.
2. Prompt: "Transcribe the handwritten note verbatim inside a quote block. Then extract the table as CSV. Flag any words or cells you are unsure of with [?]."
3. Compare against the original. Note where errors cluster (cursive, faded ink, small fonts) — that tells you where human verification is mandatory in production workflows.
:::

---
