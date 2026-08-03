In this chapter you move from *talking to Claude* to *working with Claude*. You will learn how the claude.ai web interface is organized, how to manage and search conversations, how to share chats safely (including a cautionary incident every enterprise user must know), how to use Anthropic's official prompt libraries, and how to master the two features that separate casual users from power users: **Projects** (persistent workspaces) and **Artifacts** (live, rendered output). By the end you will be able to structure an entire team's knowledge around a Project and publish interactive, shareable work products directly from a conversation.

> **Verify-as-you-go note.** Interface details, plan limits, and feature availability described in this chapter are accurate as of August 2026 — verify against current Anthropic documentation before quoting them to stakeholders. Feature status tags used throughout: (GA) generally available, (Beta), (Preview), (Research Preview), (Experimental), (Enterprise only), (Team/Enterprise only).

---

### 5.1 The Web Interface: Navigation and Chat Anatomy

Everything in this section assumes you are signed in at **claude.ai** in a browser. The desktop app (a free download from claude.ai/download for macOS 11+ and Windows 10+, GA) mirrors the web layout and adds three surfaces — **Chat, Cowork, Code** — plus extras like a Quick Entry global shortcut and built-in dictation (claudeai.guide, Jul 2026). This chapter focuses on the Chat surface, which is identical on web and desktop.

#### The sidebar

The left sidebar is your persistent navigation. Since June 2025 it is organized into distinct areas (Anthropic, Jun 2025):

- **Chats** — your conversation history, most recent first. Hover over any chat for rename/delete options.
- **Projects** — your persistent workspaces (Section 5.5). Each project expands to show the chats inside it.
- **Artifacts space** — a dedicated gallery of every artifact you have created, independent of the chat that produced it. Anthropic reported over half a billion artifacts created within a year of GA (Anthropic, Jun 2025).
- **Scheduled** — your scheduled tasks and routines (covered in the automation chapter).

#### The chat interface, element by element

When you open a chat, the main pane contains these UI elements. Since this manual is text-only, learn to recognize them by description:

1. **Model picker** (top of the chat). A dropdown showing the current model. Paid plans let you switch among the available models (e.g., the Opus, Sonnet, and Haiku tiers); Free users get the default tier. *Model availability and naming change frequently — verify the current lineup at anthropic.com as of your reading date.*
2. **Message composer** (bottom center). The text field where you type. **Shift+Enter** inserts a line break; **Enter** (or Cmd/Ctrl+Enter, depending on your settings) sends.
3. **Attachment button** (paperclip or "+" icon in the composer). Opens file upload: PDFs, DOCX, TXT, MD, HTML, CSV, XLSX, JSON, RTF, ODT, EPUB, images (JPEG/PNG/GIF/WebP up to 8000×8000 px), and code files as plain text. Video, audio, and PPTX are *not* supported as input. The per-file upload cap was historically 30 MB and has since been raised — sources in 2026 cite chat uploads up to 500 MB per file (Anthropic Docs, 2026). Per-conversation file counts are plan-gated (roughly 5 files per chat on Free, ~20 on paid plans — Anthropic does not publish exact numbers, so treat these as approximate).
4. **"Search and tools" menu** (a slider/tune icon near the composer). This opens toggles for web search, connectors, extended thinking on supported plans, and **Styles** (Normal, Concise, Formal, Explanatory, or a Custom Style built from your own writing samples — GA, all plans). Anything you toggle here applies per conversation.
5. **Response controls** (under each Claude reply): copy, retry/regenerate, thumbs up/down feedback, and — when Claude produces one — an **artifact panel** that opens on the right side of the screen (Section 5.6).
6. **Share button** (top right of the chat). Creates a public snapshot link — see Section 5.4 before you ever click it in an enterprise context.
7. **Incognito chat** (ghost icon, desktop Chat surface). Starts a session that is not saved to history or memory. Availability on the web app is unconfirmed as of August 2026 — treat as desktop-only unless Anthropic documentation says otherwise.

:::exercise Try it #1: Interface orientation drill
1. Open claude.ai and locate each of the seven elements above. Write down where you found the "Search and tools" menu — many users never discover it.
2. Open the Style picker inside "Search and tools" and switch a single conversation between **Concise** and **Explanatory**. Ask the same question both ways ("Explain what an API rate limit is") and compare the responses.
3. Press **Cmd/Ctrl+K** and type the name of any chat from earlier this week. Jump to it without touching the mouse.
:::

---

### 5.2 Keyboard Shortcuts

Keyboard shortcuts are the cheapest productivity upgrade available to you. The table below lists the commonly used shortcuts on web and desktop. **Caveat:** Anthropic's official shortcut list could not be verified directly for this edition; this table is drawn from reputable secondary sources (eliteaiadvantage.com, May 2026) and should be confirmed in-app — press **Cmd/Ctrl + /** to open the built-in shortcut overlay and compare.

| Action | macOS | Windows/Linux |
|---|---|---|
| Quick navigation / search all chats | Cmd + K | Ctrl + K |
| New chat | Cmd + Shift + N | Ctrl + Shift + N |
| Project switcher | Cmd + Shift + O | Ctrl + Shift + O |
| Show shortcut overlay | Cmd + / | Ctrl + / |
| Edit your last message | Cmd + ↑ | Ctrl + ↑ |
| Send message | Cmd + Enter (or Enter, per settings) | Ctrl + Enter |
| New line inside message | Shift + Enter | Shift + Enter |

Two habits pay for themselves immediately: **Cmd/Ctrl+K** instead of scrolling the sidebar, and **Cmd/Ctrl+↑** to fix a typo in your last prompt instead of starting a new chat.

---

### 5.3 Conversation Management & Search

#### Organizing and deleting chats

Every conversation is saved to your history automatically (unless you use an Incognito chat). Housekeeping basics:

- **Rename** a chat from the sidebar hover menu so it is findable later ("Q3 vendor analysis" beats "New chat").
- **Delete** chats individually, or use the sidebar's multi-select mode to delete in bulk.
- **Move chats into Projects** to group related work (Section 5.5). Chats inside a shared project remain private to you by default — see the collaboration rules in Section 5.5.

#### Searching across past conversations

Claude can search and reference your previous chats directly — you can literally ask, *"Have we ever discussed our refund policy for enterprise contracts?"* and Claude will surface the relevant prior conversation (Northeastern ITS, Sep 2025). Key behaviors:

- The capability is called **"Search and reference chats"** and is on by default. Manage it at **Settings → Capabilities → Memory**.
- It **respects project boundaries**: Claude distinguishes chats that live inside a project from those outside, so a question asked inside your "Legal Review" project does not silently pull in unrelated personal chats.
- You can disable it entirely, and you can manage what Claude remembers at **Settings → Capabilities → Memory** ("Generate memory from chat history," "View and manage memory"). Memory — rolled out to all plans including Free in March 2026 — stores synthesized summaries (your role, preferences, formatting habits), not full transcripts (Syracuse ITS, Jun 2026).

> **Enterprise caution.** On Team and Enterprise plans, your administrator controls data retention policies. Deleting a chat removes it from your view, but retention and audit behavior are governed by your organization's settings — do not assume deletion equals instant erasure from compliance systems.

---
