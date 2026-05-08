# Voxdonna — Claude Project Instructions

## Design System

**Always read `DESIGN.md` before making any visual or UI decisions.**

All font choices, colors, spacing, motion approaches, and aesthetic direction are defined there. Do not deviate without explicit user approval. In QA mode, flag any code that doesn't match `DESIGN.md`.

Key constants (full reference in DESIGN.md):
- Display headlines: **Instrument Serif** 400 (italic for accent words)
- Body + UI: **Inter** 300-800
- Mono / scramble: **JetBrains Mono** (intentional techie texture)
- Brand accent: copper `#c17f59` (primary), `#d4a574` (light)
- Background: `#0a0a0c` (warm black, never `#000`)
- Dark-mode-only

## Project Stack

- Static HTML + CSS + vanilla JS (no React, no build step)
- GSAP 3.12.5 + ScrollTrigger for motion
- Hosted on Hostinger (`voxdonna.com`) with GitHub-driven webhook deploys
- ElevenLabs Conversational AI for voice agents (12 demo agents in `demos.html`)
- Blog posts in markdown at `blog/{en,fr,it}/`, rendered by `blog-post.html`
- Knowledge bases in `kb/` (one `.md` per voice agent, attached via ElevenLabs API)

## Deployment

- Push to `main` → GitHub webhook → Hostinger PHP receiver pulls + redeploys (~10s)
- If webhook stalls: SSH to Hostinger and `git fetch origin && git merge --ff-only origin/main`
- See `hostinger-claude-agent-guide.md` for full deploy notes (PHP `proc_open`, cache-bust pattern, rate-limit recovery)

## Voice Agents

- All demo agents use **Jessica** voice (`cgSgspJ2msm6clMCkdW9`) + `eleven_turbo_v2` + stability 0.35 (set May 2026 — was robotic flash_v2 with 0.5 before)
- Multilingual demo keeps Rachel (`21m00Tcm4TlvDq8ikWAM`) — needs multilingual support
- Each agent has a scenario-specific KB attached from `kb/<slug>.md`
- API key in `.env` (`ELEVENLABS_API_KEY` with convai_write scope)

## Brand Voice (writing)

- Builder-tone, never corporate. No AI clichés.
- **Banned words:** delve, robust, comprehensive, nuanced, multifaceted, leverage, pivotal, landscape, intricate, vibrant, fundamental, significant.
- Short paragraphs. Concrete examples. Real numbers with sources.
- Code follows the same rule: no comments unless the WHY is non-obvious.
