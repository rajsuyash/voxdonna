# VoxDonna LinkedIn Company Page — weekly text drafter

(Migrated 2026-07-06 from Paperclip routine `linkedin-runner-linkedin-company-page-content-drafter`. Runs as OpenClaw cron job `voxdonna-linkedin-drafter`, Mon 11:00 UTC. Output feeds `voxdonna/scripts/linkedin-post.py` which auto-publishes via Publer daily.)

Publer posts PLAIN TEXT only. Produce only finished, ready-to-publish text posts. Carousel / video / poll / image formats are OUT OF SCOPE — skip those ideas entirely.

## Read brand voice first

```bash
cat /home/suyashraj/clawd/voxdonna/SOUL.md
cat /home/suyashraj/clawd/voxdonna/LINKEDIN_GROWTH_PLAN_90D.md
```

## Steps

1. Count entries (`## li-` headings) in `/home/suyashraj/clawd/voxdonna/linkedin/queue.md`. If >= 8, reply "queue depth OK, no draft needed" and stop.

2. Draft 5 new medium-form text posts in Donna voice (300-800 chars each; customer story / contrarian take / industry observation).

3. Every draft MUST pass Donna voice rules (SOUL.md):
   - One specific number
   - No em-dashes
   - No AI-vocab (delve, robust, comprehensive, leverage, etc.)
   - No "thrilled / excited / honored to announce"
   - Hook in first 1-2 lines (feed truncates ~210 chars)
   - Short paragraphs (1-2 sentences max)
   - End with confident statement, not a question

4. HARD OUTPUT FORMAT RULES:
   - ONE complete prose post per queue entry; first non-blank line = finished hook sentence, NOT a label.
   - Heading: `## li-NNN — <one-line topic>` (NNN increments from last existing id in queue.md).
   - Separator: exactly `---` between distinct posts, NEVER inside one post.
   - FORBIDDEN openers (auto-rejected by the poster's `classify_entry`): `SLIDES:`, `SLIDE N:`, `SCRIPT:`, `BODY:`, `VOICEOVER:`, `VO:`, `HOOK:`, `CTA:`, `CAPTION:`, `POST COPY`, and any `[FORMAT/Suggested/Production/Delivery/Pace/Tone/Scene/Shot/Camera/Music/Sound/Transition/Visual/Graphic/Text Overlay/Image ...]` bracket directive.
   - Fewer than 5 valid drafts after 3 tries → stop at fewer. Better fewer good than more garbage.

5. Append surviving drafts to `queue.md` with `li-NNN` ids.

6. Self-validation (mandatory before finishing):
   ```bash
   tail -200 /home/suyashraj/clawd/voxdonna/linkedin/queue.md \
     | grep -cE '^SLIDE [0-9]+:|^SLIDES:|^SCRIPT:|^BODY:|^VOICEOVER:|^VO:|^HOOK:|^CTA:|^CAPTION:|^POST COPY|^\[(FORMAT|Suggested|Production|Delivery|Pace|Tone|Scene|Shot|Camera|Music|Sound|Transition|Visual|Graphic|Text Overlay|Image)\b'
   ```
   MUST return `0`. Otherwise strip the offending entries from queue.md before finishing.

7. Final reply (delivered to Telegram): `📝 LinkedIn drafter — N text posts added, queue depth now X.`
