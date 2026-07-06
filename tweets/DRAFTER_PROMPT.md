# VoxDonna Twitter/X — weekly drafter

(Runs as OpenClaw cron job `voxdonna-twitter-drafter`, Mon 09:00 UTC. Output feeds `voxdonna/scripts/post-next-tweet.py`, which posts ONE tweet per weekday at 12:00 Paris to @voxdonna via X API.)

## Read brand voice first

```bash
cat /home/suyashraj/clawd/voxdonna/SOUL.md
```

## Steps

1. Count entries (`## ` headings) in `/home/suyashraj/clawd/voxdonna/tweets/queue.md`. If >= 8, reply "queue depth OK, no draft needed" and stop.

2. Skim `/home/suyashraj/clawd/voxdonna/tweets/posted.md` (last ~20) — never repeat a topic or hook.

3. Draft 5 new tweets in Donna voice. Topic mix across: missed-call/inbound-cost stats (cited only), voice-AI contrarian takes (IVR, hold music, voicemail), customer proof (Le Marquier, care-home concierge, manufacturer order-status), pricing transparency, "talk to Donna" CTA (max 1 per batch, link https://voxdonna.com/demos.html).

4. Rules per tweet:
   - ≤ 280 chars TOTAL. Count carefully.
   - Donna voice: present tense, diagnosis not argument, one specific number where natural, confident ending, no question-endings.
   - No em-dashes, no AI-vocab (delve, robust, leverage...), no hashtags, no "thrilled/excited", max 1 emoji per batch.
   - Never fabricate a statistic — cite-able numbers only, else omit.
   - Format in queue.md: `## NNN — <topic slug>` heading (NNN increments from last id across queue.md AND posted.md), body lines, then `---` separator.

5. Append the drafts to `queue.md`.

6. Self-check: every appended body ≤ 280 chars (`awk` or python check). Fix any overage before finishing.

7. Final reply (delivered to Telegram): `🐦 Twitter drafter — N tweets added, queue depth now X.`
