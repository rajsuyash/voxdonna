#!/usr/bin/env node
// VoxDonna X mention monitor — single run (node port of mention_monitor_run.py).
// Polls GET /2/users/{me}/mentions since data/last_mention_id, appends to inbox.jsonl,
// fires Telegram alerts per priority score. Never auto-replies.

import { createHmac, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, appendFileSync, existsSync } from "node:fs";

const REPO = "/home/suyashraj/clawd/voxdonna";
const LAST_ID = `${REPO}/data/last_mention_id`;
const INBOX = `${REPO}/data/inbox.jsonl`;
const MY_ID = readFileSync(`${REPO}/data/my_user_id`, "utf8").trim();

const ESCALATION = ["lawsuit", "trademark", "infringement", "gdpr", "compliance", "data breach"];
const POSITIVE = ["love", "great", "recommend", "awesome", "amazing"];

const CK = process.env.TWITTER_API_KEY;
const CS = process.env.TWITTER_API_SECRET;
const AT = process.env.TWITTER_ACCESS_TOKEN;
const ATS = process.env.TWITTER_ACCESS_TOKEN_SECRET;
const TG_BOT = process.env.TELEGRAM_BOT_TOKEN;
const TG_CHAT = process.env.TELEGRAM_CHAT_ID;

function pctEnc(s) {
  return encodeURIComponent(s).replace(/[!*'()]/g, c => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

function oauth1Header(method, url, params) {
  const oauthParams = {
    oauth_consumer_key: CK,
    oauth_nonce: randomBytes(16).toString("hex"),
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_token: AT,
    oauth_version: "1.0",
  };
  const all = { ...params, ...oauthParams };
  const paramStr = Object.keys(all).sort().map(k => `${pctEnc(k)}=${pctEnc(all[k])}`).join("&");
  const base = `${method.toUpperCase()}&${pctEnc(url)}&${pctEnc(paramStr)}`;
  const signingKey = `${pctEnc(CS)}&${pctEnc(ATS)}`;
  const sig = createHmac("sha1", signingKey).update(base).digest("base64");
  oauthParams.oauth_signature = sig;
  const header = "OAuth " + Object.keys(oauthParams).sort()
    .map(k => `${pctEnc(k)}="${pctEnc(oauthParams[k])}"`).join(", ");
  return header;
}

async function tg(text) {
  try {
    const r = await fetch(`https://api.telegram.org/bot${TG_BOT}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: TG_CHAT, text, disable_web_page_preview: true }),
    });
    if (!r.ok) {
      console.error(`[tg-err] ${r.status} ${await r.text()}`);
      return false;
    }
    return true;
  } catch (e) {
    console.error(`[tg-err] ${e.message}`);
    return false;
  }
}

function score(text, followers) {
  let s = 0;
  const why = [];
  const lc = (text || "").toLowerCase();
  if (followers > 100000) {
    s += 5;
    why.push(`>100K followers (${followers})`);
  }
  for (const kw of ESCALATION) {
    if (lc.includes(kw)) {
      s += 3;
      why.push(`escalation:${kw}`);
      break;
    }
  }
  for (const cue of POSITIVE) {
    if (lc.includes(cue)) {
      s += 2;
      why.push(`positive:${cue}`);
      break;
    }
  }
  return { s, why };
}

async function main() {
  const params = {
    max_results: "20",
    "tweet.fields": "created_at,author_id,public_metrics,text",
    expansions: "author_id",
    "user.fields": "username,name,public_metrics",
  };
  const since = existsSync(LAST_ID) ? readFileSync(LAST_ID, "utf8").trim() : "";
  if (since) params.since_id = since;

  const baseUrl = `https://api.twitter.com/2/users/${MY_ID}/mentions`;
  const qs = Object.entries(params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
  const auth = oauth1Header("GET", baseUrl, params);

  const r = await fetch(`${baseUrl}?${qs}`, { headers: { Authorization: auth } });
  const rl = r.headers.get("x-rate-limit-remaining");
  console.error(`STATUS ${r.status} rl-remaining=${rl}`);

  if (r.status === 429) {
    console.log(JSON.stringify({ error: "rate_limited" }));
    process.exit(2);
  }
  const bodyText = await r.text();
  if (r.status !== 200) {
    console.log(JSON.stringify({ error: r.status, body: bodyText.slice(0, 500) }));
    process.exit(1);
  }
  const body = JSON.parse(bodyText);
  const tweets = body.data || [];
  const usersArr = (body.includes && body.includes.users) || [];
  const users = Object.fromEntries(usersArr.map(u => [u.id, u]));
  const meta = body.meta || {};

  let newCount = 0, alerts = 0, priorityAlerts = 0, hasEsc = false;

  for (const t of tweets) {
    const author = users[t.author_id] || {};
    const followers = (author.public_metrics || {}).followers_count || 0;
    const handle = author.username || "unknown";
    const text = t.text || "";
    const { s: sc, why } = score(text, followers);
    if (ESCALATION.some(k => text.toLowerCase().includes(k))) hasEsc = true;

    const row = {
      ts: Math.floor(Date.now() / 1000),
      tweet_id: t.id,
      author_id: t.author_id,
      author_handle: handle,
      author_followers: followers,
      created_at: t.created_at,
      text,
      score: sc,
      score_reasons: why,
    };
    appendFileSync(INBOX, JSON.stringify(row) + "\n");
    newCount++;

    const url = `https://x.com/${handle}/status/${t.id}`;
    if (sc >= 5) {
      await tg(
        `🔴 PRIORITY MENTION [id: m-${t.id}]\n` +
        `From: @${handle} (${followers} followers)\n` +
        `Their tweet: "${text}"\n` +
        `URL: ${url}\n` +
        `Score: ${sc} (${why.join(", ")})\n` +
        `Action: human review required. No auto-draft.`
      );
      alerts++; priorityAlerts++;
    } else if (sc >= 3) {
      await tg(
        `📝 MENTION [id: m-${t.id}]\n` +
        `From: @${handle} (${followers} followers)\n` +
        `Their tweet: "${text}"\n` +
        `URL: ${url}\n` +
        `Score: ${sc} (${why.join(", ")})\n` +
        `Reply /draft m-${t.id} to request a draft, /reject m-${t.id} to ignore.\n` +
        `(No reply will be posted without explicit /approve.)`
      );
      alerts++;
    }
  }

  if (meta.newest_id) writeFileSync(LAST_ID, meta.newest_id);

  console.log(JSON.stringify({
    new_mentions: newCount,
    alerts_sent: alerts,
    priority_alerts: priorityAlerts,
    escalation_keyword_seen: hasEsc,
    newest_id: meta.newest_id || null,
    rate_limit_remaining: rl,
  }));
}

main().catch(e => { console.error(e); process.exit(1); });
