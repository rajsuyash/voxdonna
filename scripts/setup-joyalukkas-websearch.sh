#!/bin/bash
# scripts/setup-joyalukkas-websearch.sh
# Give the Joyalukkas outbound voice agent live web search, the house way
# (see build-elevenlabs-agent SKILL.md "Live web-search / lookup tool"):
#   1. Provision TAVILY_API_KEY + SCHEME_TOOL_SECRET into local .env AND the
#      live Hostinger .env (the key stays server-side; only the shared secret
#      ever rides in the ElevenLabs tool header).
#   2. Deploy websearch.php (push -> Hostinger webhook pull) and verify it.
#   3. Create the webhook tool -> https://voxdonna.com/websearch.php and attach
#      to the agent (tool_ids), moving system tools to built_in_tools, bump LLM
#      to gpt-4o, append prompt lines for when to search.
# Run it yourself:  bash scripts/setup-joyalukkas-websearch.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# ---- config -----------------------------------------------------------------
AGENT_ID="${JOY_AGENT_ID:-agent_8301krqtkf74ecqthne2r2rvgpbe}"
TOOL_URL="${WEBSEARCH_TOOL_URL:-https://voxdonna.com/websearch.php}"
LLM="${JOY_LLM:-gpt-4o}"
BJP_ENV="/Users/suyashraj/Downloads/07 Tech Projects/BJP Voice Agent/web/.env.local"

# ---- load creds -------------------------------------------------------------
set -a; source .env; set +a
API_KEY="${ELEVENLABS_API_KEY:-}"
[ -z "$API_KEY" ] && { echo "ERROR: ELEVENLABS_API_KEY missing in .env" >&2; exit 1; }

SECRET="${SCHEME_TOOL_SECRET:-}"
[ -z "$SECRET" ] && SECRET=$(openssl rand -hex 24)
TAVILY="${TAVILY_API_KEY:-}"
[ -z "$TAVILY" ] && TAVILY=$(grep -E '^TAVILY_API_KEY=' "$BJP_ENV" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"')
[ -z "$TAVILY" ] && { echo "ERROR: no TAVILY_API_KEY (set it in .env or $BJP_ENV)" >&2; exit 1; }

# ---- 1. provision local + remote .env (idempotent) --------------------------
grep -q '^SCHEME_TOOL_SECRET=' .env || printf 'SCHEME_TOOL_SECRET=%s\n' "$SECRET" >> .env
grep -q '^TAVILY_API_KEY='     .env || printf 'TAVILY_API_KEY=%s\n'     "$TAVILY" >> .env

echo "[1/4] Provisioning live Hostinger .env"
export SSHPASS="$SSH_PASSWORD"
# .env stores WEB_ROOT with a leading ~ which the local shell expanded to the
# local home at source time. Strip the local $HOME and let the SERVER expand $HOME.
SUB="${WEB_ROOT#"$HOME"/}"; SUB="${SUB#\~/}"; SUB="${SUB%/}"   # e.g. domains/voxdonna.com/public_html
SSH="sshpass -e ssh -p $SSH_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=25 $SSH_USER@$SSH_HOST"
# append only if the key is absent on the server ($HOME escaped -> expands remotely)
$SSH "cd \"\$HOME/$SUB\" && grep -q '^SCHEME_TOOL_SECRET=' .env 2>/dev/null" \
  || printf 'SCHEME_TOOL_SECRET=%s\n' "$SECRET" | $SSH "cd \"\$HOME/$SUB\" && cat >> .env"
$SSH "cd \"\$HOME/$SUB\" && grep -q '^TAVILY_API_KEY=' .env 2>/dev/null" \
  || printf 'TAVILY_API_KEY=%s\n' "$TAVILY" | $SSH "cd \"\$HOME/$SUB\" && cat >> .env"
echo "       done (keys present on server: ~/$SUB/.env)"

# ---- 2. deploy the proxy + verify -------------------------------------------
echo "[2/4] Deploying websearch.php"
if [ -n "$(git status --porcelain websearch.php)" ]; then
  git add websearch.php
  git commit -q -m "feat: live web-search proxy (Tavily) for voice agents" || true
  git push -q origin main
fi
echo "       waiting for Hostinger pull + verifying endpoint..."
OK=""
for i in $(seq 1 20); do
  sleep 4
  R=$(curl -sS -m 15 -X POST "$TOOL_URL" -H "Content-Type: application/json" \
        -H "x-scheme-key: $SECRET" -d '{"query":"gold rate today India 22k per gram"}' || true)
  echo "$R" | grep -q '"found"' && { OK=1; echo "       endpoint live: $(echo "$R" | head -c 160)"; break; }
done
[ -z "$OK" ] && { echo "ERROR: websearch.php did not respond with JSON after deploy. Last: $R" >&2; exit 1; }

# ---- 3. create the webhook tool ---------------------------------------------
echo "[3/4] Creating webhook tool -> $TOOL_URL"
export TOOL_URL SECRET
TOOL_PAYLOAD=$(python3 <<'PY'
import json, os
cfg={"tool_config":{
  "type":"webhook","name":"search_web",
  "description":"Search the live web for current information you do not already know: today's gold or silver rate, a current metal price, an ongoing offer, store timings you are unsure of, or recent news. Call it whenever the customer asks for 'today', 'latest', 'current', or a figure not in your knowledge. Pass a short English query in 'query', e.g. 'gold rate today India 22k per gram'.",
  "response_timeout_secs":12,
  "api_schema":{
    "url":os.environ["TOOL_URL"],"method":"POST","content_type":"application/json",
    "request_headers":{"x-scheme-key":os.environ["SECRET"]},
    "request_body_schema":{"type":"object","properties":{
      "query":{"type":"string","description":"Short English web search query."}},"required":["query"]}
  }}}
print(json.dumps(cfg))
PY
)
TOOL_RESP=$(curl -sS -X POST "https://api.elevenlabs.io/v1/convai/tools" \
  -H "xi-api-key: $API_KEY" -H "Content-Type: application/json" -d "$TOOL_PAYLOAD")
TOOL_ID=$(echo "$TOOL_RESP" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('id') or d.get('tool_id',''))")
[ -z "$TOOL_ID" ] && { echo "ERROR: tool create failed: $TOOL_RESP" >&2; exit 1; }
echo "       TOOL_ID: $TOOL_ID"

# ---- 4. attach to agent -----------------------------------------------------
echo "[4/4] Attaching tool + LLM=$LLM to $AGENT_ID"
AGENT_JSON=$(curl -sS "https://api.elevenlabs.io/v1/convai/agents/$AGENT_ID" -H "xi-api-key: $API_KEY")
export AGENT_JSON TOOL_ID LLM
PATCH_BODY=$(python3 <<'PY'
import json, os
agent=json.loads(os.environ["AGENT_JSON"], strict=False)
cc=agent.get("conversation_config",{})
prompt=cc.setdefault("agent",{}).setdefault("prompt",{})

# API rejects both `tools` and `tool_ids`: move system tools to built_in_tools.
existing=prompt.pop("tools",[]) or []
bit=prompt.setdefault("built_in_tools",{})
for t in existing:
    if t.get("type")=="system":
        n=t.get("name")
        bit.setdefault(n,{"name":n,"description":t.get("description",""),"type":"system","params":{"system_tool_type":n}})

ids=prompt.get("tool_ids") or []
tid=os.environ["TOOL_ID"]
if tid not in ids: ids.append(tid)
prompt["tool_ids"]=ids
prompt["llm"]=os.environ["LLM"]

marker="# Live web search (search_web tool)"
if marker not in prompt.get("prompt",""):
    prompt["prompt"]=prompt.get("prompt","")+"\n\n"+marker+"\n"+ \
"- When the customer asks for live or current info you do not have (today's gold or silver rate, a current price, an ongoing offer, store timings you are unsure of), call the search_web tool with a short English query. Say a brief filler first, like 'one moment, let me check that.'\n"+ \
"- If the tool returns found:true, give its answer in your own words in the language you are speaking, and note it is the latest available. Mention the source if useful.\n"+ \
"- If found:false or the tool fails, answer from your knowledge base and suggest confirming at the store. Never invent a rate or figure."

print(json.dumps({"conversation_config":cc}, ensure_ascii=False))
PY
)
PATCH_RESP=$(curl -sS -X PATCH "https://api.elevenlabs.io/v1/convai/agents/$AGENT_ID" \
  -H "xi-api-key: $API_KEY" -H "Content-Type: application/json" -d "$PATCH_BODY")
DONE=$(echo "$PATCH_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null || true)
[ -z "$DONE" ] && { echo "ERROR: agent patch failed: $(echo "$PATCH_RESP" | head -c 800)" >&2; exit 1; }
echo "Done. Agent $DONE has web-search tool $TOOL_ID (search_web), LLM=$LLM."
echo "search_web=$TOOL_ID" >> scripts/agent-ids.txt
