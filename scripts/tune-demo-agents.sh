#!/bin/bash
# scripts/tune-demo-agents.sh
# Bring the whole demo-gallery fleet up to the aisewak "gold standard" voice
# tuning, IN PLACE (PATCH — keeps agent ids, no demo-page re-pointing):
#   tts.model_id                -> eleven_v3_conversational  (most natural)
#   tts.optimize_streaming_latency -> 3
#   agent.prompt.max_tokens     -> 250   (short voice turns; fixes max_tokens=-1 ramble)
#   turn.turn_eagerness         -> eager
#   turn.speculative_turn       -> true
# Everything else (voice_id, stability, similarity, llm, prompt, tools, KB, eval)
# is preserved. Idempotent. Agent list comes from scripts/demos.json.
set -euo pipefail
cd "$(dirname "$0")/.."

API_KEY=$(grep '^ELEVENLABS_API_KEY=' .env | cut -d= -f2- | tr -d '"')
[ -z "$API_KEY" ] && { echo "ERROR: ELEVENLABS_API_KEY missing" >&2; exit 1; }

MODEL="${DEMO_TTS_MODEL:-eleven_v3_conversational}"
MAXTOK="${DEMO_MAX_TOKENS:-250}"

if [ -n "${DEMO_ONLY:-}" ]; then
  IDS="$DEMO_ONLY"
else
  IDS=$(python3 -c "import json;d=json.load(open('scripts/demos.json'));i=d if isinstance(d,list) else d.get('demos',[]);print('\n'.join(x['agent_id'] for x in i if x.get('agent_id')))")
fi
ok=0; fail=0
for id in $IDS; do
  A=$(curl -sS "https://api.elevenlabs.io/v1/convai/agents/$id" -H "xi-api-key: $API_KEY")
  BODY=$(MODEL="$MODEL" MAXTOK="$MAXTOK" AGENT="$A" python3 <<'PY'
import os, json, sys
a=json.loads(os.environ['AGENT'], strict=False)
cc=a['conversation_config']
tts=cc.setdefault('tts',{}); pr=cc['agent']['prompt']; turn=cc.setdefault('turn',{})
before=(tts.get('model_id'), pr.get('max_tokens'), turn.get('turn_eagerness'), turn.get('speculative_turn'))
tts['model_id']=os.environ['MODEL']
tts['optimize_streaming_latency']=3
pr['max_tokens']=int(os.environ['MAXTOK'])
turn['turn_eagerness']='eager'
turn['speculative_turn']=True
# API rejects both `tools` and `tool_ids`; drop inline tools when tool_ids set.
if pr.get('tool_ids'):
    pr.pop('tools', None)
after=(tts['model_id'], pr['max_tokens'], turn['turn_eagerness'], turn['speculative_turn'])
sys.stderr.write("  %-40s %s -> %s\n" % ((a.get('name') or '?')[:40], before, after))
print(json.dumps({'conversation_config':cc}, ensure_ascii=False))
PY
)
  if [ "${DRY_RUN:-0}" = "1" ]; then ok=$((ok+1)); continue; fi
  R=$(curl -sS -X PATCH "https://api.elevenlabs.io/v1/convai/agents/$id" \
        -H "xi-api-key: $API_KEY" -H "Content-Type: application/json" -d "$BODY")
  if echo "$R" | python3 -c "import sys,json;sys.exit(0 if json.load(sys.stdin).get('agent_id') else 1)" 2>/dev/null; then
    ok=$((ok+1))
  else
    fail=$((fail+1)); echo "  FAIL $id: $(echo "$R" | head -c 200)" >&2
  fi
done
echo "Done. patched ok=$ok fail=$fail (model=$MODEL, max_tokens=$MAXTOK, eager+speculative turn)."
