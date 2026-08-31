#!/usr/bin/env bash
# Self-check for qualify.php: boots php -S in a scratch dir and asserts the
# scoring gate, validation, honeypot and rate limit. Needs php on PATH.
#   bash scripts/test-qualify.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
PORT=8899
trap 'kill "$SRV" 2>/dev/null; rm -rf "$TMP"' EXIT

cp "$ROOT/qualify.php" "$TMP/"
printf 'LEAD_EMAIL=devnull@localhost\nBOOKING_URL=https://example.com/book\n' > "$TMP/.env"

php -S "127.0.0.1:$PORT" -t "$TMP" >/dev/null 2>&1 &
SRV=$!
for _ in $(seq 1 20); do curl -s "127.0.0.1:$PORT/qualify.php" >/dev/null 2>&1 && break; sleep 0.2; done

fails=0
post() { curl -s -o "$TMP/body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "$1" "127.0.0.1:$PORT/qualify.php"; }
check() { # name expected_code grep_pattern payload
  local code; code="$(post "$4")"
  if [ "$code" = "$2" ] && grep -q "$3" "$TMP/body"; then
    echo "ok   $1"
  else
    echo "FAIL $1 (http $code) $(cat "$TMP/body")"; fails=$((fails+1))
  fi
}

base='"name":"Priya Sharma","email":"priya@acmeretail.com","phone":"+91 9820000000","company":"Acme Retail","title":"Head of CX","problem":"400 inbound calls a day and 40 percent go unanswered after 7pm."'

check "qualified lead gets booking url" 200 '"booking_url"' \
  "{$base,\"company_size\":\"201-1000\",\"volume\":\"2k-10k\",\"timeline\":\"now\",\"budget\":\"2k-10k\",\"authority\":\"decide\"}"

check "low-fit lead is gated" 200 '"qualified":false' \
  "{$base,\"company_size\":\"1-10\",\"volume\":\"under-500\",\"timeline\":\"exploring\",\"budget\":\"under-500\",\"authority\":\"researching\"}"

if grep -q 'booking_url' "$TMP/body"; then
  echo "FAIL low-fit lead leaked a booking url"; fails=$((fails+1))
else
  echo "ok   low-fit lead gets no booking url"
fi

check "missing fields rejected" 422 '"validation"' \
  '{"name":"Bob","email":"bob@acme.com"}'

check "bad email rejected" 422 'email' \
  "{\"name\":\"Bob\",\"email\":\"not-an-email\",\"phone\":\"+919820000000\",\"company\":\"Acme\",\"title\":\"CTO\",\"problem\":\"we need to answer calls after hours reliably\",\"company_size\":\"51-200\",\"volume\":\"500-2k\",\"timeline\":\"now\",\"budget\":\"2k-10k\",\"authority\":\"decide\"}"

check "short problem rejected" 422 'problem' \
  "{\"name\":\"Bob\",\"email\":\"bob@acme.com\",\"phone\":\"+919820000000\",\"company\":\"Acme\",\"title\":\"CTO\",\"problem\":\"dunno\",\"company_size\":\"51-200\",\"volume\":\"500-2k\",\"timeline\":\"now\",\"budget\":\"2k-10k\",\"authority\":\"decide\"}"

check "honeypot silently dropped" 200 '"qualified":false' \
  "{$base,\"website\":\"http://spam.example\",\"company_size\":\"1000+\",\"volume\":\"10k+\",\"timeline\":\"now\",\"budget\":\"10k+\",\"authority\":\"decide\"}"

check "bad json rejected" 400 'bad_json' 'not json at all'

# 2 logged so far; top up to 5 so the next one trips the per-IP hourly limit
for _ in 1 2 3; do
  post "{$base,\"company_size\":\"51-200\",\"volume\":\"500-2k\",\"timeline\":\"quarter\",\"budget\":\"500-2k\",\"authority\":\"influence\"}" >/dev/null
done
check "rate limit trips" 429 'rate_limited' \
  "{$base,\"company_size\":\"1000+\",\"volume\":\"10k+\",\"timeline\":\"now\",\"budget\":\"10k+\",\"authority\":\"decide\"}"

echo "---"
[ "$fails" -eq 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
