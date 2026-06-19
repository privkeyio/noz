#!/usr/bin/env bash
# Relay-tier black-box tests for noz: publish/query round-trips against a
# running relay, exercising event, req, count, relay, and verify end to end.
# The reciprocal of wisp's protocol harness, which uses noz as its client.
#
# Usage: tests/integration_relay.sh [relay-url]   (default ws://127.0.0.1:7777)
#   NOZ=path overrides the binary (default ./zig-out/bin/noz)
#
# Exits non-zero if any assertion fails.
set -u
R="${1:-ws://127.0.0.1:7777}"
NOZ="${NOZ:-./zig-out/bin/noz}"

SEC1=0000000000000000000000000000000000000000000000000000000000000001
PK1=$($NOZ key public $SEC1)

pass=0
fail=0

chk() { # desc expected actual
  if [ "$2" = "$3" ]; then
    echo "ok   - $1"
    pass=$((pass + 1))
  else
    echo "FAIL - $1 (expected '$2', got '$3')"
    fail=$((fail + 1))
  fi
}

req() { timeout 10 $NOZ req "$@" "$R" 2>/dev/null | grep -c '"kind"'; }
idof() { $NOZ event "$@" "$R" 2>/dev/null | grep -oE '"id":"[a-f0-9]{64}"' | head -1 | cut -d'"' -f4; }

# A run-unique tag isolates this run's events from anything else in the relay.
TAG="noz$RANDOM$RANDOM"

# --- NIP-01: publish + EVENT delivery on REQ (the core round-trip) ---
ID=$(idof --sec $SEC1 -k 1 -t t=$TAG -c "noz relay round-trip")
sleep 0.5
chk "REQ by id returns the event" 1 "$(req -i "$ID")"
chk "REQ by author + tag" 1 "$(req -a "$PK1" -t t=$TAG)"
chk "REQ by kind + author + tag" 1 "$(req -k 1 -a "$PK1" -t t=$TAG)"
chk "REQ #t tag filter" 1 "$(req -t t=$TAG)"
chk "REQ wrong kind is empty" 0 "$(req -k 9999 -t t=$TAG)"
chk "REQ since in the future is empty" 0 "$(req -t t=$TAG -s 9999999999)"
chk "REQ until in the past is empty" 0 "$(req -t t=$TAG -u 1)"

# --- NIP-45 COUNT (noz prints the bare count) ---
chk "COUNT returns the event count" 1 "$(timeout 10 $NOZ count -t t=$TAG "$R" 2>/dev/null)"

# --- A fetched event survives verify end to end ---
EV=$(timeout 10 $NOZ req -i "$ID" "$R" 2>/dev/null | head -1)
chk "fetched event passes verify" valid "$(echo "$EV" | $NOZ verify)"

# --- NIP-11 relay information document ---
INFO=$(timeout 10 $NOZ relay "$R" 2>/dev/null)
has() { echo "$INFO" | grep -qE "\"$1\"[[:space:]]*:" && echo 1 || echo 0; }
chk "relay info has name" 1 "$(has name)"
chk "relay info has supported_nips" 1 "$(has supported_nips)"

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
