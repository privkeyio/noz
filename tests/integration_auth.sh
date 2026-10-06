#!/usr/bin/env bash
# NIP-42 tests for `noz send --auth`. The relay must have AUTH available
# (for wisp: WISP_RELAY_URL set to the URL passed here) and reject NIP-70
# protected events from unauthenticated connections.
#
# Usage: tests/integration_auth.sh <relay-url>
#   NOZ=path overrides the binary (default ./zig-out/bin/noz)
#
# Exits non-zero if any assertion fails.
set -u
R="${1:?relay url required}"
NOZ="${NOZ:-./zig-out/bin/noz}"

SEC1=0000000000000000000000000000000000000000000000000000000000000001

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

# A signed-but-unpublished protected event, sent raw.
EV=$($NOZ event --sec $SEC1 -t - -c "noz auth $RANDOM$RANDOM" 2>/dev/null)
ID=$(echo "$EV" | grep -oE '"id":"[a-f0-9]{64}"' | head -1 | cut -d'"' -f4)

OUT=$(timeout 15 $NOZ send "$R" "[\"EVENT\",$EV]" 2>/dev/null)
chk "protected EVENT without --auth is rejected" 1 "$(echo "$OUT" | tail -1 | grep -c "^\[\"OK\",\"$ID\",false")"

OUT=$(timeout 15 $NOZ send "$R" "[\"EVENT\",$EV]" --sec $SEC1 --auth 2>/dev/null)
chk "protected EVENT with --auth is accepted" 1 "$(echo "$OUT" | grep -c "^\[\"OK\",\"$ID\",true")"
chk "only the reply to the user's message is printed" 1 "$(echo "$OUT" | wc -l | tr -d ' ')"

OUT=$(timeout 15 $NOZ send "$R" "[\"REQ\",\"a\",{\"ids\":[\"$ID\"]}]" --sec $SEC1 --auth 2>/dev/null)
chk "authenticated REQ ends at EOSE" '["EOSE","a"]' "$(echo "$OUT" | tail -1)"
chk "authenticated REQ returns the event once" 1 "$(echo "$OUT" | grep -c '^\["EVENT"')"

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
