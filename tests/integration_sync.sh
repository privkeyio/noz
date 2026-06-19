#!/usr/bin/env bash
# NIP-77 sync tests for noz: reconcile one relay's events into another and
# confirm they land. Needs two running relays.
#
# Usage: tests/integration_sync.sh [src-url] [dst-url]
#   (defaults ws://127.0.0.1:7777 ws://127.0.0.1:7778)
#   NOZ=path overrides the binary (default ./zig-out/bin/noz)
#
# Exits non-zero if any assertion fails.
set -u
SRC="${1:-ws://127.0.0.1:7777}"
DST="${2:-ws://127.0.0.1:7778}"
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

# count events matching the args on a specific relay
on() { local r=$1; shift; timeout 10 $NOZ req "$@" "$r" 2>/dev/null | grep -c '"kind"'; }

TAG="nozsync$RANDOM$RANDOM"
ID=$($NOZ event --sec $SEC1 -k 1 -t t=$TAG -c "sync me" "$SRC" 2>/dev/null |
  grep -oE '"id":"[a-f0-9]{64}"' | head -1 | cut -d'"' -f4)
sleep 0.5

chk "event present on src" 1 "$(on "$SRC" -i "$ID")"
chk "event absent on dst before sync" 0 "$(on "$DST" -i "$ID")"

$NOZ sync "$SRC" "$DST" -t t=$TAG >/dev/null 2>&1
sleep 0.8

chk "event present on dst after sync" 1 "$(on "$DST" -i "$ID")"

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
