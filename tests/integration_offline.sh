#!/usr/bin/env bash
# Offline black-box tests for the noz CLI: the commands that need no relay
# (key, decode, verify, and event sign-only mode). Deterministic, so it gates
# CI. Relay-dependent commands (event publish, req, count, relay, sync) are
# covered separately against a live relay.
#
# Usage: tests/integration_offline.sh [path-to-noz]   (default ./zig-out/bin/noz)
#
# Exits non-zero if any assertion fails.
set -u
NOZ="${1:-./zig-out/bin/noz}"

# secp256k1 generator: the pubkey for private key = 1 (NIP-01 / BIP-340 vector).
SEC1=0000000000000000000000000000000000000000000000000000000000000001
PK1=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

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

chk_code() { # desc expected-exit-code cmd...
  local desc=$1 want=$2
  shift 2
  "$@" >/dev/null 2>&1
  chk "$desc" "$want" "$?"
}

field() { grep -E "^$1" | awk '{print $2}'; } # extract a `label  value` line

# --- key ---
chk "key public derives the generator pubkey" "$PK1" "$($NOZ key public $SEC1)"
GEN=$($NOZ key generate)
chk "key generate prints a 64-hex sec" 64 "$(echo "$GEN" | awk '/^sec/{print length($2)}')"
chk "key generate prints a 64-hex pub" 64 "$(echo "$GEN" | awk '/^pub/{print length($2)}')"

# --- decode (NIP-19 test vectors) ---
chk "decode npub -> hex pubkey" \
  7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e \
  "$($NOZ decode npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg | field pubkey)"
chk "decode note -> hex id" \
  4cd665db042864ee600ee976d6cfcc7c5ce743859462f94a347cd970d88a5f3b \
  "$($NOZ decode note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc | field id)"
chk "decode nsec -> hex seckey" \
  67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa \
  "$($NOZ decode nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5 | field seckey)"
chk "decode nprofile -> hex pubkey" \
  3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d \
  "$($NOZ decode nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p | field pubkey)"
chk_code "decode rejects garbage (exit 1)" 1 $NOZ decode notarealthing

# --- event sign-only + verify round-trip ---
EV=$($NOZ event --sec $SEC1 -k 1 -c "integration test" --ts 1700000000)
chk "event sign-only embeds the author pubkey" "$PK1" \
  "$(echo "$EV" | grep -oE '"pubkey":"[a-f0-9]{64}"' | cut -d'"' -f4)"
chk "verify accepts a freshly signed event (arg)" valid "$($NOZ verify "$EV")"
chk "verify accepts via stdin" valid "$(echo "$EV" | $NOZ verify)"
chk_code "verify exits 0 on a valid event" 0 $NOZ verify "$EV"

# tampered content -> recomputed id no longer matches
TAMP=$(echo "$EV" | sed 's/integration test/integration TEST/')
chk "verify reports id mismatch on tampered content" \
  "invalid: id does not match content" "$($NOZ verify "$TAMP")"
chk_code "verify exits 1 on tampered content" 1 $NOZ verify "$TAMP"

# malformed input
chk_code "verify exits 1 on malformed json" 1 bash -c "echo '{\"x\":1}' | $NOZ verify"

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
