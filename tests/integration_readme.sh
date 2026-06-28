#!/usr/bin/env bash
# Executable README: parse the ```shell blocks in README.md and assert that
# each example still produces the output shown. This keeps the documentation
# honest -- a drifted example fails CI.
#
# Only the deterministic, offline examples are asserted. Examples that hit a
# relay (any "://" URL) or are random by nature (`key generate`) are skipped
# and reported. Event signatures use random BIP-340 aux data, so a "sig" field
# is normalised to "..." on both sides before comparing: the id, content, and
# tags are still checked exactly, only the unreproducible signature is ignored.
#
# Usage: tests/integration_readme.sh [path-to-noz]   (default ./zig-out/bin/noz)
#
# Exits non-zero if any asserted example does not match.
set -u
NOZ="${1:-./zig-out/bin/noz}"
README="$(cd "$(dirname "$0")/.." && pwd)/README.md"

pass=0
fail=0
skip=0

have=0
cmd=""
out=""
nout=0

# Replace the 64-hex signature with a placeholder so the random sig is ignored
# while the rest of the event is compared exactly.
norm() { sed -E 's/"sig":"[0-9a-f]{128}"/"sig":"..."/g'; }

run_record() {
  [ "$have" = 1 ] || return 0
  have=0
  local c="$cmd" expected="$out"

  case "$c" in
    noz\ *) ;;
    *) skip=$((skip + 1)); return 0 ;;            # not a noz invocation
  esac
  case "$c" in
    *"://"*) skip=$((skip + 1)); return 0 ;;      # needs a relay
  esac
  case "$c" in
    "noz key generate"*) skip=$((skip + 1)); return 0 ;;  # random
  esac
  [ -n "$expected" ] || { skip=$((skip + 1)); return 0; }  # no output shown

  local actual
  actual="$(eval "$NOZ ${c#noz } 2>/dev/null" </dev/null)"

  local e_n a_n
  e_n="$(printf '%s' "$expected" | norm)"
  a_n="$(printf '%s' "$actual" | norm)"

  if [ "$a_n" = "$e_n" ]; then
    echo "ok   - $c"
    pass=$((pass + 1))
  else
    echo "FAIL - $c"
    echo "  expected: $e_n"
    echo "  actual:   $a_n"
    fail=$((fail + 1))
  fi
}

inblk=0
while IFS= read -r line; do
  case "$line" in
    '```shell') inblk=1; have=0; continue ;;
    '```'*) if [ "$inblk" = 1 ]; then run_record; inblk=0; fi; continue ;;
  esac
  [ "$inblk" = 1 ] || continue

  if [ -z "$line" ]; then
    run_record
    continue
  fi
  if [ "${line#"~> "}" != "$line" ]; then
    run_record
    cmd="${line#"~> "}"
    # Join backslash-continued command lines.
    while [ "${cmd%\\}" != "$cmd" ]; do
      cmd="${cmd%\\}"
      IFS= read -r cont || break
      cont="${cont#"${cont%%[![:space:]]*}"}"   # strip leading whitespace
      cmd="$cmd$cont"
    done
    have=1
    out=""
    nout=0
  elif [ "$have" = 1 ]; then
    if [ "$nout" -gt 0 ]; then out="$out"$'\n'"$line"; else out="$line"; fi
    nout=$((nout + 1))
  fi
done < "$README"
run_record

echo
echo "asserted $pass, failed $fail, skipped $skip (relay/random/no-output)"
[ "$pass" -gt 0 ] && [ "$fail" -eq 0 ]
