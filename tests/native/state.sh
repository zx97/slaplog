#!/bin/sh
# tests/native/state.sh — --save-state / --resume, and repeated -o.
#
# The acceptance rule for a state file is "split == single": analysing A and B
# at once must give the same report as analysing A, saving the state, then
# resuming it with B.  The runner normalises the floating-point tails, which are
# summed in merge order and therefore differ in their last digits.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
. "$(dirname -- "$0")/lib.sh"

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

A="$ROOT/tests/fixtures/logsmall/a.log"
B="$ROOT/tests/fixtures/logsmall/b.log"

norm() { sed -E 's/-?[0-9]+\.[0-9]+([eE][-+]?[0-9]+)?/0/g'; }
fail=0
check() { # <label> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "state: $1 = $3 OK"
    else echo "state: $1 = $3 (expected $2) FAIL"; fail=1; fi
}

# 1. split == single
"$BIN" -q -o json "$A" "$B" 2>/dev/null | norm > "$SCRATCH/all.json"
"$BIN" -q -o json --save-state "$SCRATCH/a.to" "$A" > /dev/null 2>&1
"$BIN" -q -o json --resume "$SCRATCH/a.to" "$B" 2>/dev/null | norm > "$SCRATCH/res.json"
check "A then save, resume + B == A + B" 0 \
    "$(diff -q "$SCRATCH/all.json" "$SCRATCH/res.json" > /dev/null 2>&1; echo $?)"

# 2. a state alone re-displays exactly what it holds
"$BIN" -q -o json --resume "$SCRATCH/a.to" 2>/dev/null | norm > "$SCRATCH/only.json"
"$BIN" -q -o json "$A" 2>/dev/null | norm > "$SCRATCH/direct.json"
check "--resume with no new log == analysing that log" 0 \
    "$(diff -q "$SCRATCH/only.json" "$SCRATCH/direct.json" > /dev/null 2>&1; echo $?)"

# 3. a state can be extended and saved again
"$BIN" -q -o json --resume "$SCRATCH/a.to" --save-state "$SCRATCH/ab.to" "$B" > /dev/null 2>&1
"$BIN" -q -o json --resume "$SCRATCH/ab.to" 2>/dev/null | norm > "$SCRATCH/ab.json"
check "resume + save + resume == A + B" 0 \
    "$(diff -q "$SCRATCH/all.json" "$SCRATCH/ab.json" > /dev/null 2>&1; echo $?)"

# 4. bad files are refused, with a message that says which case it is
printf 'hello' > "$SCRATCH/bad.to"
rc=0; "$BIN" -q -o json --resume "$SCRATCH/bad.to" "$A" > /dev/null 2>"$SCRATCH/e1" || rc=$?
check "a foreign file is refused" 1 "$rc"
check "and named as such" 1 "$(grep -c 'not a slaplog state file' "$SCRATCH/e1" || true)"

head -c 60 "$SCRATCH/a.to" > "$SCRATCH/trunc.to"
rc=0; "$BIN" -q -o json --resume "$SCRATCH/trunc.to" "$A" > /dev/null 2>"$SCRATCH/e2" || rc=$?
check "a truncated state is refused" 1 "$rc"
check "and named as such" 1 "$(grep -c 'truncated or corrupt' "$SCRATCH/e2" || true)"

# 5. repeated -o
out=$("$BIN" -q -o json="$SCRATCH/m.json" -o html="$SCRATCH/m.html" "$A" 2>/dev/null)
check "two reports go to their files (stdout stays empty)" 0 "${#out}"
check "the JSON file is written" 1 "$([ -s "$SCRATCH/m.json" ] && echo 1 || echo 0)"
check "the HTML file is written" 1 "$([ -s "$SCRATCH/m.html" ] && echo 1 || echo 0)"

"$BIN" -q -o json -o html="$SCRATCH/o.html" "$A" > "$SCRATCH/o.json" 2>/dev/null
check "one report may go to stdout while another goes to a file" 1 \
    "$([ -s "$SCRATCH/o.json" ] && [ -s "$SCRATCH/o.html" ] && echo 1 || echo 0)"

rc=0; "$BIN" -q -o json -o text "$A" > /dev/null 2>"$SCRATCH/e3" || rc=$?
check "two reports on stdout are refused" 1 "$rc"
check "with a message that names the fix" 1 \
    "$(grep -c 'give the others a file' "$SCRATCH/e3" || true)"

# 6. exact ties.  Two logs identical except the server name and the base suffix:
#    the top lists and the "slowest" fields have nothing to order the rows on, so
#    the report must not depend on worker order — nor on whether the run went
#    through a state file.  (Ties used to be settled by whichever thread merged
#    last, which made two runs of one command disagree.)
sed -e 's/dc=europa,dc=eu/o=cec.eu.int/g' -e 's/digiameudspp41/digiameudspp42/g' "$A" \
    > "$SCRATCH/twin.log"
check "the twin log fixture is still transformable" 1 \
    "$(cmp -s "$SCRATCH/twin.log" "$A" && echo 0 || echo 1)"

"$BIN" -q -o json "$SCRATCH/twin.log" "$A" 2>/dev/null | norm > "$SCRATCH/tie1.json"
"$BIN" -q -o json "$SCRATCH/twin.log" "$A" 2>/dev/null | norm > "$SCRATCH/tie2.json"
check "two runs over perfectly tied rows agree" 0 \
    "$(diff -q "$SCRATCH/tie1.json" "$SCRATCH/tie2.json" > /dev/null 2>&1; echo $?)"

# The state is created from both servers (its perimeter), then replayed.
"$BIN" -q -o json --save-state "$SCRATCH/twin.to" "$SCRATCH/twin.log" "$A" > /dev/null 2>&1
"$BIN" -q -o json --resume "$SCRATCH/twin.to" 2>/dev/null | norm > "$SCRATCH/tie3.json"
check "and the state replay agrees with them" 0 \
    "$(diff -q "$SCRATCH/tie1.json" "$SCRATCH/tie3.json" > /dev/null 2>&1; echo $?)"

# A subset of the state's servers is a resume too.
rc=0; "$BIN" -q -o json --resume "$SCRATCH/twin.to" "$A" > /dev/null 2>&1 || rc=$?
check "a subset of the state's servers is accepted" 0 "$rc"

"$BIN" -q -o json --resume "$SCRATCH/twin.to" 2>/dev/null > "$SCRATCH/tie.json"
"$BIN" -q -o text --resume "$SCRATCH/twin.to" 2>/dev/null > "$SCRATCH/tie.txt"
check "the replayed report names o=cec.eu.int" 1 \
    "$([ "$(grep -c 'o=cec.eu.int' "$SCRATCH/tie.txt")" -ge 1 ] && echo 1 || echo 0)"
check "the replayed report names dc=europa,dc=eu" 1 \
    "$([ "$(grep -c 'dc=europa,dc=eu' "$SCRATCH/tie.txt")" -ge 1 ] && echo 1 || echo 0)"

# 6b. two state files can be merged: the result is the single run of both sets,
#     and the merged perimeter is the union of the two states' servers.
"$BIN" -q -o json --save-state "$SCRATCH/pp42.to" "$SCRATCH/twin.log" > /dev/null 2>&1
"$BIN" -q -o json "$SCRATCH/twin.log" "$A" 2>/dev/null | norm > "$SCRATCH/both.json"
"$BIN" -q -o json --resume "$SCRATCH/a.to" --resume "$SCRATCH/pp42.to" 2>/dev/null \
    | norm > "$SCRATCH/merged.json"
check "two merged states == one run over both logs" 0 \
    "$(diff -q "$SCRATCH/both.json" "$SCRATCH/merged.json" > /dev/null 2>&1; echo $?)"
"$BIN" -q -o json --resume "$SCRATCH/pp42.to" --resume "$SCRATCH/a.to" 2>/dev/null \
    | norm > "$SCRATCH/rev.json"
check "and the order of the states does not matter" 0 \
    "$(diff -q "$SCRATCH/merged.json" "$SCRATCH/rev.json" > /dev/null 2>&1; echo $?)"
rc=0; "$BIN" -q -o json --resume "$SCRATCH/a.to" --resume "$SCRATCH/pp42.to" "$A" \
    > /dev/null 2>&1 || rc=$?
check "the merged perimeter accepts either server" 0 "$rc"

sed 's/digiameudspp41/digiameudspp43/g' "$A" > "$SCRATCH/pp43.log"
rc=0; "$BIN" -q -o json --resume "$SCRATCH/a.to" --resume "$SCRATCH/pp42.to" \
    "$SCRATCH/pp43.log" > /dev/null 2>&1 || rc=$?
check "and refuses a server outside the union" 1 "$rc"

# 7. a resume stays on the servers the state holds.  The twin log above names
#    another server, so folding it into A's state would mix two networks: it must
#    be refused, and nothing may be written.
rc=0; out=$("$BIN" -q -o json --resume "$SCRATCH/a.to" "$SCRATCH/twin.log" 2>"$SCRATCH/e4") || rc=$?
check "a log from another server is refused" 1 "$rc"
check "and nothing is reported for it" 0 "${#out}"
check "the refusal says it is not a resume" 1 \
    "$(grep -c 'not a resume' "$SCRATCH/e4" || true)"
check "and names both sides" 1 \
    "$(grep -c 'digiameudspp42' "$SCRATCH/e4" || true)"

rc=0; "$BIN" -q -o json --resume "$SCRATCH/a.to" --save-state "$SCRATCH/never.to" \
    "$SCRATCH/twin.log" > /dev/null 2>&1 || rc=$?
check "no state is written from a refused resume" 0 \
    "$([ -e "$SCRATCH/never.to" ] && echo 1 || echo 0)"

exit $fail
