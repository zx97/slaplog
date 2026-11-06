#!/bin/sh
# tests/native/patterns.sh — behaviour-pattern detection is on by default and
# --no-patterns disables it.
#
# The point of the feature is to fold concrete filters down to their shape:
# (employeeNumber=100*) and (employeeNumber=0*) must land in the one family
# (employeenumber=#*), and the back-to-back searches must show as a repeated
# sequence.  The test also checks the state round-trip, because the patterns are
# part of the analysis state (schema 3).
#
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
. "$(dirname -- "$0")/lib.sh"

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

cat > "$SCRATCH/a.log" <<'EOF'
6a734745.00000001 0x7f9c1e33a700 slapd starting
6a734745.00000002 0x7f9c1e33a700 conn=1 fd=12 ACCEPT from IP=192.0.2.10:1111 (IP=0.0.0.0:389)
6a734745.00000003 0x7f9c1e33a700 conn=1 op=0 BIND dn="uid=reporting,ou=apps,dc=example,dc=com" method=128
6a734745.00000004 0x7f9c1e33a700 conn=1 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text=
6a734745.00000005 0x7f9c1e33a700 conn=1 op=1 SRCH base="dc=example,dc=com" scope=2 deref=0 filter="(employeeNumber=100*)"
6a734745.00000006 0x7f9c1e33a700 conn=1 op=1 SEARCH RESULT tag=101 err=0 qtime=0 etime=25000 nentries=3 text=
6a734745.00000007 0x7f9c1e33a700 conn=1 op=2 SRCH base="dc=example,dc=com" scope=2 deref=0 filter="(employeeNumber=0*)"
6a734745.00000008 0x7f9c1e33a700 conn=1 op=2 SEARCH RESULT tag=101 err=0 qtime=0 etime=30000 nentries=5 text=
6a734745.00000009 0x7f9c1e33a700 conn=1 op=3 UNBIND
EOF

# grep -c returns 1 when the count is 0; `|| true` normalises it under `set -e`.
count() { grep -cF "$1" "$2" 2>/dev/null || true; }

n=0
eq() { # <label> <actual> <expected>
    if [ "$2" = "$3" ]; then echo "patterns: $1 = $3 OK"
    else echo "patterns: $1 = $2 (expected $3) FAIL"; n=1; fi
}
ge() { # <label> <actual> <expected-minimum>
    if [ "$2" -ge "$3" ]; then echo "patterns: $1 >= $3 OK"
    else echo "patterns: $1 = $2 (expected >= $3) FAIL"; n=1; fi
}

# 1. by default (no option) the section is drawn, and the two filters fold into
#    one family of count 2.
env -u TZ "$BIN" -q -s patterns "$SCRATCH/a.log" > "$SCRATCH/p.txt" 2>/dev/null
ge "the families section is drawn by default" \
    "$(count "Generalized Search Filter Families" "$SCRATCH/p.txt")" 1
ge "the sequences section is drawn by default" \
    "$(count "Repeated Operation Sequences" "$SCRATCH/p.txt")" 1
# the generalized family exists, with its literal values masked away:
ge "the family is generalized to (employeenumber=#*)" \
    "$(count "(employeenumber=#*)" "$SCRATCH/p.txt")" 1
eq "the concrete value 904 is masked" \
    "$(count "employeenumber=904" "$SCRATCH/p.txt")" 0
# the two searches landed in the same family: the ops column reads 2.  The
# family table row has the filter in column 3 (after the leading '|'), the
# sequence rows have it buried in the sequence text, so exclude SRCH.
eq "the two searches fold into one family (ops = 2)" \
    "$(awk -F'|' '$3 ~ /employeenumber=#/ && $3 !~ /SRCH/ { gsub(/[[:space:]]/,"",$4); print $4 }' "$SCRATCH/p.txt")" 2
# the back-to-back search is a repeated sequence (the "walk"):
ge "the SRCH->SRCH walk is a counted sequence" \
    "$(count "SRCH|(employeenumber=#*)|2 > SRCH|(employeenumber=#*)|2" "$SCRATCH/p.txt")" 1

# 2. --no-patterns disables collection, so the section is absent.
env -u TZ "$BIN" -q --no-patterns -s patterns "$SCRATCH/a.log" > "$SCRATCH/no.txt" 2>/dev/null
eq "with --no-patterns the section is absent" \
    "$(count "Generalized Search Filter Families" "$SCRATCH/no.txt")" 0

# 3. the JSON carries both aggregates by default.
env -u TZ "$BIN" -q -o json "$SCRATCH/a.log" > "$SCRATCH/p.json" 2>/dev/null
ge "json carries filter_families" \
    "$(count '"filter_families"' "$SCRATCH/p.json")" 1
ge "json carries op_sequences" \
    "$(count '"op_sequences"' "$SCRATCH/p.json")" 1

# 4. the patterns survive a save/resume round-trip.
env -u TZ "$BIN" -q --save-state "$SCRATCH/p.slapstate" "$SCRATCH/a.log" > /dev/null 2>&1
env -u TZ "$BIN" -q --resume "$SCRATCH/p.slapstate" -s patterns > "$SCRATCH/r.txt" 2>/dev/null
ge "the resumed state still holds the family" \
    "$(count "(employeenumber=#*)" "$SCRATCH/r.txt")" 1

# 5. the cost-per-operation verdict is present by default.
ge "cost per operation (by account) is drawn" \
    "$(count "Cost per Operation (by Account)" "$SCRATCH/p.txt")" 1
ge "cost per operation (by type) is drawn" \
    "$(count "Cost per Operation (by Type)" "$SCRATCH/p.txt")" 1
ge "json carries cost_by_account" \
    "$(count '"cost_by_account"' "$SCRATCH/p.json")" 1
ge "json carries cost_by_type" \
    "$(count '"cost_by_type"' "$SCRATCH/p.json")" 1

# 6. --compact still draws the patterns (smoke test for the trim).
env -u TZ "$BIN" -q -c -s patterns "$SCRATCH/a.log" > "$SCRATCH/c.txt" 2>/dev/null
ge "compact still draws the families section" \
    "$(count "Generalized Search Filter Families" "$SCRATCH/c.txt")" 1
ge "compact still draws the cost by type" \
    "$(count "Cost per Operation (by Type)" "$SCRATCH/c.txt")" 1

# 7. the resource-hog verdict names the account whose unindexed scans dominate.
ge "the resource-hog verdict is drawn" \
    "$(count "Resource Hog" "$SCRATCH/p.txt")" 1
ge "the verdict names the account" \
    "$(count "uid=reporting" "$SCRATCH/p.txt")" 1
ge "json carries resource_hogs" \
    "$(count '"resource_hogs"' "$SCRATCH/p.json")" 1

# 8. the hourly top-consumer view is drawn (and its JSON is emitted).
ge "the top-consumer-per-hour table is drawn" \
    "$(count "Top Consumer per Hour" "$SCRATCH/p.txt")" 1
ge "json carries top_consumer_per_hour" \
    "$(count '"top_consumer_per_hour"' "$SCRATCH/p.json")" 1

exit $n
