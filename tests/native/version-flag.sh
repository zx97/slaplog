#!/bin/sh
# tests/native/version-flag.sh — --no-version keeps the engine name and its
# version out of the report footer.
#
# The footer is the only place a report advertises the engine ("slaplog vX.Y.Z
# — OpenLDAP Log Analysis Report").  A report handed to a third party sometimes
# should not; the option then leaves the report's own name and nothing else.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
. "$(dirname -- "$0")/lib.sh"

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

cat > "$SCRATCH/a.log" <<'EOF'
6a734745.00000001 0x7f9c1e33a700 slapd starting
6a734745.00000002 0x7f9c1e33a700 conn=1 fd=12 ACCEPT from IP=192.0.2.10:1111 (IP=0.0.0.0:389)
6a734745.00000003 0x7f9c1e33a700 conn=1 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text=
EOF

# grep -c returns 1 on a zero count, which `set -e` would treat as fatal.
count() { grep -cF "$1" "$2" 2>/dev/null || true; }

fail=0
check() { # <label> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "version-flag: $1 = $3 OK"
    else echo "version-flag: $1 = $3 (expected $2) FAIL"; fail=1; fi
}

env -u TZ "$BIN" -q -o html -s stats "$SCRATCH/a.log" > "$SCRATCH/on.html" 2>/dev/null
env -u TZ "$BIN" -q -o html -s stats --no-version "$SCRATCH/a.log" > "$SCRATCH/off.html" 2>/dev/null

check "default footer names the engine and its version" 1 \
    "$(count 'class="footer">slaplog v' "$SCRATCH/on.html")"

check "--no-version keeps 'slaplog' out of the footer" 0 \
    "$(count 'class="footer">slaplog' "$SCRATCH/off.html")"

check "--no-version keeps the version number out of the footer" 0 \
    "$(count 'class="footer">OpenLDAP Log Analysis Report v' "$SCRATCH/off.html")"

check "--no-version keeps the report's own name" 1 \
    "$(count 'class="footer">OpenLDAP Log Analysis Report</div>' "$SCRATCH/off.html")"

# The option must not leak into the other formats.
env -u TZ "$BIN" -q -o json --no-version "$SCRATCH/a.log" > "$SCRATCH/off.json" 2>/dev/null
check "the JSON report is valid and unchanged" 1 \
    "$(count '"title": "OpenLDAP Log Analysis Report"' "$SCRATCH/off.json")"

exit $fail
