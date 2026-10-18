#!/bin/sh
# tests/native/title.sh — the --title option keeps spaces and hyphens.
#
# A custom title containing a space or a hyphen used to be truncated at the
# first one (4.0.4), and nothing covered the option at all.
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

TITLE="Acceptance - Proxy-cache"

# grep -c returns 1 when the count is 0, which `set -e` would treat as a fatal
# error; `|| true` keeps the count and normalises the status.
count() { grep -cF "$1" "$2" 2>/dev/null || true; }

n=0
check() {
    if [ "$2" = "1" ]; then echo "title: $1 OK"
    else echo "title: $1 FAIL (count $2)"; n=1; fi
}

# text report: the heading keeps the whole title
env -u TZ "$BIN" -q -o text --title "$TITLE" "$SCRATCH/a.log" > "$SCRATCH/t.txt" 2>/dev/null
check "text heading carries the full title" \
    "$(count "OpenLDAP Log Analysis Report - $TITLE" "$SCRATCH/t.txt")"

# JSON: --title is ignored by design (and must not fail, it used to throw).
env -u TZ "$BIN" -q -o json --title "$TITLE" "$SCRATCH/a.log" > "$SCRATCH/t.json" 2>/dev/null
check "json output ignores --title" \
    "$(count '"title": "OpenLDAP Log Analysis Report"' "$SCRATCH/t.json")"

# HTML: the <title> element carries the whole title
env -u TZ "$BIN" -q -o html --title "$TITLE" "$SCRATCH/a.log" > "$SCRATCH/t.html" 2>/dev/null
check "html <title> carries the full title" \
    "$(count "<title>LDAP Log Analysis Report - $TITLE</title>" "$SCRATCH/t.html")"

# no --title: the default heading is unchanged
env -u TZ "$BIN" -q -o json "$SCRATCH/a.log" > "$SCRATCH/n.json" 2>/dev/null
check "without --title the title is the default" \
    "$(count '"title": "OpenLDAP Log Analysis Report"' "$SCRATCH/n.json")"

exit $n
