#!/bin/sh
# tests/native/opendj.sh — OpenDJ / ForgeRock DS / PingDS / Oracle Unified
# Directory access logs (the OpenDS family), default text format.
#
# Format: [dd/MMM/yyyy:HH:mm:ss ±HHMM] <VERB> REQ|RES conn=N op=M msgID=K ...
# with CONNECT/DISCONNECT and key=value fields; `etime` is in milliseconds
# (the report shows seconds), and scopes are names (wholeSubtree, …).
#
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
. "$(dirname -- "$0")/lib.sh"

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

fail=0
check() { # <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        echo "opendj: $1 = $3 OK"
    else
        echo "opendj: $1 = $3 (expected $2) FAIL"
        fail=1
    fi
}

stat_of() { # <file> <field> [args...]
    _f=$1; _k=$2; shift 2
    env -u TZ "$BIN" -q -o text -s stats "$@" "$_f" 2>/dev/null \
        | grep -F "| $_k" | head -1 | sed 's/.*| \(.*\)| *$/\1/' | sed 's/ *$//'
}

cat > "$SCRATCH/access.log" <<'LOG'
[20/Apr/2012:13:31:05 +0200] CONNECT conn=5 from=192.0.2.10:51561 to=192.0.2.20:1389 protocol=LDAP
[20/Apr/2012:13:31:05 +0200] EXTENDED REQ conn=5 op=0 msgID=1 name="StartTLS" oid="1.3.6.1.4.1.1466.20037"
[20/Apr/2012:13:31:05 +0200] EXTENDED RES conn=5 op=0 msgID=1 name="StartTLS" oid="1.3.6.1.4.1.1466.20037" result=0 etime=0
[20/Apr/2012:13:31:07 +0200] BIND REQ conn=5 op=1 msgID=2 version=3 type=SIMPLE dn="cn=Directory Manager"
[20/Apr/2012:13:31:07 +0200] BIND RES conn=5 op=1 msgID=2 result=0 authDN="cn=Directory Manager" etime=1
[20/Apr/2012:13:31:07 +0200] SEARCH REQ conn=5 op=2 msgID=3 base="dc=example,dc=org" scope=wholeSubtree filter="(uid=user01)" attrs="isMemberOf"
[20/Apr/2012:13:31:07 +0200] SEARCH RES conn=5 op=2 msgID=3 result=0 nentries=1 etime=6
[20/Apr/2012:13:31:07 +0200] UNBIND REQ conn=5 op=3 msgID=4
[20/Apr/2012:13:31:07 +0200] DISCONNECT conn=5 reason="Client Unbind"
LOG

check "lines"       9 "$(stat_of "$SCRATCH/access.log" "Lines processed")"
check "unknown"     0 "$(stat_of "$SCRATCH/access.log" "Unknown lines")"
check "connections" "1 / 1" "$(stat_of "$SCRATCH/access.log" "Connections opened / closed")"
check "local->UTC"  "from 2012-04-20T11:31:05Z" \
    "$(stat_of "$SCRATCH/access.log" "Time range" | sed 's/ to .*//')"
# 1 ms for the bind + 6 ms for the search = 7 ms, shown in seconds.
check "etime in seconds" "0.007" "$(stat_of "$SCRATCH/access.log" "Total etime")"

json_has() { # <pattern> <file>
    env -u TZ "$BIN" -q -o json "$2" 2>/dev/null | grep -q "$1"
}
if json_has '"BIND": 1' "$SCRATCH/access.log" &&
   json_has '"SRCH": 1' "$SCRATCH/access.log" &&
   json_has '"SEARCH RESULT": 1' "$SCRATCH/access.log" &&
   json_has '"EXT": 1' "$SCRATCH/access.log"; then
    echo "opendj: operation counts OK"
else
    echo "opendj: operation counts FAIL"; fail=1
fi
if json_has '"simple": 1' "$SCRATCH/access.log"; then
    echo "opendj: SIMPLE bind classified OK"
else
    echo "opendj: SIMPLE bind classified FAIL"; fail=1
fi
env -u TZ "$BIN" -q -o text -s bases,filters "$SCRATCH/access.log" >"$SCRATCH/r.txt" 2>/dev/null
if grep -q 'dc=example,dc=org' "$SCRATCH/r.txt" && grep -q '(uid=user01)' "$SCRATCH/r.txt"; then
    echo "opendj: base and filter recorded OK"
else
    echo "opendj: base and filter recorded FAIL"; fail=1
fi

# Forcing the dialect gives the same result as auto-detection.
check "forced opendj matches auto" 9 \
    "$(stat_of "$SCRATCH/access.log" "Lines processed" --log-format opendj)"

# A 389-ds file and an OpenDJ file in one run: the first fixes the format.
cat > "$SCRATCH/zz_opendj.log" <<'LOG'
[20/Apr/2012:13:31:05 +0200] CONNECT conn=1 from=192.0.2.10:1 to=192.0.2.20:1389 protocol=LDAP
LOG
cat > "$SCRATCH/a_389.log" <<'LOG'
[17/Oct/2026:02:00:47.302202000 +0200] conn=1 fd=7 slot=0 connection from 192.0.2.10 to 192.0.2.20
LOG
env -u TZ "$BIN" -q -o text -s stats "$SCRATCH/a_389.log" "$SCRATCH/zz_opendj.log" \
    >"$SCRATCH/mixed.txt" 2>"$SCRATCH/mixed.err"
check "mixed: only the 389 file is counted" 1 \
    "$(grep -F '| Lines processed' "$SCRATCH/mixed.txt" | sed 's/.*| \(.*\)| *$/\1/' | sed 's/ *$//')"
if grep -q "different log format for this run" "$SCRATCH/mixed.err"; then
    echo "opendj: mixed run names the skipped format OK"
else
    echo "opendj: mixed run names the skipped format FAIL"; fail=1
fi

exit $fail
