#!/bin/sh
# tests/native/tz-invariance.sh — the parser must not depend on the host's TZ.
#
# A syslog line ("Oct 18 09:30:16") names neither a year nor a zone, and the
# syslog-utc format says the fields ARE UTC.  The instant produced for such a
# line must therefore be the same whatever TZ the analysing machine happens to
# have — and it must not silently depend on it, which is exactly what the old
# mktime()/localtime()/gmtime() chain did: it mixed the DST offset (from
# localtime) with the standard one (from gmtime) and read 09:30:16 as 06:30:16Z
# here and 09:30:16Z under TZ=UTC.
#
# This is the deterministic half of the guard; perf-ratio.sh is the other.  Both
# are needed: a correct-but-slow fix fails perf-ratio, a fast-but-wrong one fails
# here.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set -eu
. "$(dirname -- "$0")/lib.sh"

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

# A syslog-utc fixture with a known answer: 09:30:16Z (and one second later).
cat > "$SCRATCH/s.log" <<'EOF'
Oct 18 09:30:16 host1 slapd[1]: conn=1 op=0 BIND dn="uid=a,dc=x" method=128
Oct 18 09:30:17 host1 slapd[1]: conn=1 op=0 RESULT tag=97 err=0 qtime=0.000010 etime=0.000200 text=
EOF

stamps() { # <TZ-setter...> -> "first last"
    env "$@" "$BIN" -q -o json "$SCRATCH/s.log" 2>/dev/null \
        | grep -E '"first_timestamp"|"last_timestamp"' | head -2 \
        | sed 's/.*: *"//; s/".*//' | tr '\n' ' '
}

REF="2026-10-18T09:30:16Z 2026-10-18T09:30:17Z "
FAIL=0

for tz in UTC Europe/Luxembourg America/New_York Australia/Sydney; do
    got=$(stamps "TZ=$tz")
    if [ "$got" = "$REF" ]; then
        echo "tz-invariance: TZ=$tz -> $got OK"
    else
        echo "tz-invariance: TZ=$tz -> $got (expected $REF) FAIL"
        FAIL=1
    fi
done

# TZ unset is what a shell, cron and a systemd unit actually see.
got=$(env -u TZ "$BIN" -q -o json "$SCRATCH/s.log" 2>/dev/null \
      | grep -E '"first_timestamp"|"last_timestamp"' | head -2 \
      | sed 's/.*: *"//; s/".*//' | tr '\n' ' ')
if [ "$got" = "$REF" ]; then
    echo "tz-invariance: TZ unset -> $got OK"
else
    echo "tz-invariance: TZ unset -> $got (expected $REF) FAIL"
    FAIL=1
fi

exit $FAIL
