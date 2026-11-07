#!/bin/sh
# tests/native/timestamps.sh — UTC conversion of the rfc3339/ol26 formats and
# the "default" alias of --log-format.
#
# Two independent defects are pinned here:
#
#  1. parse_log_format() did not know "default", although it is a valid
#     olcLogFileFormat value (slapd treats it exactly like "debug").  Passing
#     it silently fell back to auto-detection, i.e. to a slower and looser
#     parse than the caller asked for.
#
#  2. convert_to_rfc3339_utc() and parse_any_timestamp() decoded RFC3339
#     fields with get_time()+mktime(), so a *UTC* string was read as *local*
#     time: every ol26/rfc3339 timestamp was shifted by the analysing host's
#     UTC offset, an explicit "+02:00" offset was ignored, and "-o replay"
#     suffered the same shift because it re-parses an already-normalised UTC
#     timestamp.  The instant must be the same whatever TZ the analyser runs
#     under (tz-invariance.sh pins the syslog side of the same rule).
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set -eu
. "$(dirname -- "$0")/lib.sh"

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

fail=0
check() { # <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        echo "timestamps: $1 = $3 OK"
    else
        echo "timestamps: $1 = $3 (expected $2) FAIL"
        fail=1
    fi
}

# first_timestamp reported by the JSON report, under a fixed TZ.
# Usage: first_ts <TZ> <binary args...>   (the log file goes last)
first_ts() {
    _tz=$1; shift
    env TZ="$_tz" "$BIN" -q -o json "$@" 2>/dev/null \
        | grep '"first_timestamp"' | head -1 | sed 's/.*: *"//; s/".*//'
}

# Number of lines the parser classified as UNKNOWN_LINE.
unknown_count() { # <binary args...>
    env -u TZ "$BIN" -q -o json "$@" 2>/dev/null \
        | grep '"unknown_lines"' | head -1 | sed 's/.*: *//; s/,.*//'
}

# ---------------------------------------------------------------------------
# 1. "--log-format default" must mean "debug" (fixed), not "auto".
# ---------------------------------------------------------------------------
# A mixed file separates the two: a fixed debug parse refuses the syslog line,
# an auto-detecting run accepts it.  Without the alias the option was silently
# ignored and this file parsed with 0 unknown lines.
cat > "$SCRATCH/mixed.log" <<'EOF'
6a734745.1f4b2c3a 0x7f9c1e33a700 conn=1 fd=12 ACCEPT from IP=192.0.2.10:1111 (IP=0.0.0.0:389)
Nov 07 15:56:09 host1 slapd[1]: conn=1 op=0 BIND dn="" method=128
EOF

check "--log-format default refuses a non-debug line" 1 \
      "$(unknown_count --log-format default "$SCRATCH/mixed.log")"
check "--log-format debug   refuses a non-debug line" 1 \
      "$(unknown_count --log-format debug "$SCRATCH/mixed.log")"
check "--log-format auto    accepts both lines" 0 \
      "$(unknown_count "$SCRATCH/mixed.log")"

check "--log-format default decodes the debug timestamp" \
      "2026-08-05T14:23:01.525020218Z" \
      "$(first_ts UTC --log-format default "$SCRATCH/mixed.log")"

# ---------------------------------------------------------------------------
# 2. ol26 and generic rfc3339 must be read as UTC, offsets honoured.
# ---------------------------------------------------------------------------
cat > "$SCRATCH/ol26.log" <<'EOF'
[2026-08-05T14:23:01.123Z] conn=1 op=0 BIND dn="" method=128
EOF

cat > "$SCRATCH/rfc-z.log" <<'EOF'
2026-08-05T14:23:01Z host1 slapd[1]: conn=1 op=0 BIND dn="" method=128
EOF

cat > "$SCRATCH/rfc-offset.log" <<'EOF'
2026-08-05T14:23:01+02:00 host1 slapd[1]: conn=1 op=0 BIND dn="" method=128
EOF

for tz in UTC Europe/Luxembourg America/New_York Australia/Sydney; do
    check "ol26 ($tz)" "2026-08-05T14:23:01.123000000Z" \
          "$(first_ts "$tz" "$SCRATCH/ol26.log")"
    check "rfc3339 Z ($tz)" "2026-08-05T14:23:01Z" \
          "$(first_ts "$tz" "$SCRATCH/rfc-z.log")"
    check "rfc3339 +02:00 ($tz)" "2026-08-05T12:23:01Z" \
          "$(first_ts "$tz" "$SCRATCH/rfc-offset.log")"
done

# ---------------------------------------------------------------------------
# 3. "-o replay" re-parses an already-normalised UTC timestamp: it must not
#    shift it by the analyser's own UTC offset.  The row carries the
#    operation's completion timestamp, fraction included, so the exact value
#    also proves the nanosecond part survives the round trip.
# ---------------------------------------------------------------------------
cat > "$SCRATCH/replay.log" <<'EOF'
2026-04-19T09:59:01.633228219Z ldap1.example.com slapd[1]: conn=1 op=0 BIND dn="" method=128
2026-04-19T09:59:01.704195746Z ldap1.example.com slapd[1]: conn=1 op=0 RESULT tag=97 err=0 qtime=0.000010 etime=0.000200 text=
EOF

replay_ts() { # <TZ> -> timestamp column of the first data row
    env TZ="$1" "$BIN" -q -o replay --replay-separator comma "$SCRATCH/replay.log" \
        2>/dev/null | sed -n '2p' | cut -d, -f1
}

for tz in UTC Europe/Luxembourg America/New_York Australia/Sydney; do
    check "replay ($tz)" "2026-04-19T09:59:01.704195746Z" "$(replay_ts "$tz")"
done

exit $fail
