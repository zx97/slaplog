#!/bin/sh
# tests/native/determinism.sh — several files, several servers: the report must
# be identical on every run, and each server's window must be its own log's.
#
# This is the guard for the std::gmtime() defect: formatting a timestamp went
# through one process-wide static `struct tm`, so worker threads overwrote each
# other's civil time.  The symptom was never a crash but a *different* report on
# some runs — a date that appears nowhere in the logs — which a single-run test
# cannot see.  It is also what the per-server coverage lanes and both chart
# windows are drawn from.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
. "$(dirname -- "$0")/lib.sh"

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

N=${N:-1200}    # lines per server; each line is a BIND/RESULT pair

# Three syslog servers, each covering a distinct hour of the same day, so every
# per-server window has a known answer ("syslog-utc" fields are UTC as-is).
gen() { # <file> <host> <base-hour>
    awk -v n="$N" -v host="$1" -v h0="$3" 'BEGIN{
      for (i = 0; i < n; i++) {
        t = i; hh = h0 + int(t/3600); mm = int((t%3600)/60); ss = t%60;
        printf "Oct 17 %02d:%02d:%02d %s slapd[1]: conn=%d fd=%d ACCEPT from IP=10.0.0.%d:1 (IP=0.0.0.0:389)\n", hh,mm,ss,host,i,i,i%250;
        printf "Oct 17 %02d:%02d:%02d %s slapd[1]: conn=%d op=0 BIND dn=\"uid=%s,dc=x\" method=128\n", hh,mm,ss,host,i,host;
      }
    }' > "$2"
}
gen hostA "$SCRATCH/a.log" 10
gen hostB "$SCRATCH/b.log" 12
gen hostC "$SCRATCH/c.log" 14

# What must be reproducible: the structure, every count, every timestamp, every
# window, every message.  What is not: the last digits of the floating-point
# sums (etime_total, qtime_total, processing_time), which are added in merge
# order and therefore vary with thread scheduling.  The sed zeroes floats and
# leaves integers alone.
norm() { "$BIN" -q -o json "$SCRATCH/a.log" "$SCRATCH/b.log" "$SCRATCH/c.log" 2>/dev/null \
         | sed -E 's/-?[0-9]+\.[0-9]+([eE][-+]?[0-9]+)?/0/g'; }

REF=$(norm)
fail=0

# 1. the same input yields the same report, run after run
i=0
while [ "$i" -lt 6 ]; do
    if [ "$(norm)" = "$REF" ]; then :; else
        echo "determinism: run $i differs from run 0 FAIL"
        fail=1
    fi
    i=$((i + 1))
done
[ "$fail" -eq 0 ] && echo "determinism: 6 runs identical OK"

# 2. each server's window is its own file's range, under any TZ
for spec in "hostA:10:00:00:10:19:59" "hostB:12:00:00:12:19:59" "hostC:14:00:00:14:19:59"; do
    host=${spec%%:*}; rest=${spec#*:}
    first="2026-10-17T$(echo "$rest" | cut -d: -f1-3)Z"
    last="2026-10-17T$(echo "$rest" | cut -d: -f4-6)Z"
    got_first=$(printf '%s' "$REF" | python3 -c "
import json,sys; j=json.load(sys.stdin); t=j['time_by_server']['$host']
print(t['first_timestamp'])" 2>/dev/null || echo "?")
    got_last=$(printf '%s' "$REF" | python3 -c "
import json,sys; j=json.load(sys.stdin); t=j['time_by_server']['$host']
print(t['last_timestamp'])" 2>/dev/null || echo "?")
    if [ "$got_first" = "$first" ] && [ "$got_last" = "$last" ]; then
        echo "determinism: $host window $got_first .. $got_last OK"
    else
        echo "determinism: $host window $got_first .. $got_last (expected $first .. $last) FAIL"
        fail=1
    fi
done

# 3. the whole report is the same whatever TZ says
for tz in UTC America/New_York Europe/Luxembourg; do
    got=$(TZ=$tz "$BIN" -q -o json "$SCRATCH/a.log" "$SCRATCH/b.log" "$SCRATCH/c.log" 2>/dev/null \
          | sed -E 's/-?[0-9]+\.[0-9]+([eE][-+]?[0-9]+)?/0/g')
    if [ "$got" = "$REF" ]; then echo "determinism: TZ=$tz identical OK"
    else echo "determinism: TZ=$tz differs FAIL"; fail=1; fi
done

exit $fail
