#!/bin/sh
# tests/native/perf-ratio.sh — guard against a throughput cliff on syslog logs.
#
# Why a *ratio* and not a threshold: syslog-format lines carry no year and no
# timezone ("Oct 18 09:30:16"), so turning them into an instant used to rebuild
# the local zone on every line.  While TZ is unset — the default in a shell, in
# cron and in a systemd unit — glibc re-stats and re-reads /etc/localtime on
# every mktime()/localtime() call, which made a syslog log parse ~4.7x slower
# than an rfc3339 log of the same size (37k vs 173k lines/s, measured).
#
# Comparing the two rates measured on the *same* machine, in the *same* run,
# makes the check independent of CPU speed and of background load: an absolute
# "must exceed 100k lines/s" would fail on a slow or busy box and pass on a fast
# one while the regression was present.  Before the fix the ratio was ~0.21;
# after it, ~0.85.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set -eu
. "$(dirname -- "$0")/lib.sh"

FLOOR=${FLOOR:-0.60}
N=${N:-200000}          # awk iterations -> 2N lines per file

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

# Two fixtures, same shape and same count, differing only in the timestamp form.
awk -v n="$N" 'BEGIN{
  for (i = 0; i < n; i++) {
    d = 1 + (i % 28); h = i % 24; m = i % 60; s = i % 60;
    printf "Oct %02d %02d:%02d:%02d host1 slapd[1]: conn=%d op=0 BIND dn=\"uid=u%d,dc=x\" method=128\n", d,h,m,s,i,i;
    printf "Oct %02d %02d:%02d:%02d host1 slapd[1]: conn=%d op=0 RESULT tag=97 err=0 qtime=0.000010 etime=0.000200 text=\n", d,h,m,s,i;
  } }' > "$SCRATCH/syslog.log"

awk -v n="$N" 'BEGIN{
  for (i = 0; i < n; i++) {
    d = 1 + (i % 28); h = i % 24; m = i % 60; s = i % 60;
    printf "2026-10-%02dT%02d:%02d:%02d.000000001Z host1 slapd[1]: conn=%d op=0 BIND dn=\"uid=u%d,dc=x\" method=128\n", d,h,m,s,i,i;
    printf "2026-10-%02dT%02d:%02d:%02d.000000002Z host1 slapd[1]: conn=%d op=0 RESULT tag=97 err=0 qtime=0.000010 etime=0.000200 text=\n", d,h,m,s,i;
  } }' > "$SCRATCH/rfc3339.log"

rate() { # <file> -> lines/second
    _lines=$(wc -l < "$1")
    _t=$(best_seconds "$1" 3)
    awk -v l="$_lines" -v t="$_t" 'BEGIN{ printf "%d", l / t }'
}

R=$(rate "$SCRATCH/rfc3339.log")
S=$(rate "$SCRATCH/syslog.log")

printf 'perf-ratio: rfc3339 %s lines/s, syslog %s lines/s\n' "$R" "$S"
awk -v s="$S" -v r="$R" -v floor="$FLOOR" 'BEGIN{
    ratio = s / r;
    printf "perf-ratio: syslog/rfc3339 = %.2f (floor %.2f) %s\n",
           ratio, floor, (ratio >= floor ? "OK" : "FAIL");
    exit (ratio >= floor) ? 0 : 1;
}'
