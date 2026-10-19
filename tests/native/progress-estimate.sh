#!/bin/sh
# tests/native/progress-estimate.sh — the progress bar's total is the estimated
# *decompressed* size, not the on-disk size.
#
# The counter advances by decompressed bytes for every input, so a compressed
# file must contribute its size times its expansion ratio; with the on-disk size
# the bar reached 100 % almost immediately and then sat there.  The ratios are
# measured on real slapd logs (xz 17.7x, bzip2 20.6x, gzip 13.3x).
#
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
. "$(dirname -- "$0")/lib.sh"

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

awk 'BEGIN{for (i = 0; i < 20000; i++)
  printf "Oct 18 20:%02d:%02d hostA slapd[1]: conn=%d op=0 BIND dn=\"uid=user%05d,ou=people,dc=example,dc=com\" method=128\n",
         i % 60, i % 60, i, i}' > "$SCRATCH/p.log"
gzip -c "$SCRATCH/p.log" > "$SCRATCH/p.log.gz"
bzip2 -c "$SCRATCH/p.log" > "$SCRATCH/p.log.bz2"
xz -c "$SCRATCH/p.log" > "$SCRATCH/p.log.xz"

estimated() { # <file> -> the estimate -d prints, in bytes
    "$BIN" -d -q -o text "$1" 2>&1 >/dev/null \
        | sed -n 's/^Total size: \([0-9]*\) bytes.*/\1/p' | head -1
}

fail=0
check() { # <label> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "progress-estimate: $1 = $3 OK"
    else echo "progress-estimate: $1 = $3 (expected $2) FAIL"; fail=1; fi
}

plain=$(stat -c%s "$SCRATCH/p.log")
check "an uncompressed file counts its exact size" "$plain" "$(estimated "$SCRATCH/p.log")"

for ext in gz bz2 xz; do
    disk=$(stat -c%s "$SCRATCH/p.log.$ext")
    got=$(estimated "$SCRATCH/p.log.$ext")
    # At least 5x the on-disk size: the old behaviour was exactly the on-disk
    # size, and every real ratio is far above 5.
    if [ "$got" -gt $((disk * 5)) ]; then
        echo "progress-estimate: .$ext is estimated from its expansion ($disk on disk, $got estimated) OK"
    else
        echo "progress-estimate: .$ext is estimated from its expansion ($disk on disk, $got estimated) FAIL"
        fail=1
    fi
done

exit $fail
