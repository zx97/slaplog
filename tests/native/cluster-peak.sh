#!/bin/sh
# tests/native/cluster-peak.sh — a multi-server run reports the peak of the
# *sum* of the concurrent connections, not the busiest single server.
#
# update_aggregator() tracks the count per file and merge_aggregators() can only
# keep the larger of two peaks; the run's peak is therefore recomputed from the
# merged connection timeline.  That timeline is collected even with --no-graph:
# the peak is a statistic, not a drawing.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
. "$(dirname -- "$0")/lib.sh"

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

# mk <file> <host> <accept-minute> <count> [close-minute]
mk() {
    awk -v h="$2" -v m="$3" -v n="$4" -v cm="${5:-}" 'BEGIN{
        for (i = 0; i < n; i++)
            printf "Oct 18 20:%02d:00 %s slapd[1]: conn=%d fd=%d ACCEPT from IP=10.0.0.1:1 (IP=0.0.0.0:389)\n", m, h, i, i;
        if (cm != "")
            for (i = 0; i < n; i++)
                printf "Oct 18 20:%02d:00 %s slapd[1]: conn=%d fd=%d closed\n", cm, h, i, i;
    }' > "$1"
}

peak() { # <args...> -> peak_active_connections
    "$BIN" -q -o json "$@" 2>/dev/null \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["peak_active_connections"])'
}

fail=0
check() { # <label> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "cluster-peak: $1 = $3 OK"
    else echo "cluster-peak: $1 = $3 (expected $2) FAIL"; fail=1; fi
}

# 1. two servers with three connections each open at the same time: 6, not 3.
mk "$SCRATCH/a.log" hostA 0 3 5
mk "$SCRATCH/b.log" hostB 0 3 5
check "two servers overlapping (3+3)" 6 "$(peak "$SCRATCH/a.log" "$SCRATCH/b.log")"

# 2. the same counts, but the servers' connections never overlap: 3, not 6.
mk "$SCRATCH/c.log" hostA 0 3 1
mk "$SCRATCH/d.log" hostB 10 3 11
check "two servers not overlapping (3, then 3)" 3 "$(peak "$SCRATCH/c.log" "$SCRATCH/d.log")"

# 3. --no-graph must not change the figure.
check "the same, with --no-graph" 6 "$(peak --no-graph "$SCRATCH/a.log" "$SCRATCH/b.log")"

# 4. one server stays exact and unchanged.
check "single server (3)" 3 "$(peak "$SCRATCH/a.log")"

exit $fail
