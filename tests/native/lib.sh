#!/bin/sh
# tests/native/lib.sh — shared helpers for the dependency-free shell tests.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# These tests need only the native binary and a POSIX shell: no node, no jsdom,
# no WebAssembly build.  That is what lets `make test` run anywhere.

set -eu

# Repository root (this file is <root>/tests/native/lib.sh).
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BIN="$ROOT/slaplog"

[ -x "$BIN" ] || { echo "tests: build the binary first (make)" >&2; exit 2; }

# A scratch directory.  Prefer /dev/shm (tmpfs, RAM) when it is writable, else
# fall back to mktemp(1) so the tests also run on a machine without it.
new_scratch() {
    if [ -d /dev/shm ] && [ -w /dev/shm ]; then
        # Containers leave /dev/shm at 64 MB by default, and the throughput
        # test writes ~80 MB there; use it only when it really has the room.
        avail=$(df -Pk /dev/shm 2>/dev/null | awk 'NR == 2 { print $4 }')
        if [ -n "$avail" ] && [ "$avail" -ge 262144 ]; then
            mktemp -d /dev/shm/slaplog-test.XXXXXX
            return
        fi
    fi
    mktemp -d "${TMPDIR:-/tmp}/slaplog-test.XXXXXX"
}

# Best-of-N wall-clock seconds for one run, with TZ unset (the real default of a
# shell, cron and a systemd unit).  Best-of removes scheduler noise.
best_seconds() { # <file> [runs]
    _f=$1; _n=${2:-3}; _best=999999
    _i=0
    while [ "$_i" -lt "$_n" ]; do
        _t=$( { /usr/bin/time -f "%e" env -u TZ "$BIN" -q -o text "$_f" >/dev/null; } 2>&1 | tail -1 )
        _best=$(awk -v a="$_t" -v b="$_best" 'BEGIN{print (a<b)?a:b}')
        _i=$((_i + 1))
    done
    echo "$_best"
}
