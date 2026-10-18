#!/bin/sh
# tests/native/run.sh — run every dependency-free shell test and summarise.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
set -u

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fail=0
ran=0

for s in "$DIR"/*.sh; do
    b=$(basename "$s")
    [ "$b" = "lib.sh" ] && continue
    [ "$b" = "run.sh" ] && continue
    ran=$((ran + 1))
    if sh "$s"; then
        :
    else
        echo "  ^^ FAILED: $b"
        fail=$((fail + 1))
    fi
done

echo ""
if [ "$fail" -eq 0 ]; then
    echo "native tests: $ran script(s), all OK"
else
    echo "native tests: $fail of $ran script(s) FAILED"
fi
exit "$fail"
