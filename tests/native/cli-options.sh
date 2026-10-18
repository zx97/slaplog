#!/bin/sh
# tests/native/cli-options.sh — option parsing: attached short-option values.
#
# "-j4" (and -o, -n, -m, -s) must behave exactly like "-j 4".  A short option
# with a glued value used to be silently treated as an input path, so "-j1" ran
# with the default worker count.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
. "$(dirname -- "$0")/lib.sh"

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

cat > "$SCRATCH/a.log" <<'EOF'
6a734745.00000001 0x7f9c1e33a700 slapd starting
6a734745.00000002 0x7f9c1e33a700 conn=1 fd=12 ACCEPT from IP=192.0.2.10:1111 (IP=0.0.0.0:389)
6a734745.00000003 0x7f9c1e33a700 conn=1 op=0 BIND dn="cn=admin,dc=example,dc=com" method=128
EOF
cp "$SCRATCH/a.log" "$SCRATCH/b.log"

workers() { # <args...> -> the worker count the binary reports with -d
    env -u TZ "$BIN" -d "$@" "$SCRATCH/a.log" "$SCRATCH/b.log" 2>&1 >/dev/null \
        | sed -n 's/^Workers: \([0-9]*\) .*/\1/p' | head -1
}

fail=0
check() { # <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        echo "cli-options: $1 = $3 OK"
    else
        echo "cli-options: $1 = $3 (expected $2) FAIL"
        fail=1
    fi
}

check "-j1"    1 "$(workers -j1)"
check "-j 1"   1 "$(workers -j 1)"
check "-j2"    2 "$(workers -j2)"
check "-j 2"   2 "$(workers -j 2)"
check "-j8"    2 "$(workers -j8)"          # capped by the file count
check "--jobs 2" 2 "$(workers --jobs 2)"

# -o glued must produce the same format as "-o json".
if env -u TZ "$BIN" -q -ojson "$SCRATCH/a.log" 2>/dev/null | head -c1 | grep -q '{'; then
    echo "cli-options: -ojson emits JSON OK"
else
    echo "cli-options: -ojson emits JSON FAIL"
    fail=1
fi

# -s glued must select the section like "-s stats".
env -u TZ "$BIN" -q -o text -sstats "$SCRATCH/a.log" > "$SCRATCH/s.txt" 2>/dev/null
if grep -q "Statistics" "$SCRATCH/s.txt" && ! grep -q "Operation Counts" "$SCRATCH/s.txt"; then
    echo "cli-options: -sstats selects only Statistics OK"
else
    echo "cli-options: -sstats selects only Statistics FAIL"
    fail=1
fi

exit $fail
