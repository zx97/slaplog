#!/bin/sh
# tests/native/not-a-log.sh — a file that is not an LDAP log is refused.
#
# Passing an LDIF export (or any other text file) by mistake used to fill the
# report with unknown lines and empty statistics.  The head of every input is
# now sniffed, after decompression, with the parser's own header detection: a
# file carrying no recognisable slapd line is skipped, named on stderr, and the
# run fails when nothing else could be analysed.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
. "$(dirname -- "$0")/lib.sh"

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

# A directory export is the real-world mistake this guard exists for.
cat > "$SCRATCH/export.ldif" <<'EOF'
version: 1

dn: cn=ldapcfmgr,dc=example,dc=com
objectClass: person
cn: ldapcfmgr
sn: ldapcfmgr
EOF
gzip -c "$SCRATCH/export.ldif" > "$SCRATCH/export.ldif.gz"
bzip2 -c "$SCRATCH/export.ldif" > "$SCRATCH/export.ldif.bz2"
xz -c "$SCRATCH/export.ldif" > "$SCRATCH/export.ldif.xz"

# A genuine log, used to prove a mixed run still produces a report.
cat > "$SCRATCH/access.log" <<'EOF'
2026-04-19T09:59:01.633228219Z ldap1.example.com slapd[2983068]: conn=1 fd=12 ACCEPT from IP=192.0.2.12:50000 (IP=0.0.0.0:389)
2026-04-19T09:59:01.700000000Z ldap1.example.com slapd[2983068]: conn=1 op=0 BIND dn="cn=admin,dc=example,dc=com" method=128
2026-04-19T09:59:01.800000000Z ldap1.example.com slapd[2983068]: conn=1 op=0 RESULT tag=97 err=0 text=
EOF

fail=0
check() { # <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        echo "not-a-log: $1 = $3 OK"
    else
        echo "not-a-log: $1: expected '$2', got '$3'" >&2
        fail=$((fail + 1))
    fi
}

contains() { # <haystack-file> <needle>
    grep -q -- "$2" "$1" && echo yes || echo no
}

# ------------------------------------------------------------------
# 1. A lone non-log file, plain and compressed, is refused.
# ------------------------------------------------------------------
for f in export.ldif export.ldif.gz export.ldif.bz2 export.ldif.xz; do
    rc=0
    env -u TZ "$BIN" -q "$SCRATCH/$f" >"$SCRATCH/out" 2>"$SCRATCH/err" || rc=$?
    check "$f: exit status" 1 "$rc"
    check "$f: names the problem" yes \
        "$(contains "$SCRATCH/err" 'not a supported LDAP log file')"
    check "$f: no report emitted" no \
        "$(contains "$SCRATCH/out" 'LDAP Log Analysis Report')"
done

# ------------------------------------------------------------------
# 2. A binary file is refused the same way (no NUL-terminated text noise).
# ------------------------------------------------------------------
cp /bin/true "$SCRATCH/firmware.bin"
rc=0
env -u TZ "$BIN" -q "$SCRATCH/firmware.bin" >"$SCRATCH/out" 2>"$SCRATCH/err" || rc=$?
check "binary: exit status" 1 "$rc"
check "binary: names the problem" yes \
    "$(contains "$SCRATCH/err" 'not a supported LDAP log file')"

# ------------------------------------------------------------------
# 3. A mixed run keeps the log and skips the export.
# ------------------------------------------------------------------
rc=0
env -u TZ "$BIN" -q -o text "$SCRATCH/access.log" "$SCRATCH/export.ldif" \
    >"$SCRATCH/out" 2>"$SCRATCH/err" || rc=$?
check "mixed: exit status" 0 "$rc"
check "mixed: report produced" yes \
    "$(contains "$SCRATCH/out" 'LDAP Log Analysis Report')"
check "mixed: export named on stderr" yes \
    "$(contains "$SCRATCH/err" 'export.ldif')"

# ------------------------------------------------------------------
# 4. A leading banner and blank lines do not make a log look foreign.
# ------------------------------------------------------------------
{
    echo ""
    echo "2026-04-19T09:59:01.633228219Z ldap1.example.com slapd[2983068]: @(#) \$OpenLDAP: slapd 2.6.7 (Mar 14 2025 12:00:00) \$"
    cat "$SCRATCH/access.log"
} > "$SCRATCH/banner.log"
rc=0
env -u TZ "$BIN" -q -o text "$SCRATCH/banner.log" >"$SCRATCH/out" 2>"$SCRATCH/err" || rc=$?
check "banner: exit status" 0 "$rc"
check "banner: no complaint" no \
    "$(contains "$SCRATCH/err" 'not a supported LDAP log file')"

if [ "$fail" -eq 0 ]; then
    echo "not-a-log: all OK"
    exit 0
fi
echo "not-a-log: $fail check(s) FAILED" >&2
exit 1
