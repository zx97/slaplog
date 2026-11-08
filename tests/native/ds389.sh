#!/bin/sh
# tests/native/ds389.sh — 389 Directory Server access logs.
#
# Checks the text (default), JSON and json-pretty access formats end to end, the
# local-time-plus-offset decoding, and the one-format-per-run rule used to keep
# the per-line loop monomorphic (a mixed directory is refused with a pointer to
# --save-state/--resume).  The non-access streams (errors/audit/security) are
# recognised and skipped rather than folded in as unknown lines.
#
# The fixtures are synthetic: the real 389-ds sample set carries production
# identifiers and must not be committed.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
. "$(dirname -- "$0")/lib.sh"

SCRATCH=$(new_scratch)
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

fail=0
check() { # <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        echo "ds389: $1 = $3 OK"
    else
        echo "ds389: $1 = $3 (expected $2) FAIL"
        fail=1
    fi
}

stat_of() { # <file> <field> -> value column of the statistics table
    env -u TZ "$BIN" -q -o text -s stats "$1" 2>/dev/null \
        | grep -F "| $2" | head -1 | sed 's/.*| \(.*\)| *$/\1/' | sed 's/ *$//'
}

# --- text access log -------------------------------------------------------
# Title (two tab lines), the blank line after it (which used to truncate the
# file), then the 389-ds operations.
cat > "$SCRATCH/access.log" <<'EOF'
	389-Directory/2.6.0 B2026.001.0000
	ldap01.example.com:389 (/etc/dirsrv/slapd-ldap01)

[17/Oct/2026:02:00:47.302202000 +0200] conn=1 fd=7 slot=0 connection from 192.0.2.10 to 192.0.2.20
[17/Oct/2026:02:00:47.302350000 +0200] conn=1 op=0 BIND dn="cn=Directory Manager" method=128 version=3
[17/Oct/2026:02:00:47.302488000 +0200] conn=1 op=0 RESULT err=0 tag=97 nentries=0 wqtime=0.000109391 wtime=0.000026200 optime=0.000045759 etime=0.000194658
[17/Oct/2026:02:03:39.311753000 +0200] conn=1 op=1 SRCH base="ou=People,dc=example,dc=org" scope=2 filter="(objectClass=*)" attrs=uid
[17/Oct/2026:02:03:39.312379000 +0200] conn=1 op=1 RESULT err=0 tag=101 nentries=1 wqtime=0.000021603 wtime=0.000054652 optime=0.000216700 etime=0.000309649
[17/Oct/2026:02:03:39.315832000 +0200] conn=1 op=2 UNBIND
[17/Oct/2026:02:03:39.316181000 +0200] conn=1 op=2 fd=7 Disconnect - Cleanly Closed Connection - U1
[17/Oct/2026:02:04:28.235523000 +0200] conn=2 fd=8 slot=1 SSL connection from 192.0.2.11 to 192.0.2.20
[17/Oct/2026:02:04:28.236205000 +0200] conn=2 op=0 BIND dn="" method=128 version=3
[17/Oct/2026:02:04:28.236979000 +0200] conn=2 op=0 RESULT err=49 tag=97 nentries=0 wqtime=0.000107937 wtime=0.000058302 optime=0.000866890 etime=0.001040296
[17/Oct/2026:02:04:28.238141000 +0200] conn=2 op=1 UNBIND
[17/Oct/2026:02:04:28.238744000 +0200] conn=2 op=1 fd=8 Disconnect - Cleanly Closed Connection - U1
EOF

check "text: lines"          15 "$(stat_of "$SCRATCH/access.log" "Lines processed")"
check "text: unknown"         0 "$(stat_of "$SCRATCH/access.log" "Unknown lines")"
check "text: connections"     "2 / 2" "$(stat_of "$SCRATCH/access.log" "Connections opened / closed")"
check "text: local->UTC" \
    "from 2026-10-17T00:00:47.302202000Z" \
    "$(stat_of "$SCRATCH/access.log" "Time range" | sed 's/ to .*//')"

# --- JSON access log -------------------------------------------------------
cat > "$SCRATCH/access.json" <<'EOF'
{"header":{"version":"389-Directory/2.6.0 B2026.001.0000","instance":"ldap01.example.com:389 (/etc/dirsrv/slapd-ldap01)"}}
{"local_time":"2026-10-17T02:00:47.302202000 +0200","operation":"CONNECTION","key":"1792192847-1","conn_id":1,"fd":7,"tls":false,"client_ip":"192.0.2.10","server_ip":"192.0.2.20"}
{"local_time":"2026-10-17T02:00:47.302350000 +0200","operation":"BIND","key":"1792192847-1","conn_id":1,"op_id":0,"bind_dn":"cn=Directory Manager","version":3,"method":"128"}
{"local_time":"2026-10-17T02:00:47.302488000 +0200","operation":"RESULT","key":"1792192847-1","conn_id":1,"op_id":0,"tag":97,"err":0,"nentries":0,"wqtime":"0.000109391","etime":"0.000194658"}
{"local_time":"2026-10-17T02:03:39.311753000 +0200","operation":"SEARCH","key":"1792192847-1","conn_id":1,"op_id":1,"base_dn":"ou=People,dc=example,dc=org","scope":2,"filter":"(objectClass=*)","attrs":["uid"]}
{"local_time":"2026-10-17T02:03:39.312379000 +0200","operation":"RESULT","key":"1792192847-1","conn_id":1,"op_id":1,"tag":101,"err":0,"nentries":1,"etime":"0.000309649"}
{"local_time":"2026-10-17T02:03:39.315832000 +0200","operation":"UNBIND","key":"1792192847-1","conn_id":1,"op_id":2}
{"local_time":"2026-10-17T02:03:39.316181000 +0200","operation":"DISCONNECT","key":"1792192847-1","conn_id":1,"op_id":2,"fd":7,"close_reason":"Cleanly Closed Connection - U1"}
EOF

check "json: lines"       8 "$(stat_of "$SCRATCH/access.json" "Lines processed")"
check "json: unknown"     0 "$(stat_of "$SCRATCH/access.json" "Unknown lines")"
check "json: connections" "1 / 1" "$(stat_of "$SCRATCH/access.json" "Connections opened / closed")"
check "json: local->UTC" \
    "from 2026-10-17T00:00:47.302202000Z" \
    "$(stat_of "$SCRATCH/access.json" "Time range" | sed 's/ to .*//')"

# --- json-pretty -----------------------------------------------------------
cat > "$SCRATCH/pretty.log" <<'EOF'
{
  "header": {
    "version": "389-Directory/2.6.0 B2026.001.0000",
    "instance": "ldap01.example.com:389 (/etc/dirsrv/slapd-ldap01)"
  }
}
{
  "local_time": "2026-10-17T02:00:47.302202000 +0200",
  "operation": "CONNECTION",
  "conn_id": 1,
  "fd": 7,
  "client_ip": "192.0.2.10"
}
{
  "local_time": "2026-10-17T02:00:47.302350000 +0200",
  "operation": "BIND",
  "conn_id": 1,
  "op_id": 0,
  "bind_dn": "cn=Directory Manager",
  "version": 3,
  "method": "128"
}
EOF

check "pretty: records"   3 "$(stat_of "$SCRATCH/pretty.log" "Lines processed")"
check "pretty: unknown"   0 "$(stat_of "$SCRATCH/pretty.log" "Unknown lines")"
check "pretty: connections" "1 / 0" "$(stat_of "$SCRATCH/pretty.log" "Connections opened / closed")"

# --- SASL bind, unindexed notes, forced format -----------------------------
cat > "$SCRATCH/sasl.log" <<'EOF'
[17/Oct/2026:02:00:47.302350000 +0200] conn=1 op=0 BIND dn="cn=Directory Manager" method=sasl version=3 mech="GSSAPI"
[17/Oct/2026:02:00:47.302488000 +0200] conn=1 op=0 RESULT err=0 tag=97 nentries=0 etime=0.000194658
[17/Oct/2026:02:03:39.311753000 +0200] conn=1 op=1 SRCH base="ou=People,dc=example,dc=org" scope=2 filter="(uid=x)" attrs=uid
[17/Oct/2026:02:03:39.312379000 +0200] conn=1 op=1 RESULT err=0 tag=101 nentries=1 notes=U etime=0.000309649
EOF
if env -u TZ "$BIN" -q -o json "$SCRATCH/sasl.log" 2>/dev/null | grep -q '"SASL": 1'; then
    echo "ds389: method=sasl is classified as SASL OK"
else
    echo "ds389: method=sasl is classified as SASL FAIL"; fail=1
fi
check "notes=U counts as not indexed" 1 \
    "$(env -u TZ "$BIN" -q -o text -s index "$SCRATCH/sasl.log" 2>/dev/null \
       | grep -F 'Not indexed occurrences' | sed 's/.*: *//' | sed 's/ *$//')"

# Forcing the parser must give exactly the auto-detected result.
check "forced 389ds-json matches auto" \
    "$(stat_of "$SCRATCH/access.json" "Lines processed")" \
    "$(env -u TZ "$BIN" -q -o text -s stats --log-format 389ds-json "$SCRATCH/access.json" 2>/dev/null \
       | grep -F '| Lines processed' | head -1 | sed 's/.*| \(.*\)| *$/\1/' | sed 's/ *$//')"

# --- errors log: counters per severity and subsystem -----------------------
cat > "$SCRATCH/errors.log" <<'EOF'
	389-Directory/2.6.0 B2026.001.0000
	ldap01.example.com:389 (/etc/dirsrv/slapd-ldap01)

[17/Oct/2026:02:01:40.000000000 +0200] - WARNING - ldbm_back_ldbm2index - Attribute 'description' is not indexed; full table scan possible
[17/Oct/2026:08:12:07.000000000 +0200] - NOTICE - NSMMReplicationPlugin - Beginning total update of replica
[17/Oct/2026:11:58:02.000000000 +0200] - ERR - ldbm_back_search - Database error: -30995 (DB_RUNRECOVERY)
continued stack trace line, no timestamp
EOF
check "errors text: entries" 3 \
    "$(env -u TZ "$BIN" -q -o text -s stats "$SCRATCH/errors.log" 2>/dev/null \
       | grep -F '| Server log entries' | sed 's/.*| \(.*\)| *$/\1/' | sed 's/ *$//')"
check "errors text: severities" "ERR 1, NOTICE 1, WARNING 1" \
    "$(env -u TZ "$BIN" -q -o text -s stats "$SCRATCH/errors.log" 2>/dev/null \
       | grep -F '| Severities' | sed 's/.*| \(.*\)| *$/\1/' | sed 's/ *$//')"
check "errors text: subsystem" 1 \
    "$(env -u TZ "$BIN" -q -o text -s stats "$SCRATCH/errors.log" 2>/dev/null \
       | grep -F '| Subsystems' | grep -c 'NSMMReplicationPlugin 1')"

cat > "$SCRATCH/errors.json" <<'EOF'
{"header":{"version":"389-Directory/2.6.0 B2026.001.0000","instance":"ldap01.example.com:389"}}
{"local_time":"2026-10-17T02:01:40.000000000 +0200","severity":"ERR","subsystem":"ldbm_back_search","msg":"Database error"}
{"local_time":"2026-10-17T02:01:41.000000000 +0200","severity":"INFO","subsystem":"slapd_daemon","msg":"listening"}
EOF
check "errors json: entries" 2 \
    "$(env -u TZ "$BIN" -q -o text -s stats "$SCRATCH/errors.json" 2>/dev/null \
       | grep -F '| Server log entries' | sed 's/.*| \(.*\)| *$/\1/' | sed 's/ *$//')"

# The counters survive a state file (schema 7).
env -u TZ "$BIN" -q -o text -s stats "$SCRATCH/errors.log" \
    --save-state "$SCRATCH/e.state" >/dev/null 2>&1
check "errors: state round-trip" 3 \
    "$(env -u TZ "$BIN" -q -o text -s stats --resume "$SCRATCH/e.state" 2>/dev/null \
       | grep -F '| Server log entries' | sed 's/.*| \(.*\)| *$/\1/' | sed 's/ *$//')"

# --- audit and security streams are recognised and skipped -----------------
cat > "$SCRATCH/audit.log" <<'EOF'
time: 20261017121512
dn: uid=jdoe,ou=People,dc=example,dc=org
changetype: modify
replace: cn
cn: John Doe
-
EOF
if env -u TZ "$BIN" -q -o text "$SCRATCH/audit.log" >/dev/null 2>"$SCRATCH/err.txt"; then
    echo "ds389: audit stream should not be analysed FAIL"; fail=1
else
    if grep -q "not an access log" "$SCRATCH/err.txt"; then
        echo "ds389: audit stream refused with a clear reason OK"
    else
        echo "ds389: audit stream refused with a clear reason FAIL"; fail=1
    fi
fi

# --- one format per run ----------------------------------------------------
# A text file and a JSON file in the same run: the first fixes the format, the
# other is skipped and the user is pointed at --save-state/--resume.
cp "$SCRATCH/access.log" "$SCRATCH/a_text.log"
cp "$SCRATCH/access.json" "$SCRATCH/z_json.log"
env -u TZ "$BIN" -q -o text -s stats "$SCRATCH/a_text.log" "$SCRATCH/z_json.log" \
    >"$SCRATCH/mixed.txt" 2>"$SCRATCH/mixed.err"
check "mixed: only the text file is counted" 15 \
    "$(grep -F '| Lines processed' "$SCRATCH/mixed.txt" | sed 's/.*| \(.*\)| *$/\1/' | sed 's/ *$//')"
if grep -q "different log format for this run" "$SCRATCH/mixed.err"; then
    echo "ds389: mixed run names the skipped format OK"
else
    echo "ds389: mixed run names the skipped format FAIL"; fail=1
fi

# --- LDAPI autobind, op=-1 and internal-op shapes ---------------------------
# Taken from a real 389-Directory/3.1.2 access log:
#   * AUTOBIND is followed by a regular BIND method=sasl mech=EXTERNAL, so it
#     must be recognised without counting a second bind;
#   * "op=-1" belongs to no operation and must not be treated as a parse error;
#   * internal operations appear as "conn=N (Internal) op=M(i)(n)" and
#     "conn=Internal(N) op=M(i)(n)".
cat > "$SCRATCH/ldapi.log" <<'EOF'
[08/Nov/2026:10:33:56.404213041 +0000] conn=1 fd=64 slot=64 connection from local to /run/slapd-localhost.socket
[08/Nov/2026:10:33:56.404438093 +0000] conn=1 AUTOBIND dn="cn=Directory Manager"
[08/Nov/2026:10:33:56.404443163 +0000] conn=1 op=0 BIND dn="cn=Directory Manager" method=sasl version=3 mech=EXTERNAL
[08/Nov/2026:10:33:56.404460886 +0000] conn=1 op=0 RESULT err=0 tag=97 nentries=0 etime=0.000165731 dn="cn=Directory Manager"
[08/Nov/2026:10:33:56.750793386 +0000] conn=1 op=-1 fd=64 Disconnect - Operation canceled - Connection aborted - A1
[08/Nov/2026:10:34:44.857423062 +0000] conn=13 (Internal) op=0(1)(1) SRCH base="cn=Directory Manager" scope=0 filter="(objectclass=*)" attrs=ALL
[08/Nov/2026:10:34:44.857423063 +0000] conn=13 (Internal) op=0(1)(1) RESULT err=32 tag=48 nentries=0 etime=0.000035416
[08/Nov/2026:10:34:44.857428463 +0000] conn=Internal(0) op=0(2)(2) RESULT err=32 tag=48 nentries=0 etime=0.000047058
EOF
check "ldapi: lines"   8 "$(stat_of "$SCRATCH/ldapi.log" "Lines processed")"
check "ldapi: unknown" 0 "$(stat_of "$SCRATCH/ldapi.log" "Unknown lines")"
check "ldapi: connections" "1 / 1" "$(stat_of "$SCRATCH/ldapi.log" "Connections opened / closed")"
if env -u TZ "$BIN" -q -o json "$SCRATCH/ldapi.log" 2>/dev/null \
        | grep -q '"SASL": 1'; then
    echo "ds389: AUTOBIND does not double the bind count OK"
else
    echo "ds389: AUTOBIND does not double the bind count FAIL"; fail=1
fi

# The JSON stream carries the same AUTOBIND event.
cat > "$SCRATCH/ldapi.json" <<'EOF'
{"local_time":"2026-11-08T10:41:11.343490330 +0000","operation":"AUTOBIND","key":"1-1","conn_id":1,"bind_dn":"cn=Directory Manager"}
{"local_time":"2026-11-08T10:41:11.343000000 +0000","operation":"CONNECTION","key":"1-1","conn_id":1,"client_ip":"192.0.2.10"}
{"local_time":"2026-11-08T10:41:11.500000000 +0000","operation":"BIND","key":"1-1","conn_id":1,"op_id":0,"bind_dn":"cn=Directory Manager","method":"sasl","mech":"EXTERNAL"}
EOF
check "ldapi json: unknown" 0 "$(stat_of "$SCRATCH/ldapi.json" "Unknown lines")"

exit $fail
