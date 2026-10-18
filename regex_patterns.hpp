// regex_patterns.hpp
//
// Central registry of all regular expression patterns used by the log-line
// analyser.  The namespace slaplog_rx groups patterns by the kind of log
// message they match — headers, connections, LDAP operations, results,
// replication, session tracking, and miscellaneous server messages.
//
// Using PCRE2 with JIT (native) or without JIT (WASM) for high performance.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// GNU Affero General Public License v3.0 (https://www.gnu.org/licenses/agpl-3.0.txt)
// Copyright (c) 2026 Manuel FLURY
// All rights reserved.
//
// This file is part of slaplog - an OpenLDAP Log Analysis Tool.
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later).
// See the LICENSE file distributed with this work for full license text.
//
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#pragma once

#include "pcre2_wrapper.hpp"

namespace slaplog_rx {
    using Regex = slaplog_pcre2::Regex;
    using MatchResults = slaplog_pcre2::MatchResults;
    using Flag = slaplog_pcre2::Regex::Flag;
    // Convenience functions for PCRE2 wrapper
    using slaplog_pcre2::regex_match;
    using slaplog_pcre2::regex_search;
} // namespace slaplog_rx

namespace slaplog_rx {

    // -----------------------------------------------------------------
    // --- Headers ---
    // -----------------------------------------------------------------
    // The log-line header formats.  Every line processed by the
    // analyser is expected to start with one of these timestamp/prefix
    // patterns.  After the header is stripped, the remainder (payload) is
    // matched against the operation-specific patterns below.

    // [group  1] ISO-8601 datetime (e.g. 2024-01-15T08:30:00+00:00)
    // [group  2] rest of the line (payload)
    inline const Regex RE_HDR_OL26(R"xx(^\[(\d{4}-\d{2}-\d{2}T[^\]]+)\]\s+(.*)$)xx");

    // [group  1] full RFC 3339 timestamp (e.g. 2024-01-15T08:30:00.123456Z)
    // [group  2] log level / facility
    // [group  3] process / component name
    // [group  4] rest of the line (payload)
    inline const Regex RE_HDR_RFC3339(R"xx(^(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+(\S+):\s+(.*)$)xx");

    // [group  1] traditional syslog timestamp (e.g. Jan 15 08:30:00)
    // [group  2] hostname
    // [group  3] process / component name
    // [group  4] rest of the line (payload)
    inline const Regex RE_HDR_SYSLOG(R"xx(^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+(.*)$)xx");

    // -----------------------------------------------------------------
    // --- OpenLDAP olcLogFileFormat specific header formats ---
    // -----------------------------------------------------------------
    // These formats correspond to the values of olcLogFileFormat directive:
    // debug, syslog-utc, syslog-localtime, rfc3339-utc

    // debug format: hex timestamp + thread ID
    // Format: "%lx.%08x %p " (with CLOCK_GETTIME) or "%lx.%05x %p " (with gettimeofday)
    // [group  1] hex seconds (time_t in hex)
    // [group  2] hex fractional seconds (nanoseconds or microseconds)
    // [group  3] thread ID (pointer as hex)
    // [group  4] rest of the line (payload)
    // Example: 411d2b6a.1f4b2c3a 0x7f9c1e33a700 conn=...
    inline const Regex RE_HDR_DEBUG(R"xx(^([0-9a-f]+)\.([0-9a-f]+)\s+(0x[0-9a-f]+)\s+(.*)$)xx");

    // syslog-utc format: syslog-style timestamp in UTC
    // Format: "%b %d %H:%M:%S" (e.g. "Aug  5 14:23:01")
    // [group  1] syslog timestamp (month day hour:min:sec)
    // [group  2] hostname
    // [group  3] process / component name
    // [group  4] rest of the line (payload)
    inline const Regex RE_HDR_SYSLOG_UTC(R"xx(^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+(.*)$)xx");

    // syslog-localtime format: syslog-style timestamp in local time
    // Format: "%b %d %H:%M:%S" (e.g. "Aug  5 14:23:01")
    // [group  1] syslog timestamp (month day hour:min:sec)
    // [group  2] hostname
    // [group  3] process / component name
    // [group  4] rest of the line (payload)
    inline const Regex RE_HDR_SYSLOG_LOCAL(R"xx(^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+(.*)$)xx");

    // rfc3339-utc format: RFC3339 UTC with fractional seconds
    // Format: "%Y-%m-%dT%H:%M:%S.%09ldZ" (CLOCK_GETTIME) or "%Y-%m-%dT%H:%M:%S.%06ldZ" (gettimeofday)
    // [group  1] full RFC3339 timestamp with fractional seconds and Z suffix
    // [group  2] log level / facility
    // [group  3] process / component name
    // [group  4] rest of the line (payload)
    // Example: 2026-08-05T14:23:01.123456789Z myserver slapd[123]: conn=...
    inline const Regex RE_HDR_RFC3339_UTC(R"xx(^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(\S+)\s+(\S+):\s+(.*)$)xx");

    // -----------------------------------------------------------------
    // --- Connection identifiers ---
    // -----------------------------------------------------------------
    // Simple sub-patterns that extract the connection, operation, and/or
    // file-descriptor numbers from a log line.  These are often composed
    // with the header and payload patterns to form a full match.

    // [group  1] connection ID (may be -1 for unknown/no connection)
    inline const Regex RE_CONN(R"xx(conn=(-?\d+))xx");

    // [group  1] operation ID (may be -1 for unknown/no operation)
    inline const Regex RE_OP(R"xx(op=(-?\d+))xx");

    // [group  1] file descriptor number
    inline const Regex RE_FD(R"xx(fd=(\d+))xx");

    // [group  1] connection ID
    // [group  2] operation ID
    // [group  3] rest of the line after the optional colon separator
    inline const Regex RE_CONN_OP(R"xx(^conn=(\d+)\s+op=(\d+)\s*:?\s*(.*)$)xx");

    // -----------------------------------------------------------------
    // --- Connection events ---
    // -----------------------------------------------------------------
    // Patterns that match the lifecycle events of a client connection:
    // accept (local PATH or IP), close, and TLS establishment.

    // [group  1] connection ID
    // [group  2] fd number
    // [group  3] local socket path (unix-domain socket)
    // Matches: conn=1 fd=12 ACCEPT from PATH=/var/run/slapd.socket
    inline const Regex RE_ACCEPT_PATH(R"xx(^conn=(\d+)\s+fd=(\d+)\s+ACCEPT\s+from\s+PATH=(.+?)(?:\s+$.*$)?$)xx");

    // [group  1] connection ID
    // [group  2] fd number
    // [group  3] remote IP address (with optional port)
    // Matches: conn=1 fd=12 ACCEPT from IP=192.168.1.1:54321
    inline const Regex RE_ACCEPT_IP(R"xx(^conn=(\d+)\s+fd=(\d+)\s+ACCEPT\s+from\s+IP=(.+?)(?:\s+$.*$)?$)xx");

    // [group  1] connection ID
    // [group  2] fd number
    // [group  3] optional reason / additional info
    // Case-insensitive.  Matches: conn=1 fd=12 closed (connection lost)
    // The reason capture group is made to match empty string when no reason
    // is present, to ensure the ovector always has an entry for it.
    inline const Regex RE_CLOSED(R"xx(^conn=(\d+)\s+fd=(\d+)\s+closed(?:\s+(.*))?$)xx", Flag::icase);

    // [group  1] connection ID
    // [group  2] fd number
    // Case-insensitive.  Matches: conn=1 fd=12 TLS established tls_ssf=256
    inline const Regex RE_TLS(R"xx(^conn=(\d+)\s+fd=(\d+)\s+TLS established.*$)xx", Flag::icase);

    // -----------------------------------------------------------------
    // --- SASL ---
    // -----------------------------------------------------------------
    // SASL (Simple Authentication and Security Layer) failure reports
    // generated by the slapd SASL subsystem.

    // [group  1] connection ID
    // [group  2] the SASL error/failure message
    // Matches: SASL [conn=1] Failure: mechanism too weak
    inline const Regex RE_SASL_FAILURE(R"xx(^SASL\s+\[[^\]]*\]\s+conn=(\d+)\s+(.*)$)xx");

    // -----------------------------------------------------------------
    // --- BIND ---
    // -----------------------------------------------------------------
    // Five variants of the BIND operation log line, covering authenticated
    // binds (with authcid/authzid), DN+method binds, anonymous binds,
    // DN+mechanism binds, and simple DN-only binds.

    // [group  1] authentication identity (authcid)
    // [group  2] authorisation identity (authzid)
    // Matches: BIND authcid="cn=admin" authzid="cn=admin"
    inline const Regex RE_BIND_AUTH(R"rx(^BIND\s+authcid="([^"]*)"\s+authzid="([^"]*)"$)rx");

    // [group  1] bind DN
    // [group  2] authentication method number (e.g. 128 for simple)
    // Matches: BIND dn=cn=admin,dc=example,dc=com method=128
    inline const Regex RE_BIND_DN_METHOD(R"xx(^BIND\s+dn=(.*)\s+method=(\d+)$)xx");

    // [group  1] anonymous method / mechanism number
    // Matches: BIND anonymous method=128  or  BIND anonymous mech=simple
    inline const Regex RE_BIND_ANON(R"xx(^BIND\s+anonymous\s+(?:method|mech)=(\d+).*$)xx");

    // [group  1] quoted bind DN
    // [group  2] SASL mechanism name (e.g. PLAIN, GSSAPI, DIGEST-MD5)
    // Matches: BIND dn="cn=admin,dc=example,dc=com" mech=PLAIN
    inline const Regex RE_BIND_DN_MECH(R"rx(^BIND\s+dn="([^"]*)"\s+mech=([A-Za-z0-9_-]+).*$)rx");

    // [group  1] bind DN (unquoted, first whitespace-delimited token)
    // Matches: BIND dn=cn=admin,dc=example,dc=com
    inline const Regex RE_BIND_DN(R"xx(^BIND\s+dn=([^\s]+).*$)xx");

    // -----------------------------------------------------------------
    // --- Operations ---
    // -----------------------------------------------------------------
    // Operation-specific patterns for search, modify, add, delete,
    // modify-RDN, compare, abandon, and unbind.  Each extracts the
    // key parameters that are logged by slapd for that operation type.

    // [group  1] search base DN
    // [group  2] scope (0=base, 1=one, 2=sub, 3=subordinates)
    // [group  3] dereference policy (0-3)
    // [group  4] filter (RFC 4515 filter string)
    // Matches: SRCH base=dc=example,dc=com scope=2 deref=0 filter=(objectClass=*)
    inline const Regex RE_SRCH(R"xx(^SRCH\s+base=(.+?)\s+scope=(\d+)\s+deref=(\d+)\s+filter=(.+)$)xx");

    // [group  1] requested attribute list (comma- or space-separated)
    // Matches: SRCH attr=cn mail uid
    inline const Regex RE_SRCH_ATTR(R"xx(^SRCH\s+attr=(.*)$)xx");

    // [group  1] modify DN
    // Matches: MOD dn=cn=user,dc=example,dc=com
    inline const Regex RE_MOD(R"xx(^MOD\s+dn=([^\s]+).*$)xx");

    // [group  1] attribute name being modified
    // Matches: MOD attr: userPassword
    inline const Regex RE_MOD_ATTR(R"xx(^MOD\s+attr:\s+([^\s]+)$)xx");

    // [group  1] attribute name (with value after =)
    // Matches: MOD attr=userPassword
    inline const Regex RE_MOD_ATTR_EQ(R"xx(^MOD\s+attr=(.*)$)xx");

    // [group  1] entry DN being added
    // Matches: ADD dn=cn=newuser,dc=example,dc=com
    inline const Regex RE_ADD(R"xx(^ADD\s+dn=([^\s]+).*$)xx");

    // [group  1] entry DN being deleted
    // Matches: DEL dn=cn=olduser,dc=example,dc=com
    inline const Regex RE_DEL(R"xx(^DEL\s+dn=([^\s]+).*$)xx");

    // [group  1] entry DN being renamed
    // Matches: MODRDN dn=cn=user,dc=example,dc=com
    inline const Regex RE_MODRDN(R"xx(^MODRDN\s+dn=([^\s]+).*$)xx");

    // [group  1] DN being compared against
    // Matches: CMP dn=cn=user,dc=example,dc=com
    inline const Regex RE_CMP(R"xx(^CMP\s+dn=(.*)$)xx");

    // [group  1] message ID of the abandoned operation
    // Matches: ABANDON msg=12345  or  ABANDON msgid=12345
    inline const Regex RE_ABANDON(R"xx(^ABANDON\s+msg(?:id)?=(\d+).*$)xx");

    // [group  1] message ID of the unbind
    // Matches: UNBIND msgid=12345
    inline const Regex RE_UNBIND(R"xx(^UNBIND\s+msgid=(\d+).*$)xx");

    // Matches bare UNBIND with no message-id
    inline const Regex RE_UNBIND_SIMPLE(R"xx(^UNBIND$)xx");

    // -----------------------------------------------------------------
    // --- Result patterns (full line) ---
    // -----------------------------------------------------------------
    // Result lines are logged at the completion of an LDAP operation.
    // They always contain a tag, error code, queue time (qtime), and
    // elapsed time (etime).  Search results additionally include a
    // nentries count.  Extended operations include an OID.

    // [group  1] operation tag (e.g. 101 for search entry)
    // [group  2] result code (0=success)
    // [group  3] queue time in seconds (fractional)
    // [group  4] elapsed time in seconds (fractional)
    // [group  5] number of entries returned
    // [group  6] result message text
    // Matches: SEARCH RESULT tag=101 err=0 qtime=0.000123 etime=0.005678 nentries=2 text=Success
    inline const Regex RE_SEARCH_RESULT_FULL(R"rx(^SEARCH RESULT\s+tag=(\d+)\s+err=(\d+)\s+qtime=([\d.]+)\s+etime=([\d.]+)\s+nentries=(\d+)\s+text=(.*)$)rx");

    // Same as RE_SEARCH_RESULT_FULL but without the trailing text= field.
    // [group  1] tag
    // [group  2] error code
    // [group  3] qtime
    // [group  4] etime
    // [group  5] nentries
    inline const Regex RE_SEARCH_RESULT_NOTEXT(R"rx(^SEARCH RESULT\s+tag=(\d+)\s+err=(\d+)\s+qtime=([\d.]+)\s+etime=([\d.]+)\s+nentries=(\d+)$)rx");

    // Generic result line for non-search operations.
    // [group  1] tag
    // [group  2] error code
    // [group  3] qtime
    // [group  4] etime
    // [group  5] result message text
    // Matches: RESULT tag=105 err=32 qtime=0.000100 etime=0.000200 text=No such attribute
    inline const Regex RE_RESULT_FULL(R"rx(^RESULT\s+tag=(\d+)\s+err=(\d+)\s+qtime=([\d.]+)\s+etime=([\d.]+)\s+text=(.*)$)rx");

    // Same as RE_RESULT_FULL but without the trailing text= field.
    // [group  1] tag
    // [group  2] error code
    // [group  3] qtime
    // [group  4] etime
    inline const Regex RE_RESULT_NOTEXT(R"xx(^RESULT\s+tag=(\d+)\s+err=(\d+)\s+qtime=([\d.]+)\s+etime=([\d.]+)$)xx");

    // Extended operation result that includes an OID.
    // [group  1] extended request OID
    // [group  2] error code
    // [group  3] qtime
    // [group  4] etime
    // [group  5] result message text
    // Matches: RESULT oid=1.3.6.1.4.1.1466.20037 err=0 qtime=0.000100 etime=0.000200 text=
    inline const Regex RE_RESULT_OID(R"rx(^RESULT\s+oid=(.*)\s+err=(\d+)\s+qtime=([\d.]+)\s+etime=([\d.]+)\s+text=(.*)$)rx");

    // -----------------------------------------------------------------
    // --- Result sub-patterns ---
    // -----------------------------------------------------------------
    // Individual field patterns extracted from result lines.  These are
    // used as fallback or secondary matchers when the full-line patterns
    // above do not apply (e.g. lines with unusual field ordering).

    // [group  1] LDAP result code
    inline const Regex RE_ERR(R"xx(err=(\d+))xx");

    // [group  1] elapsed time in seconds (e.g. 0.005678)
    inline const Regex RE_ETIME(R"xx(etime=([\d.]+))xx");

    // [group  1] queue time in seconds (e.g. 0.000123)
    inline const Regex RE_QTIME(R"xx(qtime=([\d.]+))xx");

    // [group  1] operation tag number
    inline const Regex RE_TAG(R"xx(tag=(\d+))xx");

    // [group  1] number of entries (search result only)
    inline const Regex RE_NENTRIES(R"xx(nentries=(\d+))xx");

    // [group  1] quoted result text (contents between double quotes)
    inline const Regex RE_TEXT(R"rx(text="([^"]*)")rx");

    // -----------------------------------------------------------------
    // --- Replication (CSN) ---
    // -----------------------------------------------------------------
    // Patterns that match slapd's internal Change Sequence Number (CSN)
    // logging.  CSNs are used by syncrepl and mirror-mode replication to
    // track the ordering of changes across servers.

    // [group  1] connection ID
    // [group  2] operation ID
    // [group  3] the newly-generated CSN string
    // [group  4] manage flag (0 or 1)
    // Matches: slap_get_csn: conn=1 op=2 generated new csn=20240115083000.000001Z#000000#000#000000 manage=0
    inline const Regex RE_CSN_GET(R"xx(^slap_get_csn:\s+conn=(-?\d+)\s+op=(-?\d+)\s+generated new csn=(\S+)\s+manage=(\d+).*$)xx");

    // [group  1] the CSN being queued
    // Matches: slap_queue_csn: queueing 20240115083000.000001Z#000000#000#000000 ...
    inline const Regex RE_CSN_QUEUE(R"xx(^slap_queue_csn:\s+queueing\s+\S+\s+(\S+).*$)xx");

    // [group  1] the CSN being removed (graduated from queue)
    // Matches: slap_graduate_commit_csn: removing 20240115083000.000001Z#000000#000#000000 ...
    inline const Regex RE_CSN_GRADUATE(R"xx(^slap_graduate_commit_csn:\s+removing\s+\S+\s+(\S+).*$)xx");

    // -----------------------------------------------------------------
    // --- Other ---
    // -----------------------------------------------------------------
    // A collection of miscellaneous patterns that do not fit neatly into
    // the categories above.  These cover control handling, indexing
    // issues, extended operations, tracking, and the UNBIND-only line.

    // [group  1] OID of the unrecognised control
    // Matches: slap_global_control: unrecognized control: oid=1.3.6.1.4.1.42.2.27
    inline const Regex RE_GLOBAL_CONTROL(R"xx(slap_global_control: unrecognized control: oid=([\d.]+))xx");

    // [group  1] control OID
    // [group  2] "non" when the control is non-critical, empty when critical
    // Matches: => get_ctrls: oid="1.2.840.113556.1.4.319" (critical)
    // Emitted by slapd at loglevel trace for *every* control a request carries,
    // with no conn= prefix — the surrounding lines supply the connection.
    inline const Regex RE_GET_CTRLS(R"rx(^=>\s+get_ctrls:\s+oid="([^"]+)"\s+\((non)?critical\)$)rx");

    // [group  1] the attribute or filter component that is not indexed
    // Case-insensitive.  Matches lines produced by mdb or bdb backends
    // when a search filter term is not covered by an index.
    // Example: mdb_search: (uid=foo) not indexed
    inline const Regex RE_NOT_INDEXED(R"xx((?:^|,\s+)(?:mdb|bdb)_[a-z_]+:\s+([^)]+)\s+not indexed)xx", Flag::icase);

    // [group  1] extended operation OID
    // [group  2] optional additional parameters after the OID
    // Matches: EXT oid=1.3.6.1.4.1.1466.20037
    inline const Regex RE_EXT(R"xx(^EXT\s+oid=([\d.]+)(.*)$)xx");

    // [group  1] the tracking message / payload
    // Matches: TRACK some tracking information
    inline const Regex RE_TRACK(R"xx(^TRACK\s+(.*)$)xx");

    // [group  1] the content inside the question-mark parentheses
    // Matches patterns like (?something) used in slapd debug output
    inline const Regex RE_QMARK(R"rx(\(\?([^)]+)\))rx");

    // Matches a bare UNBIND with no message-id (alternate form)
    inline const Regex RE_UNBIND_ONLY(R"xx(^UNBIND$)xx");

    // -----------------------------------------------------------------
    // --- Session Tracking Control ---
    // -----------------------------------------------------------------
    // Patterns for the LDAP Session Tracking control (RFC 4370).  When
    // this control is active, slapd logs the client's IP, session name,
    // and username in a bracketed prefix.

    // [group  1] client IP address
    // [group  2] session name (may be empty)
    // [group  3] username (may be empty)
    // [group  4] the remainder of the log line after the session info
    // Matches: [IP=192.168.1.1 NAME=sessionX USERNAME=cn=admin] SEARCH ...
    inline const Regex RE_SESSION_TRACK_FULL(R"xx(^\[IP=(\S+)\s+NAME=(.*?)\s+USERNAME=(.*?)\]\s+(.*)$)xx");

    // Same as RE_SESSION_TRACK_FULL but without the USERNAME field.
    // [group  1] client IP address
    // [group  2] session name
    // [group  3] remainder of log line
    // Matches: [IP=192.168.1.1 NAME=sessionX] SEARCH ...
    inline const Regex RE_SESSION_TRACK_PARTIAL(R"xx(^\[IP=(\S+)\s+NAME=(.*?)\]\s+(.*)$)xx");

    // -----------------------------------------------------------------
    // --- Misc unknown-line patterns (conn/op associated) ---
    // -----------------------------------------------------------------
    // Additional patterns that match specific slapd log messages which
    // the analyser classifies as "unknown" (i.e. not one of the standard
    // operation or result lines) but whose content is still meaningful
    // for diagnostics or monitoring.

    // [group  1] severity: "critical" or "non-critical"
    // [group  2] the OID or name of the unsupported control
    // Matches: critical control "1.3.6.1.4.1.42.2.27" not supported
    inline const Regex RE_CONTROL_NOT_SUPPORTED(R"rx(^(critical|non-critical)\s+control\s+"([^"]+)"\s+not supported(?:;\s+stripped)?\.$)rx");

    // Matches anonymous BIND with implicit mechanism and SSF fields.
    // No capture groups — used for classification only.
    // Matches: BIND anonymous mech=implicit bind_ssf=128 ssf=128
    inline const Regex RE_BIND_ANON_MECH_EXT(R"xx(^BIND\s+anonymous\s+mech=implicit\s+bind_ssf=\d+\s+ssf=\d+$)xx");

    // Matches bare STARTTLS operation line (no DN or other fields).
    // No capture groups — used for classification only.
    inline const Regex RE_STARTTLS(R"xx(^STARTTLS$)xx");

    // [group  1] the invalid DN value that was submitted
    // Matches: do_bind: invalid dn (cn=invalid dn with spaces)
    inline const Regex RE_DO_BIND_INVALID(R"xx(^do_bind:\s+invalid\s+dn\s+\(([^)]+)\)$)xx");

    // [group  1] the DN that could not be rebind
    // Matches: ldap_back_dobind_int: DN="cn=proxy,dc=example,dc=com" connection was re-established but cannot rebind without creds
    inline const Regex RE_LDAP_BACK_DOBIND_INT(R"rx(^ldap_back_dobind_int:\s+DN="([^"]+)"\s+connection was re-established but cannot rebind without creds$)rx");

    // [group  1] the LDAP URI being retried
    // [group  2] the DN used for the retry
    // Matches: ldap_back_retry: retrying URI="ldap://backup.example.com" DN="cn=proxy,dc=example,dc=com"
    inline const Regex RE_LDAP_BACK_RETRY(R"rx(^ldap_back_retry:\s+retrying\s+URI="([^"]+)"\s+DN="([^"]+)"$)rx");

    // [group  1] connection ID
    // [group  2] the operation that was deferred
    // Matches: connection_input: conn=5 deferring operation: BIND dn=cn=admin ...
    inline const Regex RE_CONN_DEFER(R"xx(^connection_input:\s+conn=(-?\d+)\s+deferring operation:\s+(.*)$)xx");

    // Matches slapd daemon shutdown initiation.  No capture groups.
    inline const Regex RE_DAEMON_SHUTDOWN(R"xx(^daemon:\s+shutdown requested and initiated\.$)xx");

    // [group  1] number of remaining operations/tasks
    // Matches: slapd shutdown: waiting for 42 operations/tasks to finish
    inline const Regex RE_SLAPD_SHUTDOWN(R"xx(^slapd shutdown:\s+waiting for\s+(\d+)\s+operations/tasks to finish$)xx");

    // Matches slapd server start notification.  No capture groups.
    inline const Regex RE_SLAPD_STARTING(R"xx(^slapd starting$)xx");

    // Matches slapd clean stop notification.  No capture groups.
    inline const Regex RE_SLAPD_STOPPED(R"xx(^slapd stopped\.$)xx");

} // namespace slaplog_rx