// regex_patterns.hpp

/* 
    SPDX-License-Identifier: AGPL-3.0-or-later
    GNU Affero General Public License v3.0 (https://www.gnu.org/licenses/agpl-3.0.txt)
    Copyright (c) 2026 Manuel FLURY
    All rights reserved.
    
    This file is part of slaplog - an OpenLDAP Log Analysis Tool.
    
    Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later).
    See the LICENSE file distributed with this work for full license text.
    
    THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
    AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


//
// Central registry of all regular expression patterns used by the log-line
// analyser.  The namespace slaplog_rx groups patterns by the kind of log
// message they match — headers, connections, LDAP operations, results,
// replication, session tracking, and miscellaneous server messages.
//
// Capturing groups are documented per pattern so that consumers can
// reliably index into std::smatch results without cross-referencing the
// implementation.

#pragma once
#include <regex>

namespace slaplog_rx {

    // -----------------------------------------------------------------
    // --- Headers ---
    // -----------------------------------------------------------------
    // The three log-line header formats.  Every line processed by the
    // analyser is expected to start with one of these timestamp/prefix
    // patterns.  After the header is stripped, the remainder (payload) is
    // matched against the operation-specific patterns below.

    // [group  1] ISO-8601 datetime (e.g. 2024-01-15T08:30:00+00:00)
    // [group  2] rest of the line (payload)
    inline const std::regex RE_HDR_OL26(R"(^\[(\d{4}-\d{2}-\d{2}T[^\]]+)\]\s+(.*)$)");

    // [group  1] full RFC 3339 timestamp (e.g. 2024-01-15T08:30:00.123456Z)
    // [group  2] log level / facility
    // [group  3] process / component name
    // [group  4] rest of the line (payload)
    inline const std::regex RE_HDR_RFC3339(R"(^(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+(\S+):\s+(.*)$)");

    // [group  1] traditional syslog timestamp (e.g. Jan 15 08:30:00)
    // [group  2] hostname
    // [group  3] process / component name
    // [group  4] rest of the line (payload)
    inline const std::regex RE_HDR_SYSLOG(R"(^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+(.*)$)");

    // -----------------------------------------------------------------
    // --- Connection identifiers ---
    // -----------------------------------------------------------------
    // Simple sub-patterns that extract the connection, operation, and/or
    // file-descriptor numbers from a log line.  These are often composed
    // with the header and payload patterns to form a full match.

    // [group  1] connection ID (may be -1 for unknown/no connection)
    inline const std::regex RE_CONN(R"(conn=(-?\d+))");

    // [group  1] operation ID (may be -1 for unknown/no operation)
    inline const std::regex RE_OP(R"(op=(-?\d+))");

    // [group  1] file descriptor number
    inline const std::regex RE_FD(R"(fd=(\d+))");

    // [group  1] connection ID
    // [group  2] operation ID
    // [group  3] rest of the line after the optional colon separator
    inline const std::regex RE_CONN_OP(R"(^conn=(\d+)\s+op=(\d+)\s*:?\s*(.*)$)");

    // -----------------------------------------------------------------
    // --- Connection events ---
    // -----------------------------------------------------------------
    // Patterns that match the lifecycle events of a client connection:
    // accept (local PATH or IP), close, and TLS establishment.

    // [group  1] connection ID
    // [group  2] fd number
    // [group  3] local socket path (unix-domain socket)
    // Matches: conn=1 fd=12 ACCEPT from PATH=/var/run/slapd.socket
    inline const std::regex RE_ACCEPT_PATH(R"(^conn=(\d+)\s+fd=(\d+)\s+ACCEPT\s+from\s+PATH=(.+?)(?:\s+$.*$)?$)");

    // [group  1] connection ID
    // [group  2] fd number
    // [group  3] remote IP address (with optional port)
    // Matches: conn=1 fd=12 ACCEPT from IP=192.168.1.1:54321
    inline const std::regex RE_ACCEPT_IP(R"(^conn=(\d+)\s+fd=(\d+)\s+ACCEPT\s+from\s+IP=(.+?)(?:\s+$.*$)?$)");

    // [group  1] connection ID
    // [group  2] fd number
    // [group  3] optional reason / additional info
    // Case-insensitive.  Matches: conn=1 fd=12 closed (connection lost)
    inline const std::regex RE_CLOSED(R"(^conn=(\d+)\s+fd=(\d+)\s+closed(?:\s+(.*))?$)", std::regex::icase);

    // [group  1] connection ID
    // [group  2] fd number
    // Case-insensitive.  Matches: conn=1 fd=12 TLS established tls_ssf=256
    inline const std::regex RE_TLS(R"(^conn=(\d+)\s+fd=(\d+)\s+TLS established.*$)", std::regex::icase);

    // -----------------------------------------------------------------
    // --- SASL ---
    // -----------------------------------------------------------------
    // SASL (Simple Authentication and Security Layer) failure reports
    // generated by the slapd SASL subsystem.

    // [group  1] connection ID
    // [group  2] the SASL error/failure message
    // Matches: SASL [conn=1] Failure: mechanism too weak
    inline const std::regex RE_SASL_FAILURE(R"(^SASL\s+\[[^\]]*\]\s+conn=(\d+)\s+(.*)$)");

    // -----------------------------------------------------------------
    // --- BIND ---
    // -----------------------------------------------------------------
    // Five variants of the BIND operation log line, covering authenticated
    // binds (with authcid/authzid), DN+method binds, anonymous binds,
    // DN+mechanism binds, and simple DN-only binds.

    // [group  1] authentication identity (authcid)
    // [group  2] authorisation identity (authzid)
    // Matches: BIND authcid="cn=admin" authzid="cn=admin"
    inline const std::regex RE_BIND_AUTH(R"rx(^BIND\s+authcid="([^"]*)"\s+authzid="([^"]*)"$)rx");

    // [group  1] bind DN
    // [group  2] authentication method number (e.g. 128 for simple)
    // Matches: BIND dn=cn=admin,dc=example,dc=com method=128
    inline const std::regex RE_BIND_DN_METHOD(R"(^BIND\s+dn=(.*)\s+method=(\d+)$)");

    // [group  1] anonymous method / mechanism number
    // Matches: BIND anonymous method=128  or  BIND anonymous mech=simple
    inline const std::regex RE_BIND_ANON(R"(^BIND\s+anonymous\s+(?:method|mech)=(\d+).*$)");

    // [group  1] quoted bind DN
    // [group  2] SASL mechanism name (e.g. PLAIN, GSSAPI, DIGEST-MD5)
    // Matches: BIND dn="cn=admin,dc=example,dc=com" mech=PLAIN
    inline const std::regex RE_BIND_DN_MECH(R"rx(^BIND\s+dn="([^"]*)"\s+mech=([A-Za-z0-9_-]+).*$)rx");

    // [group  1] bind DN (unquoted, first whitespace-delimited token)
    // Matches: BIND dn=cn=admin,dc=example,dc=com
    inline const std::regex RE_BIND_DN(R"(^BIND\s+dn=([^\s]+).*$)");

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
    inline const std::regex RE_SRCH(R"(^SRCH\s+base=(.+?)\s+scope=(\d+)\s+deref=(\d+)\s+filter=(.+)$)");

    // [group  1] requested attribute list (comma- or space-separated)
    // Matches: SRCH attr=cn mail uid
    inline const std::regex RE_SRCH_ATTR(R"(^SRCH\s+attr=(.*)$)");

    // [group  1] modify DN
    // Matches: MOD dn=cn=user,dc=example,dc=com
    inline const std::regex RE_MOD(R"(^MOD\s+dn=([^\s]+).*$)");

    // [group  1] attribute name being modified
    // Matches: MOD attr: userPassword
    inline const std::regex RE_MOD_ATTR(R"(^MOD\s+attr:\s+([^\s]+)$)");

    // [group  1] attribute name (with value after =)
    // Matches: MOD attr=userPassword
    inline const std::regex RE_MOD_ATTR_EQ(R"(^MOD\s+attr=(.*)$)");

    // [group  1] entry DN being added
    // Matches: ADD dn=cn=newuser,dc=example,dc=com
    inline const std::regex RE_ADD(R"(^ADD\s+dn=([^\s]+).*$)");

    // [group  1] entry DN being deleted
    // Matches: DEL dn=cn=olduser,dc=example,dc=com
    inline const std::regex RE_DEL(R"(^DEL\s+dn=([^\s]+).*$)");

    // [group  1] entry DN being renamed
    // Matches: MODRDN dn=cn=user,dc=example,dc=com
    inline const std::regex RE_MODRDN(R"(^MODRDN\s+dn=([^\s]+).*$)");

    // [group  1] DN being compared against
    // Matches: CMP dn=cn=user,dc=example,dc=com
    inline const std::regex RE_CMP(R"(^CMP\s+dn=(.*)$)");

    // [group  1] message ID of the abandoned operation
    // Matches: ABANDON msg=12345  or  ABANDON msgid=12345
    inline const std::regex RE_ABANDON(R"(^ABANDON\s+msg(?:id)?=(\d+).*$)");

    // [group  1] message ID of the unbind
    // Matches: UNBIND msgid=12345
    inline const std::regex RE_UNBIND(R"(^UNBIND\s+msgid=(\d+).*$)");

    // Matches bare UNBIND with no message-id
    inline const std::regex RE_UNBIND_SIMPLE(R"(^UNBIND$)");

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
    inline const std::regex RE_SEARCH_RESULT_FULL(R"rx(^SEARCH RESULT\s+tag=(\d+)\s+err=(\d+)\s+qtime=([\d.]+)\s+etime=([\d.]+)\s+nentries=(\d+)\s+text=(.*)$)rx");

    // Same as RE_SEARCH_RESULT_FULL but without the trailing text= field.
    // [group  1] tag
    // [group  2] error code
    // [group  3] qtime
    // [group  4] etime
    // [group  5] nentries
    inline const std::regex RE_SEARCH_RESULT_NOTEXT(R"rx(^SEARCH RESULT\s+tag=(\d+)\s+err=(\d+)\s+qtime=([\d.]+)\s+etime=([\d.]+)\s+nentries=(\d+)$)rx");

    // Generic result line for non-search operations.
    // [group  1] tag
    // [group  2] error code
    // [group  3] qtime
    // [group  4] etime
    // [group  5] result message text
    // Matches: RESULT tag=105 err=32 qtime=0.000100 etime=0.000200 text=No such attribute
    inline const std::regex RE_RESULT_FULL(R"rx(^RESULT\s+tag=(\d+)\s+err=(\d+)\s+qtime=([\d.]+)\s+etime=([\d.]+)\s+text=(.*)$)rx");

    // Same as RE_RESULT_FULL but without the trailing text= field.
    // [group  1] tag
    // [group  2] error code
    // [group  3] qtime
    // [group  4] etime
    inline const std::regex RE_RESULT_NOTEXT(R"(^RESULT\s+tag=(\d+)\s+err=(\d+)\s+qtime=([\d.]+)\s+etime=([\d.]+)$)");

    // Extended operation result that includes an OID.
    // [group  1] extended request OID
    // [group  2] error code
    // [group  3] qtime
    // [group  4] etime
    // [group  5] result message text
    // Matches: RESULT oid=1.3.6.1.4.1.1466.20037 err=0 qtime=0.000100 etime=0.000200 text=
    inline const std::regex RE_RESULT_OID(R"rx(^RESULT\s+oid=(.*)\s+err=(\d+)\s+qtime=([\d.]+)\s+etime=([\d.]+)\s+text=(.*)$)rx");

    // -----------------------------------------------------------------
    // --- Result sub-patterns ---
    // -----------------------------------------------------------------
    // Individual field patterns extracted from result lines.  These are
    // used as fallback or secondary matchers when the full-line patterns
    // above do not apply (e.g. lines with unusual field ordering).

    // [group  1] LDAP result code
    inline const std::regex RE_ERR(R"(err=(\d+))");

    // [group  1] elapsed time in seconds (e.g. 0.005678)
    inline const std::regex RE_ETIME(R"(etime=([\d.]+))");

    // [group  1] queue time in seconds (e.g. 0.000123)
    inline const std::regex RE_QTIME(R"(qtime=([\d.]+))");

    // [group  1] operation tag number
    inline const std::regex RE_TAG(R"(tag=(\d+))");

    // [group  1] number of entries (search result only)
    inline const std::regex RE_NENTRIES(R"(nentries=(\d+))");

    // [group  1] quoted result text (contents between double quotes)
    inline const std::regex RE_TEXT(R"rx(text="([^"]*)")rx");

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
    inline const std::regex RE_CSN_GET(R"(^slap_get_csn:\s+conn=(-?\d+)\s+op=(-?\d+)\s+generated new csn=(\S+)\s+manage=(\d+).*$)");

    // [group  1] the CSN being queued
    // Matches: slap_queue_csn: queueing 20240115083000.000001Z#000000#000#000000 ...
    inline const std::regex RE_CSN_QUEUE(R"(^slap_queue_csn:\s+queueing\s+\S+\s+(\S+).*$)");

    // [group  1] the CSN being removed (graduated from queue)
    // Matches: slap_graduate_commit_csn: removing 20240115083000.000001Z#000000#000#000000 ...
    inline const std::regex RE_CSN_GRADUATE(R"(^slap_graduate_commit_csn:\s+removing\s+\S+\s+(\S+).*$)");

    // -----------------------------------------------------------------
    // --- Other ---
    // -----------------------------------------------------------------
    // A collection of miscellaneous patterns that do not fit neatly into
    // the categories above.  These cover control handling, indexing
    // issues, extended operations, tracking, and the UNBIND-only line.

    // [group  1] OID of the unrecognised control
    // Matches: slap_global_control: unrecognized control: oid=1.3.6.1.4.1.42.2.27
    inline const std::regex RE_GLOBAL_CONTROL(R"(slap_global_control: unrecognized control: oid=([\d.]+))");

    // [group  1] the attribute or filter component that is not indexed
    // Case-insensitive.  Matches lines produced by mdb or bdb backends
    // when a search filter term is not covered by an index.
    // Example: mdb_search: (uid=foo) not indexed
    inline const std::regex RE_NOT_INDEXED(R"((?:^|,\s+)(?:mdb|bdb)_[a-z_]+:\s+([^)]+)\s+not indexed)", std::regex::icase);

    // [group  1] extended operation OID
    // [group  2] optional additional parameters after the OID
    // Matches: EXT oid=1.3.6.1.4.1.1466.20037
    inline const std::regex RE_EXT(R"(^EXT\s+oid=([\d.]+)(.*)$)");

    // [group  1] the tracking message / payload
    // Matches: TRACK some tracking information
    inline const std::regex RE_TRACK(R"(^TRACK\s+(.*)$)");

    // [group  1] the content inside the question-mark parentheses
    // Matches patterns like (?something) used in slapd debug output
    inline const std::regex RE_QMARK(R"rx(\(\?([^)]+)\))rx");

    // Matches a bare UNBIND with no message-id (alternate form)
    inline const std::regex RE_UNBIND_ONLY(R"(^UNBIND$)");

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
    inline const std::regex RE_SESSION_TRACK_FULL(R"(^\[IP=(\S+)\s+NAME=(.*?)\s+USERNAME=(.*?)\]\s+(.*)$)");

    // Same as RE_SESSION_TRACK_FULL but without the USERNAME field.
    // [group  1] client IP address
    // [group  2] session name
    // [group  3] remainder of log line
    // Matches: [IP=192.168.1.1 NAME=sessionX] SEARCH ...
    inline const std::regex RE_SESSION_TRACK_PARTIAL(R"(^\[IP=(\S+)\s+NAME=(.*?)\]\s+(.*)$)");

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
    inline const std::regex RE_CONTROL_NOT_SUPPORTED(R"rx(^(critical|non-critical)\s+control\s+"([^"]+)"\s+not supported(?:;\s+stripped)?\.$)rx");

    // Matches anonymous BIND with implicit mechanism and SSF fields.
    // No capture groups — used for classification only.
    // Matches: BIND anonymous mech=implicit bind_ssf=128 ssf=128
    inline const std::regex RE_BIND_ANON_MECH_EXT(R"(^BIND\s+anonymous\s+mech=implicit\s+bind_ssf=\d+\s+ssf=\d+$)");

    // Matches bare STARTTLS operation line (no DN or other fields).
    // No capture groups — used for classification only.
    inline const std::regex RE_STARTTLS(R"(^STARTTLS$)");

    // [group  1] the invalid DN value that was submitted
    // Matches: do_bind: invalid dn (cn=invalid dn with spaces)
    inline const std::regex RE_DO_BIND_INVALID(R"(^do_bind:\s+invalid\s+dn\s+\(([^)]+)\)$)");

    // [group  1] the DN that could not be rebound
    // Matches: ldap_back_dobind_int: DN="cn=proxy,dc=example,dc=com" connection was re-established but cannot rebind without creds
    inline const std::regex RE_LDAP_BACK_DOBIND_INT(R"rx(^ldap_back_dobind_int:\s+DN="([^"]+)"\s+connection was re-established but cannot rebind without creds$)rx");

    // [group  1] the LDAP URI being retried
    // [group  2] the DN used for the retry
    // Matches: ldap_back_retry: retrying URI="ldap://backup.example.com" DN="cn=proxy,dc=example,dc=com"
    inline const std::regex RE_LDAP_BACK_RETRY(R"rx(^ldap_back_retry:\s+retrying\s+URI="([^"]+)"\s+DN="([^"]+)"$)rx");

    // [group  1] connection ID
    // [group  2] the operation that was deferred
    // Matches: connection_input: conn=5 deferring operation: BIND dn=cn=admin ...
    inline const std::regex RE_CONN_DEFER(R"(^connection_input:\s+conn=(-?\d+)\s+deferring operation:\s+(.*)$)");

    // Matches slapd daemon shutdown initiation.  No capture groups.
    inline const std::regex RE_DAEMON_SHUTDOWN(R"(^daemon:\s+shutdown requested and initiated\.$)");

    // [group  1] number of remaining operations/tasks
    // Matches: slapd shutdown: waiting for 42 operations/tasks to finish
    inline const std::regex RE_SLAPD_SHUTDOWN(R"(^slapd shutdown:\s+waiting for\s+(\d+)\s+operations/tasks to finish$)");

    // Matches slapd server start notification.  No capture groups.
    inline const std::regex RE_SLAPD_STARTING(R"(^slapd starting$)");

    // Matches slapd clean stop notification.  No capture groups.
    inline const std::regex RE_SLAPD_STOPPED(R"(^slapd stopped\.$)");

} // namespace slaplog_rx
