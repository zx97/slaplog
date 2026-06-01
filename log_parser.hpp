// log_parser.hpp

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
// ===============
// Declarations for the ldap-access log parser: data structures that represent
// a parsed log line, per-connection / per-operation state, aggregation
// results, and the top-level parsing / processing functions.

#ifndef LOG_PARSER_HPP
#define LOG_PARSER_HPP

#include <string>
#include <unordered_map>
#include <map>
#include <vector>
#include <chrono>
#include <atomic>
#include <mutex>
#include <ostream>
#include <optional>
#include <set>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

// ---- Event ----
// Represents a single parsed line from the LDAP access log.  Every field
// that can appear in the various log-line kinds (conn, op, result, etc.)
// is stored here, with optional types used for numeric fields that may be
// absent.
struct Event {
    // --- Line classification ---
    std::string kind;   // e.g. "conn", "op", "result", "fd", "slapd", "daemon", etc.
    std::string raw;    // The complete original log line, verbatim.
    std::string rest;   // The portion of the line after the kind token.

    // --- Common header fields ---
    std::string ts;     // Timestamp of the log entry.
    std::string host;   // Hostname that appears in the syslog-style prefix.
    std::string proc;   // Process identifier (e.g. "slapd[12345]").

    // --- Connection / operation identifiers ---
    std::optional<int> conn;  // Connection number.
    std::optional<int> op;    // Operation number (within a connection).
    std::optional<int> fd;    // File-descriptor number (fd events).

    // --- Result fields ---
    std::optional<int> err;   // LDAP result code (0 = success).
    std::optional<int> tag;   // LDAP protocol tag.
    std::optional<int> scope; // Search scope (0=base, 1=one, 2=sub).
    std::optional<int> deref; // Aliases dereference policy.
    std::optional<int> nentries; // Number of entries returned.
    std::optional<int> method;   // Bind method (0=simple, 3=SASL, etc.).
    std::optional<int> msgid;    // Message ID for extended ops / controls.
    std::optional<int> manage;   // Manage DSA-IT control value (present or absent).

    // --- Timing fields ---
    std::optional<double> qtime;  // Queue time (milliseconds, time spent waiting).
    std::optional<double> etime;  // Execution (elapsed) time (milliseconds).

    // --- Textual metadata ---
    std::string reason;    // Descriptive text or error message.
    std::string src;       // Source IP:port of the client connection.
    std::string authcid;   // Authentication identity (who is binding).
    std::string authzid;   // Authorization identity (who the request acts as).
    std::string binddn;    // Distinguished Name used in a bind operation.
    std::string dn;        // Target DN of the operation.
    std::string base;      // Search base DN.
    std::string filter;    // Search filter string.
    std::string attrs;     // Requested attribute list (comma separated).
    std::string text;      // Free-text field (e.g. additional info).
    std::string oid;       // OID for extended operations or controls.
    std::string csn;       // Context Sequence Number (replication).
    std::string mech;      // SASL mechanism name.

    // --- Session tracking ---
    std::map<std::string, std::string> track; // Key-value pairs from session-tracking control.

    std::string session_ip;       // Client IP extracted from session tracking.
    std::string session_name;     // Session name from session-tracking control.
    std::string session_username; // Username from session-tracking control.
};

// ---- OpState ----
// Tracks the accumulated state of a single LDAP operation while it is
// in-flight.  Fields are populated incrementally as "op" and "result"
// lines arrive.  Once the operation completes (result line received),
// the data is merged into the Aggregator.
struct OpState {
    bool counted = false;      // Whether this op has already been counted in stats.
    std::string type;          // Operation type: BIND, SRCH, ADD, MOD, DEL, etc.
    std::string base;          // Search base (for SRCH operations).
    std::string filter;        // Search filter (for SRCH).
    std::string attrs;         // Requested attributes (for SRCH).
    std::string who;           // Who performed the operation (bind DN or authcid).
    std::string dn;            // Target DN of the operation.
    std::string oid;           // OID for extended operations.
    std::string binddn;        // DN used to authenticate on this connection.
    std::string authcid;       // Authentication identity.
    std::string authzid;       // Authorization identity.
    std::optional<int> method; // Bind method.
    std::optional<int> msgid;  // Message ID (controls / extended ops).
    std::optional<double> etime; // Execution time, populated when result arrives.
    std::optional<double> qtime; // Queue time, populated when result arrives.
    std::optional<int> nentries; // Entry count from result.
    std::optional<int> err;      // Result code.
    std::optional<int> tag;      // Protocol tag.
    std::string text;            // Additional free-text from result.
};

// ---- ConnState ----
// Per-connection state that accumulates across all operations on one
// client connection.  Created when a "conn=" line appears, updated as
// each sub-operation completes, and finalised when the connection closes.
struct ConnState {
    std::map<int, OpState> ops; // Map of operation-number -> in-flight OpState.
    long long ops_count = 0;          // Total operations initiated on this connection.
    long long completed_ops = 0;      // Operations that have received a result.
    double total_etime = 0.0;         // Sum of etime for all completed operations.
    std::string binddn;               // Authenticated DN (set on bind result).
    std::string authcid;              // Authentication identity from the bind.
    std::string app;                  // Application name (from session tracking or note).
    std::string src;                  // Client source IP:port.
    std::optional<int> fd;            // File descriptor associated with this connection.
    std::map<std::string, std::string> track; // Session-tracking key-value pairs.

    // Session-tracking fields (extracted from track KV pairs).
    std::string session_ip;
    std::string session_name;
    std::string session_username;
    bool session_tracked = false; // True once valid session-tracking data is seen.
};

// ---- TopOpRow ----
// Holds data for a single "top operation by etime" entry.  Stored in
// a vector that is sorted after all files are processed.
struct TopOpRow {
    double etime = 0.0;      // Execution time (ms) for this operation.
    int conn = 0;            // Connection number.
    int op = 0;              // Operation number.
    std::string type;        // Operation type (SRCH, BIND, etc.).
    std::string who;         // Who issued the operation.
    std::string base;        // Search base DN.
    std::string filter;      // Search filter.
    std::optional<int> nentries; // Number of entries returned.
    std::optional<int> err;      // Result code.
};

// ---- TopConnRow ----
// Holds data for a single "top connection by total etime" entry.  Stored
// in a vector sorted at the end of processing.
struct TopConnRow {
    double total_etime = 0.0; // Sum of etime across all ops on this connection.
    int conn = 0;             // Connection number.
    std::string who;          // Bound DN or authcid for the connection.
    std::string src;          // Client source IP:port.
    long long ops_count = 0;  // Total operations on this connection.
    std::string binddn;       // Authenticated DN.
    std::string reason;       // Disconnect reason or last error text.
};

// ---- Stats ----
// Simple aggregate counters collected across the entire log set.
struct Stats {
    long long lines = 0;              // Total log lines processed.
    long long fd_open = 0;            // Number of FD open events.
    long long fd_close = 0;           // Number of FD close events.
    long long conn_count = 0;         // Number of unique connections seen.
    long long unknown_lines = 0;      // Lines that could not be parsed.
    long long replication_logs = 0;   // Lines related to replication (syncrepl, etc.).
};

// ---- Aggregator ----
// The top-level structure that holds **all** analysis results produced by
// the parser.  One Aggregator is built per input file; they can be merged
// with merge_aggregators() so that multi-file runs produce a single set
// of results.

// Maximum number of raw unknown-line texts to keep in memory.
// The statistic (Aggregator::stats::unknown_lines) is always accurate;
// once this limit is reached the raw text is discarded to bound memory.
// 100 000 lines × ~200 bytes = ~20 MB, which is a reasonable diagnostic
// window without exhausting RAM on large archives.
constexpr size_t MAX_STORED_UNKNOWN_LINES = 100000;

struct Aggregator {
    // -- Basic counters --
    Stats stats;

    // -- Per-operation-type counts --
    // Maps operation-type string (e.g. "SRCH", "BIND") to the number of
    // completed operations of that type.
    std::map<std::string, long long> operation_count = {
        {"BIND", 0},         {"BIND ANONYMOUS", 0}, {"EXT", 0},      {"ADD", 0},     {"DEL", 0},
        {"MOD", 0},          {"MODRDN", 0},         {"CMP", 0},      {"SRCH", 0},    {"SRCH ATTR", 0},
        {"RESULT", 0},       {"SEARCH RESULT", 0},  {"ABANDON", 0},  {"UNBIND", 0},  {"TLS", 0},
        {"SASL", 0},         {"GLOBAL_CONTROL", 0}, {"SYNCPROV", 0}, {"CSN_GET", 0}, {"CSN_QUEUE", 0},
        {"CSN_GRADUATE", 0}, {"NOT_INDEXED", 0}, {"STARTTLS", 0}};

    // -- Read vs. write breakdown --
    struct {
        long long read = 0;   // Count of read operations (SRCH, CMP).
        long long write = 0;  // Count of write operations (ADD, DEL, MOD, MODRDN).
    } read_write_stats;

    // -- Per-connection state --
    std::map<int, ConnState> conn_state;   // Conn number -> state for active/seen connections.
    std::map<int, std::string> binddn_by_conn; // Quick lookup: conn -> last bind DN.
    std::map<int, std::string> src_by_conn;    // Quick lookup: conn -> source address.

    // -- Time range --
    std::string firsttime; // Timestamp of the earliest log line processed.
    std::string lasttime;  // Timestamp of the latest log line processed.

    // -- Slowest operation (by etime) --
    std::optional<double> maxetime;   // Highest etime value seen.
    std::string maxetimeusr;          // Who issued the slowest operation.
    std::string maxopdesc;            // Description (type + base + filter) of the slowest op.

    // -- Slowest connection (by total etime) --
    std::optional<double> maxconnetime; // Highest total-etime for a single connection.
    std::string maxconnetimeusr;        // Who owned the slowest connection.
    std::string maxconnopdesc;          // Description of operations on that connection.

    // -- Cumulative timing --
    double etime_total = 0.0; // Sum of etime across all completed operations.
    double qtime_total = 0.0; // Sum of qtime across all completed operations.

    // -- Per-app breakdown --
    // Combined into a single map so each unique app name stores its
    // string key once instead of twice (was app_count + app_etime_total).
    struct AppInfo { long long count = 0; double etime_total = 0.0; };
    std::map<std::string, AppInfo> app_stats;

    // -- Per-base breakdown --
    struct BaseInfo { long long count = 0; double etime_total = 0.0; };
    std::map<std::string, BaseInfo> base_stats;

    // -- Per-filter breakdown --
    struct FilterInfo { long long count = 0; double etime_total = 0.0; };
    std::map<std::string, FilterInfo> filter_stats;
    std::map<std::string, long long> norm_filter_attrs_count;  // Normalised filter (attrs only) -> count.
    std::map<std::string, long long> norm_filter_n1_count;     // Normalised filter with 1 RDN -> count.
    std::map<std::string, long long> norm_filter_n0_count;     // Normalised filter with 0 RDNs -> count.
    std::map<std::string, long long> wildcard_filter_count;    // Filters containing wildcards -> count.
    // Flat map (app, filter) -> count. Was a nested map, which stored
    // duplicated filter strings per app; a single combined key avoids
    // the per-app map node overhead.
    std::map<std::pair<std::string, std::string>, long long> filter_by_app;
    std::map<std::string, long long> attr_count;            // Requested attribute -> count.

    // -- "?" (unindexed) filter tracking --
    long long qmark_filter_count = 0;                          // Count of "?" filter occurrences.
    std::map<std::string, long long> qmark_filter_attr_count;  // Attr causing "?" -> count.

    // -- Error tracking --
    std::map<int, long long> error_count;                 // LDAP result code -> count.
    std::map<std::string, std::map<int, long long>> error_per_app; // App -> (code -> count).

    // -- Extended operation & control OID tracking --
    std::map<std::string, long long> ext_oid_count;            // Extended request OID -> count.
    std::map<std::string, long long> global_control_oid_count; // Global control OID -> count.

    // -- CSN event counts (replication) --
    struct {
        long long get = 0;       // CSN get events.
        long long queue = 0;     // CSN queue events.
        long long graduate = 0;  // CSN graduate events.
    } csn_event_count;

    // -- Not-indexed search tracking --
    long long not_indexed_count = 0;               // Count of not-indexed searches.
    std::map<std::string, long long> not_indexed_attr; // Attribute -> count for not-indexed.

    // -- Top-N slowest operations / connections --
    std::vector<TopOpRow> top_ops;      // All completed ops (sorted by etime after processing).
    std::vector<TopConnRow> top_conns;  // All connections (sorted by total_etime after processing).

    // -- Active / peak connection tracking --
    long long active_connections = 0;        // Current number of open connections.
    long long peak_active_connections = 0;   // Peak concurrent connections seen.

    // -- Unparsable lines --
    std::vector<std::string> unknown_lines;  // Raw text of lines that could not be parsed.

    // -- Session tracking correlations --
    // Each entry maps (restart_epoch, conn) to the session-tracked metadata
    // so that even across server restarts the same logical session can be
    // correlated.
    int restart_count = 0;
    struct SessionCorrelation {
        int restart;           // Restart epoch counter.
        int conn;              // Connection number.
        std::string ts;        // Timestamp of the accept event.
        std::string accept_ip; // IP from the accept.
        std::string real_ip;   // Client IP from session-tracking control.
        std::string name;      // Session name.
        std::string username;  // Session username.
        std::string binddn;    // DN used for bind on this session.
    };
    std::map<std::pair<int,int>, SessionCorrelation> session_correlations;

    // -- Misc counters for integrated lines --
    long long control_not_supported_count = 0;
    long long invalid_dn_count = 0;
    long long rebind_failed_count = 0;
    long long retry_count = 0;
    long long defer_count = 0;

    // -- Server start / stop events --
    struct {
        long long start_count = 0;           // Number of server start events.
        long long stop_count = 0;            // Number of server stop events.
        long long shutdown_count = 0;        // Number of shutdown events.
        long long daemon_shutdown_count = 0; // Number of daemon shutdown events.
    } server_events;
    std::vector<std::pair<std::string, std::string>> server_event_list; // (timestamp, event_type) pairs.
};

// ---- Function declarations ----

// Parse a single log line and return a fully populated Event struct.
Event parse_line(const std::string& line);

// Incorporate the data from one parsed Event into the Aggregator,
// updating counters, per-connection state, top-N lists, etc.
// If unknown_out is non-null, unparseable lines are written directly
// to that stream (under unknown_mtx) instead of being stored in the
// Aggregator's unknown_lines vector.
void update_aggregator(Aggregator& agg, const Event& ev,
                       std::ostream* unknown_out = nullptr,
                       std::mutex* unknown_mtx = nullptr);

// Merge the contents of `src` into `dest`.  Used when combining results
// from multiple files processed in parallel.
void merge_aggregators(Aggregator& dest, const Aggregator& src);

// Process a single file by auto-detecting its compression type (plain,
// gzip, bzip2, xz) and calling the appropriate handler.  Uses an atomic
// progress counter for reporting.
// unknown_out / unknown_mtx are forwarded to update_aggregator (see above).
void process_file(const std::string& filename, Aggregator& agg,
                  std::atomic<size_t>& progress,
                  std::ostream* unknown_out = nullptr,
                  std::mutex* unknown_mtx = nullptr);

void process_plain_file(const std::string& filename, Aggregator& agg,
                        std::atomic<size_t>& progress,
                        std::ostream* unknown_out = nullptr,
                        std::mutex* unknown_mtx = nullptr);
void process_gzip_file(const std::string& filename, Aggregator& agg,
                       std::atomic<size_t>& progress,
                       std::ostream* unknown_out = nullptr,
                       std::mutex* unknown_mtx = nullptr);
void process_bzip2_file(const std::string& filename, Aggregator& agg,
                        std::atomic<size_t>& progress,
                        std::ostream* unknown_out = nullptr,
                        std::mutex* unknown_mtx = nullptr);
void process_xz_file(const std::string& filename, Aggregator& agg,
                     std::atomic<size_t>& progress,
                     std::ostream* unknown_out = nullptr,
                     std::mutex* unknown_mtx = nullptr);

#endif // LOG_PARSER_HPP
