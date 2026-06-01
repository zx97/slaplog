// log_parser.cpp

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


// ==============
// Implementation of the LDAP access-log parser.  This file contains the
// core parsing and aggregation logic that transforms raw slapd log lines
// into structured Event objects, then folds those events into an
// Aggregator structure that accumulates all statistics.
//
// The parsing pipeline has two stages:
//   1. parse_line()   — classify a single line and extract its fields.
//   2. update_aggregator() — merge one Event into the running Aggregator.
//
// Multi-file processing is supported through process_file() (which
// auto-detects .gz/.bz2/.xz compression) and merge_aggregators() for
// combining results from parallel workers.
//
// Dependencies:
//   - regex_patterns.hpp : all regular expressions (namespace slaplog_rx).
//   - utils.hpp          : string helpers (ends_with, timestamp parsing).
//   - zlib / bzlib / lzma : transparent decompression.

#include "log_parser.hpp"
#include "regex_patterns.hpp"
#include "utils.hpp"
#include <map>
#include <regex>
#include <string>
#include <vector>
#include <iostream>
#include <mutex>
#include <fstream>
#include <cstring>
#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>
#include <cctype>
#include <cstdlib>     // std::strtod (portable float parsing; from_chars<double> needs GCC 11+)
#include <algorithm>
#include <set>
#include <sstream>
#include <iomanip>
#include <charconv>

// using namespace slaplog_rx;

// =========================================================================
// Helper Functions — string manipulation and data conversion
// =========================================================================

/**
 * dequote: Remove surrounding double quotes from a string, if present.
 *
 * Input:  any string
 * Output: the same string with the first and last characters erased
 *         iff the string is >= 2 characters and both are '"'.
 *         Otherwise unchanged.
 *
 * Example:  dequote("\"cn=admin\"") -> "cn=admin"
 *           dequote("plain")        -> "plain"
 */
    std::string dequote(std::string s) {
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
            s.erase(s.begin());
            s.pop_back();
        }
        return s;
    }

/**
 * to_int: Convert a std::ssub_match (regex capture group) to an integer.
 *
 * Uses std::from_chars for fast, no-allocation parsing.
 * Returns 0 when the sub-match is empty or on conversion failure.
 */
    int to_int(const std::ssub_match& m) {
        int v = 0;
        if (m.matched) {
            auto r = std::from_chars(&*m.first, &*m.second, v);
            if (r.ec != std::errc()) v = 0;
        }
        return v;
    }

/**
 * to_double: Convert a std::ssub_match (regex capture group) to a double.
 *
 * Used for floating-point values (qtime, etime).  Returns 0.0 when the
 * sub-match is empty or on conversion failure.
 *
 * NOTE: We intentionally do NOT use std::from_chars here.  The
 * floating-point overload of std::from_chars was only implemented in
 * libstdc++ starting with GCC 11; GCC 8 (RHEL 8 default toolchain) ships
 * only the integer overloads, so calling it on a double fails to compile.
 * std::strtod is portable across all supported compilers.  The sub-match
 * range is copied into a std::string to guarantee NUL termination, since
 * the underlying log line is not terminated at m.second.
 */
    double to_double(const std::ssub_match& m) {
        if (!m.matched) return 0.0;
        std::string s(m.first, m.second);
        const char* begin = s.c_str();
        char* end = nullptr;
        double v = std::strtod(begin, &end);
        if (end == begin) return 0.0;  // no conversion performed
        return v;
    }

/**
 * trim: Strip leading and trailing whitespace from a string.
 *
 * Whitespace is defined by std::isspace() (space, tab, CR, NL, etc.).
 * Returns a new string — the original is not modified.
 */
    std::string trim(const std::string& s) {
        size_t b = 0, e = s.size();
        while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
        while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
        return s.substr(b, e - b);
    }

/**
 * to_lower: Convert a string to lowercase in-place and return it.
 *
 * Uses std::tolower on each character.  Non-ASCII characters are
 * passed through unchanged (unsigned char cast avoids UB).
 */
    std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }

/**
 * normalize_filter: Canonicalise a search filter string for aggregation.
 *
 * Steps:
 *   1. Remove surrounding double quotes (dequote).
 *   2. Collapse consecutive whitespace into a single space.
 *   3. Lowercase everything.
 *   4. Trim leading/trailing whitespace.
 *
 * This ensures that semantically identical filters (e.g. "(uid=foo)"
 * vs. "(uid=FOO)") are counted together.
 */
    std::string normalize_filter(std::string f) {
        if (f.empty()) return "";
        f = dequote(f);
        std::string out;
        bool prev_space = false;
        for (char c : f) {
            if (std::isspace(static_cast<unsigned char>(c))) {
                if (!prev_space) out.push_back(' ');
                prev_space = true;
            } else {
                out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
                prev_space = false;
            }
        }
        return trim(out);
    }

/**
 * normalize_attrs: Canonicalise a space-separated attribute list.
 *
 * Steps:
 *   1. Tokenise by whitespace.
 *   2. Lowercase each token.
 *   3. Sort tokens alphabetically.
 *   4. Rejoin with single spaces.
 *
 * This ensures "[cn mail uid]" and "[uid cn mail]" are treated as
 * the same attribute set for aggregation.
 */
    std::string normalize_attrs(const std::string& s) {
        if (s.empty()) return "";
        std::istringstream iss(s);
        std::vector<std::string> attrs;
        std::string a;
        while (iss >> a) attrs.push_back(to_lower(a));
        std::sort(attrs.begin(), attrs.end());
        std::ostringstream oss;
        for (size_t i = 0; i < attrs.size(); ++i) {
            if (i) oss << ' ';
            oss << attrs[i];
        }
        return oss.str();
    }

/**
 * ts_sort_key: Convert a timestamp string into a sortable numeric key.
 *
 * Recognises two formats:
 *   - RFC 3339 / ISO-8601  : "2024-01-15T08:30:00..."  -> "20240115083000"
 *   - Syslog (month day HH:MM:SS) : "Jan 15 08:30:00"   -> "00000115083000"
 *
 * For syslog format the year is unknown so "0000" is used as a placeholder.
 * If neither format matches, the original string is returned as-is.
 */
    std::string ts_sort_key(const std::string& ts) {
        if (ts.empty()) return "";
        static const std::regex rfc3339(R"(^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}))");
        static const std::regex syslog(R"(^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})$)");
        std::smatch m;
        if (std::regex_search(ts, m, rfc3339)) {
            std::ostringstream oss;
            oss << m[1].str() << m[2].str() << m[3].str() << m[4].str() << m[5].str() << m[6].str();
            return oss.str();
        }
        if (std::regex_match(ts, m, syslog)) {
            static const std::map<std::string, int> mon = {{"Jan", 1}, {"Feb", 2}, {"Mar", 3}, {"Apr", 4},
                {"May", 5}, {"Jun", 6}, {"Jul", 7}, {"Aug", 8},
                {"Sep", 9}, {"Oct", 10}, {"Nov", 11}, {"Dec", 12}};
            int month = 0;
            auto it = mon.find(m[1].str());
            if (it != mon.end()) month = it->second;
            std::ostringstream oss;
            oss << "0000" << std::setw(2) << std::setfill('0') << month << std::setw(2) << std::setfill('0')
                << std::stoi(m[2].str()) << m[3].str() << m[4].str() << m[5].str();
            return oss.str();
        }
        return ts;
    }

/**
 * update_time_bounds: Expand the Aggregator's time range to include `ts`.
 *
 * Maintains agg.firsttime (earliest) and agg.lasttime (latest) timestamps
 * by comparing sort keys derived via ts_sort_key().
 */
    void update_time_bounds(Aggregator& agg, const std::string& ts) {
        if (ts.empty()) return;
        std::string key = ts_sort_key(ts);
        if (agg.firsttime.empty() || key < ts_sort_key(agg.firsttime)) {
            agg.firsttime = ts;
        }
        if (agg.lasttime.empty() || key > ts_sort_key(agg.lasttime)) {
            agg.lasttime = ts;
        }
    }

// =========================================================================
// Aggregator Helper Functions
// =========================================================================

/**
 * ensure_conn: Return a reference to the ConnState for a given connection ID.
 *
 * The operator[] on the map will default-construct a new ConnState if
 * the connection ID has not been seen before.
 */
    ConnState& ensure_conn(Aggregator& agg, int cid) {
        return agg.conn_state[cid];
    }

/**
 * ensure_op: Return a reference to the OpState for a given (conn, op) pair.
 *
 * Also default-constructs the ConnState for cid if necessary.
 */
    OpState& ensure_op(Aggregator& agg, int cid, int opid) {
        return agg.conn_state[cid].ops[opid];
    }

/**
 * ensure_total_counted: Mark an operation as counted, incrementing the
 * connection's ops_count on first call.
 *
 * The ops_count tracks the total number of initiated operations on a
 * connection (regardless of whether they have completed).  The `counted`
 * guard prevents double-counting when multiple log lines refer to the
 * same operation (e.g. SRCH followed by SEARCH RESULT).
 */
    void ensure_total_counted(Aggregator& agg, int cid, int opid) {
        auto& conn = agg.conn_state[cid];
        auto& op = conn.ops[opid];
        if (op.counted) return;
        op.counted = true;
        conn.ops_count++;
    }

/**
 * app_for_conn: Determine the "application" or "user" identity for a
 * connection, using a priority chain of available data:
 *
 *   1. binddn (DN used to authenticate)
 *   2. authcid (authentication identity)
 *   3. TRACK USERNAME (session-tracking control)
 *   4. TRACK NAME (session-tracking control)
 *   5. conn.app (explicitly set app name)
 *   6. "unknown" (fallback)
 */
    std::string app_for_conn(const Aggregator& agg, int cid) {
        auto it = agg.conn_state.find(cid);
        if (it == agg.conn_state.end()) return "unknown";
        const auto& conn = it->second;
        if (!conn.binddn.empty()) return conn.binddn;
        if (!conn.authcid.empty()) return conn.authcid;
        auto itu = conn.track.find("USERNAME");
        if (itu != conn.track.end() && !itu->second.empty()) return itu->second;
        auto itn = conn.track.find("NAME");
        if (itn != conn.track.end() && !itn->second.empty()) return itn->second;
        if (!conn.app.empty()) return conn.app;
        return "unknown";
    }

/**
 * track_qmark_filter: Search a filter string for "(?attr)" patterns that
 * indicate unindexed attribute lookups (commonly flagged by slapd's
 * mdb/bdb backends).
 *
 * Each match increments the global qmark_filter_count and the
 * per-attribute count in qmark_filter_attr_count.
 */
    void track_qmark_filter(Aggregator& agg, const std::string& filter) {
        std::smatch m;
        std::string f = filter;
        while (std::regex_search(f, m, slaplog_rx::RE_QMARK)) {
            agg.qmark_filter_count++;
            agg.qmark_filter_attr_count[m[1].str()]++;
            f = m.suffix().str();
        }
    }

/**
 * add_top_op: Insert a completed operation into the top-100 slowest list.
 *
 * Once the list exceeds 100 entries, it is sorted descending by etime
 * and truncated to keep only the top 100.  This avoids storing all
 * completed operations in memory while still capturing the slowest ones.
 */
    /* struct TopOpRow {
       double etime;
       int conn;
       int op;
       std::string type;
       std::string who;
       std::string base;
       std::string filter;
       std::optional<int> nentries;
       std::optional<int> err;
       }; */
    void add_top_op(Aggregator& agg, const ::TopOpRow& row) {
        agg.top_ops.push_back(row);
        if (agg.top_ops.size() > 100) {
            std::sort(agg.top_ops.begin(), agg.top_ops.end(),
                    [](const ::TopOpRow& a, const ::TopOpRow& b) { return a.etime > b.etime; });
            agg.top_ops.resize(100);
        }
    }

/**
 * finalize_connection: Record final statistics for a connection when it
 * closes (CLOSED event).
 *
 * The function:
 *   1. Computes who (application identity) via app_for_conn().
 *   2. Computes total operations (completed + in-flight).
 *   3. Adds a TopConnRow to the top-100 list (sorted by total_etime).
 *   4. Updates maxconnetime if this connection had the highest total etime.
 */
    void finalize_connection(Aggregator& agg, int cid, const std::string& reason) {
        auto it = agg.conn_state.find(cid);
        if (it == agg.conn_state.end()) return;
        auto& conn = it->second;

        std::string who = app_for_conn(agg, cid);
        long long ops_cnt = conn.completed_ops + conn.ops.size();
        agg.top_conns.push_back({conn.total_etime, cid, who, conn.src, ops_cnt, conn.binddn, reason});
        if (agg.top_conns.size() > 100) {
            std::sort(agg.top_conns.begin(), agg.top_conns.end(),
                    [](const auto& a, const auto& b) { return a.total_etime > b.total_etime; });
            agg.top_conns.resize(100);
        }

        if (!agg.maxconnetime.has_value() || conn.total_etime > *agg.maxconnetime) {
            agg.maxconnetime = conn.total_etime;
            agg.maxconnetimeusr = who;
            std::ostringstream desc;
            desc << "conn=" << cid << " src=" << conn.src << " reason=" << reason;
            agg.maxconnopdesc = desc.str();
        }
    }

// =========================================================================
// parse_line — Parse a single log line into an Event structure
// =========================================================================
//
// This is the main parsing function.  It processes one line of text from
// an LDAP access log (slapd) and returns an Event with all recognised
// fields populated.  Unrecognised lines are marked as "UNKNOWN_LINE".
//
// The parsing proceeds through several stages:
//   1. Header matching     — strip the timestamp / host / proc prefix.
//   2. Connection/Op IDs   — extract conn=N and op=M identifiers.
//   3. Session tracking     — strip [IP=... NAME=...] session data.
//   4. Prefix dispatch      — use the first character to choose a regex set.
//
// The prefix-based dispatch is a performance optimisation: instead of
// trying every regex in sequence, we group patterns by the first character
// of the remainder string (after header/conn/op/session are stripped).
// This eliminates the vast majority of regex attempts on each line.

Event parse_line(const std::string& line) {
    Event ev;
    ev.raw = line;

    // ------------------------------------------------------------------
    // Stage 1 — Header Parsing
    // ------------------------------------------------------------------
    // Three header formats are supported:
    //   - OL26   : [2024-01-15T08:30:00] payload
    //   - RFC3339: 2024-01-15T08:30:00.123456Z LOGNAME slapd[123]: payload
    //   - SYSLOG : Jan 15 08:30:00 hostname slapd[123]: payload
    //
    // Each matcher populates ev.ts (timestamp) and optionally ev.host and
    // ev.proc (process info).  The remainder (payload) is stored in `rest`.
    //
    // If none match, the line is UNKNOWN_LINE.
    std::smatch m;
    std::string rest;

    if (std::regex_match(line, m, slaplog_rx::RE_HDR_OL26)) {
        ev.ts = m[1];
        rest = m[2];
    } else if (std::regex_match(line, m, slaplog_rx::RE_HDR_RFC3339)) {
        ev.ts = m[1];
        ev.host = m[2];
        ev.proc = m[3];
        rest = m[4];
    } else if (std::regex_match(line, m, slaplog_rx::RE_HDR_SYSLOG)) {
        ev.ts = m[1];
        ev.host = m[2];
        ev.proc = m[3];
        rest = m[4].str();
    } else {
        ev.kind = "UNKNOWN_LINE";
        return ev;
    }

    // ------------------------------------------------------------------
    // Stage 1b — Cleanup
    // ------------------------------------------------------------------
    // Strip trailing carriage-return characters (common in Windows/DOS
    // log files) and trim leading/trailing whitespace from the payload.
    // IMPORTANT: espaces/CR doivent etre enleves avant regex avec '^'.
    if (!rest.empty() && rest.back() == '\r')
        rest.pop_back();
    rest = trim(rest);

    // DEBUG: afficher un seul log
    /*
       static bool once = true;
       if (once) {
       once = false;
       std::cerr << "HDR MATCH RFC3339=" << std::regex_match(line, m, slaplog_rx::RE_HDR_RFC3339) << "\n";
       std::cerr << "m.size=" << m.size() << "\n";
       for (size_t i = 0; i < m.size(); ++i) std::cerr << "m["<<i<<"]="<<m[i].str()<<"\n";
       std::cerr << "line="<<line<<"\n";
       }
       */
    // Certains logs peuvent laisser des espaces en tete alors que nos
    // regex utilisent '^'.  Strip any remaining leading whitespace.
    size_t p = 0;
    while (p < rest.size() && std::isspace(static_cast<unsigned char>(rest[p]))) ++p;
    if (p) rest.erase(0, p);

    // ------------------------------------------------------------------
    // Stage 2 — Connection and Operation ID Extraction
    // ------------------------------------------------------------------
    // The standard "conn=N op=M" prefix is matched with RE_CONN_OP.
    // If it matches, both IDs and the remaining text are captured at once.
    // Otherwise, individual RE_CONN and RE_OP patterns are searched for
    // anywhere in the remainder (fallback for non-standard line formats).
    //
    // to_int() uses std::from_chars for efficient zero-allocation parsing.
    if (std::regex_match(rest, m, slaplog_rx::RE_CONN_OP)) {
        ev.conn = to_int(m[1]);
        ev.op = to_int(m[2]);
        rest = m[3].str();
    } else {
        if (std::regex_search(rest, m, slaplog_rx::RE_CONN)) ev.conn = to_int(m[1]);
        if (std::regex_search(rest, m, slaplog_rx::RE_OP)) ev.op = to_int(m[1]);
    }

    // ------------------------------------------------------------------
    // Stage 3 — Session Tracking Control Extraction
    // ------------------------------------------------------------------
    // The LDAP Session Tracking control (RFC 4370) adds a bracketed
    // prefix to log lines when enabled.  It carries:
    //   [IP=<client-ip> NAME=<session-name> USERNAME=<username>]
    //
    // We match either the full form (IP+NAME+USERNAME) or a partial form
    // (IP+NAME only) and populate the corresponding Event fields.
    if (!rest.empty() && rest[0] == '[') {
        std::smatch st_m;
        if (std::regex_match(rest, st_m, slaplog_rx::RE_SESSION_TRACK_FULL)) {
            ev.session_ip = st_m[1].str();
            ev.session_name = st_m[2].str();
            ev.session_username = st_m[3].str();
            rest = st_m[4].str();
        } else if (std::regex_match(rest, st_m, slaplog_rx::RE_SESSION_TRACK_PARTIAL)) {
            ev.session_ip = st_m[1].str();
            ev.session_name = st_m[2].str();
            rest = st_m[3].str();
        }
    }

    // ------------------------------------------------------------------
    // Stage 4 — FAST PREFIX-BASED DISPATCH
    // ------------------------------------------------------------------
    // Chaque groupe de patterns est route par le premier caractere,
    // evitant d'essayer 30+ regex par ligne.
    //
    // After stripping the header, conn/op IDs, and session tracking, we
    // inspect the first character of `rest` to determine which group of
    // patterns to attempt.  This first-character dispatch is a fast-path
    // optimisation that avoids iterating through all regexes for every line.
    char fc = rest.empty() ? '\0' : rest[0];

    // --- RESULT (the most frequent category, ~10% of lines) ---
    // Matches generic RESULT lines with tag, err, qtime, etime, and
    // optional text.  Three variants exist:
    //   - RE_RESULT_FULL     : includes trailing text=
    //   - RE_RESULT_NOTEXT   : no text= field
    //   - RE_RESULT_OID      : extended op result with oid= prefix
    if (fc == 'R' && rest.compare(0, 6, "RESULT") == 0) {
        if (std::regex_match(rest, m, slaplog_rx::RE_RESULT_FULL)) {
            ev.kind = "RESULT";
            ev.tag = to_int(m[1]); ev.err = to_int(m[2]);
            ev.qtime = to_double(m[3]); ev.etime = to_double(m[4]);
            ev.text = m[5].str();
            return ev;
        }
        if (std::regex_match(rest, m, slaplog_rx::RE_RESULT_NOTEXT)) {
            ev.kind = "RESULT";
            ev.tag = to_int(m[1]); ev.err = to_int(m[2]);
            ev.qtime = to_double(m[3]); ev.etime = to_double(m[4]);
            return ev;
        }
        if (std::regex_match(rest, m, slaplog_rx::RE_RESULT_OID)) {
            ev.kind = "RESULT";
            ev.oid = m[1].str();
            ev.err = to_int(m[2]); ev.qtime = to_double(m[3]); ev.etime = to_double(m[4]);
            ev.text = m[5].str();
            return ev;
        }
        ev.kind = "UNKNOWN_LINE";
        return ev;
    }

    // --- SEARCH RESULT / SRCH / SASL (first character 'S') ---
    // Three sub-groups:
    //   - SEARCH RESULT : result line for search ops (includes nentries).
    //   - SRCH          : search request (base, scope, deref, filter).
    //   - SRCH_ATTR     : attribute list for a search.
    //   - SASL          : SASL failure messages.
    if (fc == 'S') {
        if (rest.compare(0, 6, "SEARCH") == 0) {
            if (std::regex_match(rest, m, slaplog_rx::RE_SEARCH_RESULT_FULL)) {
                ev.kind = "SEARCH_RESULT";
                ev.tag = to_int(m[1]); ev.err = to_int(m[2]);
                ev.qtime = to_double(m[3]); ev.etime = to_double(m[4]);
                ev.nentries = to_int(m[5]); ev.text = m[6].str();
                return ev;
            }
            if (std::regex_match(rest, m, slaplog_rx::RE_SEARCH_RESULT_NOTEXT)) {
                ev.kind = "SEARCH_RESULT";
                ev.tag = to_int(m[1]); ev.err = to_int(m[2]);
                ev.qtime = to_double(m[3]); ev.etime = to_double(m[4]);
                ev.nentries = to_int(m[5]);
                return ev;
            }
            ev.kind = "UNKNOWN_LINE";
            return ev;
        }
        if (rest.compare(0, 4, "SRCH") == 0) {
            if (std::regex_match(rest, m, slaplog_rx::RE_SRCH)) {
                ev.kind = "SRCH";
                ev.base = m[1].str();
                ev.scope = to_int(m[2]); ev.deref = to_int(m[3]);
                ev.filter = m[4].str();
                return ev;
            }
            if (std::regex_match(rest, m, slaplog_rx::RE_SRCH_ATTR)) {
                ev.kind = "SRCH_ATTR";
                ev.attrs = m[1].str();
                return ev;
            }
            ev.kind = "UNKNOWN_LINE";
            return ev;
        }
        if (rest.compare(0, 4, "SASL") == 0) {
            if (std::regex_match(rest, m, slaplog_rx::RE_SASL_FAILURE)) {
                ev.kind = "SASL";
                ev.conn = to_int(m[1]);
                ev.raw = m[2].str();
                return ev;
            }
            ev.kind = "UNKNOWN_LINE";
            return ev;
        }
    }

    // --- BIND (first character 'B') ---
    // Captures authenticated binds (authcid/authzid), DN+method binds,
    // anonymous binds, DN+mechanism (SASL) binds, and bare DN binds.
    // The first match wins; lines that do not match any RE_BIND_*
    // pattern fall through to the misc section below.
    if (fc == 'B' && rest.compare(0, 4, "BIND") == 0) {
        if (std::regex_match(rest, m, slaplog_rx::RE_BIND_AUTH)) {
            ev.kind = "BIND_AUTH";
            ev.authcid = m[1].str(); ev.authzid = m[2].str();
            return ev;
        }
        if (std::regex_match(rest, m, slaplog_rx::RE_BIND_DN_METHOD)) {
            ev.kind = "BIND";
            ev.dn = m[1].str(); ev.method = to_int(m[2]);
            return ev;
        }
        if (std::regex_match(rest, m, slaplog_rx::RE_BIND_ANON)) {
            ev.kind = "BIND_ANON";
            ev.method = to_int(m[1]);
            return ev;
        }
        if (std::regex_match(rest, m, slaplog_rx::RE_BIND_DN_MECH)) {
            ev.kind = "BIND_DN_INFO";
            ev.dn = m[1].str(); ev.mech = m[2].str();
            return ev;
        }
        if (std::regex_match(rest, m, slaplog_rx::RE_BIND_DN)) {
            ev.kind = "BIND_DN_INFO";
            ev.dn = m[1].str();
            return ev;
        }
        // fall through to misc section for extended BIND patterns
    }

    // --- UNBIND (first character 'U') ---
    // Two forms: with a msgid= parameter, or just the bare "UNBIND" token.
    if (fc == 'U' && rest.compare(0, 6, "UNBIND") == 0) {
        if (std::regex_match(rest, m, slaplog_rx::RE_UNBIND)) {
            ev.kind = "UNBIND";
            ev.msgid = to_int(m[1]);
            return ev;
        }
        if (std::regex_match(rest, m, slaplog_rx::RE_UNBIND_SIMPLE)) {
            ev.kind = "UNBIND";
            return ev;
        }
        ev.kind = "UNKNOWN_LINE";
        return ev;
    }

    // --- Connection Events: conn= (ACCEPT, CLOSED, TLS) + connection_input ---
    // Lines starting with "conn=" cover connection lifecycle: ACCEPT (from
    // PATH or IP), CLOSED (with optional reason), and TLS established events.
    // Lines starting with "connection_input:" cover deferred operations.
    //
    // For ACCEPT, the source address is stored in ev.src with a "IP=" or
    // "PATH=" prefix so that downstream code can distinguish the two types.
    if (fc == 'c') {
        if (rest.compare(0, 17, "connection_input:") == 0) {
            if (std::regex_match(rest, m, slaplog_rx::RE_CONN_DEFER)) {
                ev.kind = "CONN_DEFER";
                ev.conn = to_int(m[1]);
                ev.text = m[2].str();
                return ev;
            }
        } else if (rest.compare(0, 5, "conn=") == 0) {
            if (std::regex_match(rest, m, slaplog_rx::RE_ACCEPT_PATH)) {
                ev.kind = "ACCEPT";
                ev.conn = to_int(m[1]); ev.fd = to_int(m[2]);
                ev.src = "PATH=" + m[3].str();
                return ev;
            }
            if (std::regex_match(rest, m, slaplog_rx::RE_ACCEPT_IP)) {
                ev.kind = "ACCEPT";
                ev.conn = to_int(m[1]); ev.fd = to_int(m[2]);
                ev.src = "IP=" + m[3].str();
                return ev;
            }
            if (std::regex_match(rest, m, slaplog_rx::RE_CLOSED)) {
                ev.kind = "CLOSED";
                ev.conn = to_int(m[1]); ev.fd = to_int(m[2]);
                ev.reason = m[3].str();
                return ev;
            }
            if (std::regex_match(rest, m, slaplog_rx::RE_TLS)) {
                ev.kind = "TLS";
                ev.conn = to_int(m[1]); ev.fd = to_int(m[2]);
                return ev;
            }
        }
        // fall through to misc section for critical/other 'c' lines
    }

    // --- EXT (first character 'E') ---
    // Extended operations: "EXT oid=1.3.6.1.4.1.1466.20037"
    if (fc == 'E' && rest.compare(0, 3, "EXT") == 0) {
        if (std::regex_match(rest, m, slaplog_rx::RE_EXT)) {
            ev.kind = "EXT";
            ev.oid = m[1].str();
            return ev;
        }
        ev.kind = "UNKNOWN_LINE";
        return ev;
    }

    // --- ADD / ABANDON (first character 'A') ---
    // ADD:    "ADD dn=cn=newuser,dc=example,dc=com"
    // ABANDON: "ABANDON msgid=12345" or "ABANDON msg=12345"
    if (fc == 'A') {
        if (rest.compare(0, 3, "ADD") == 0) {
            if (std::regex_match(rest, m, slaplog_rx::RE_ADD)) {
                ev.kind = "ADD";
                ev.dn = m[1].str();
                return ev;
            }
            ev.kind = "UNKNOWN_LINE";
            return ev;
        }
        if (rest.compare(0, 7, "ABANDON") == 0) {
            if (std::regex_match(rest, m, slaplog_rx::RE_ABANDON)) {
                ev.kind = "ABANDON";
                ev.msgid = to_int(m[1]);
                return ev;
            }
            ev.kind = "UNKNOWN_LINE";
            return ev;
        }
    }

    // --- MOD / MODRDN (first character 'M') ---
    // MODRDN: "MODRDN dn=cn=user,dc=example,dc=com"
    // MOD:    "MOD dn=cn=user,dc=example,dc=com" or "MOD attr=userPassword"
    if (fc == 'M') {
        if (rest.compare(0, 5, "MODRDN") == 0) {
            if (std::regex_match(rest, m, slaplog_rx::RE_MODRDN)) {
                ev.kind = "MODRDN";
                ev.dn = m[1].str();
                return ev;
            }
            ev.kind = "UNKNOWN_LINE";
            return ev;
        }
        if (rest.compare(0, 3, "MOD") == 0) {
            if (std::regex_match(rest, m, slaplog_rx::RE_MOD)) {
                ev.kind = "MOD";
                ev.dn = m[1].str();
                return ev;
            }
            if (std::regex_match(rest, m, slaplog_rx::RE_MOD_ATTR_EQ)) {
                ev.kind = "MOD";
                ev.attrs = m[1].str();
                return ev;
            }
            ev.kind = "UNKNOWN_LINE";
            return ev;
        }
    }

    // --- DEL (first character 'D') ---
    // "DEL dn=cn=olduser,dc=example,dc=com"
    if (fc == 'D' && rest.compare(0, 3, "DEL") == 0) {
        if (std::regex_match(rest, m, slaplog_rx::RE_DEL)) {
            ev.kind = "DEL";
            ev.dn = m[1].str();
            return ev;
        }
        ev.kind = "UNKNOWN_LINE";
        return ev;
    }

    // --- CMP (first character 'C') ---
    // "CMP dn=cn=user,dc=example,dc=com"
    if (fc == 'C' && rest.compare(0, 3, "CMP") == 0) {
        if (std::regex_match(rest, m, slaplog_rx::RE_CMP)) {
            ev.kind = "CMP";
            ev.dn = m[1].str();
            return ev;
        }
        ev.kind = "UNKNOWN_LINE";
        return ev;
    }

    // --- slap_* (CSN, GLOBAL_CONTROL) / syncprov (first character 's') ---
    // These are slapd-internal messages related to replication and controls:
    //   - slap_get_csn:          CSN generation (conn/op/manage).
    //   - slap_queue_csn:        CSN being queued.
    //   - slap_graduate_commit_csn: CSN being removed from queue.
    //   - slap_global_control:   Unrecognised global control (OID).
    //   - syncprov:              Syncrepl provider messages.
    if (fc == 's') {
        if (rest.rfind("slap_get_csn:", 0) == 0) {
            if (std::regex_match(rest, m, slaplog_rx::RE_CSN_GET)) {
                ev.kind = "CSN_GET";
                ev.conn = to_int(m[1]); ev.op = to_int(m[2]);
                ev.csn = m[3].str(); ev.manage = to_int(m[4]);
                return ev;
            }
            ev.kind = "UNKNOWN_LINE";
            return ev;
        }
        if (rest.rfind("slap_queue_csn:", 0) == 0) {
            if (std::regex_match(rest, m, slaplog_rx::RE_CSN_QUEUE)) {
                ev.kind = "CSN_QUEUE";
                ev.csn = m[1].str();
                return ev;
            }
            ev.kind = "UNKNOWN_LINE";
            return ev;
        }
        if (rest.rfind("slap_graduate_commit_csn:", 0) == 0) {
            if (std::regex_match(rest, m, slaplog_rx::RE_CSN_GRADUATE)) {
                ev.kind = "CSN_GRADUATE";
                ev.csn = m[1].str();
                return ev;
            }
            ev.kind = "UNKNOWN_LINE";
            return ev;
        }
        if (rest.rfind("slap_global_control:", 0) == 0) {
            ev.kind = "GLOBAL_CONTROL";
            std::smatch x;
            if (std::regex_search(rest, x, slaplog_rx::RE_GLOBAL_CONTROL)) {
                ev.oid = x[1].str();
            }
            return ev;
        }
        if (rest.rfind("syncprov", 0) == 0) {
            ev.kind = "SYNCPROV";
            return ev;
        }
    }

    // --- TRACK (first character 'T') ---
    // Session tracking control data logged as key=value pairs, comma
    // separated: "TRACK IP=..., NAME=..., USERNAME=..."
    // The pairs are parsed into the ev.track map for later consumption
    // by update_aggregator().
    if (fc == 'T' && rest.compare(0, 5, "TRACK") == 0) {
        if (std::regex_match(rest, m, slaplog_rx::RE_TRACK)) {
            ev.kind = "TRACK";
            std::string track_data = m[1].str();
            std::istringstream iss(track_data);
            std::string pair;
            while (std::getline(iss, pair, ',')) {
                size_t eq = pair.find('=');
                if (eq != std::string::npos) {
                    std::string key = trim(pair.substr(0, eq));
                    std::string value = trim(pair.substr(eq + 1));
                    if (!key.empty()) ev.track[key] = value;
                }
            }
            return ev;
        }
        ev.kind = "UNKNOWN_LINE";
        return ev;
    }

    // --- NOT INDEXED (may be embedded within other line types) ---
    // Look for "mdb_*:" or "bdb_*:" patterns in the remainder that
    // indicate an unindexed search.  These are emitted by slapd's
    // backends when a filter term cannot use an index.
    if (rest.find("mdb_") != std::string::npos || rest.find("bdb_") != std::string::npos) {
        std::smatch x;
        if (std::regex_search(rest, x, slaplog_rx::RE_NOT_INDEXED)) {
            ev.kind = "NOT_INDEXED";
            ev.attrs = x[1].str();
            return ev;
        }
    }

    // ------------------------------------------------------------------
    // Stage 5 — Misc Patterns (fallback for lines not caught above)
    // ------------------------------------------------------------------
    // These patterns handle various slapd messages that do not follow the
    // standard LDAP operation format but carry useful diagnostic data:
    //
    //   CONTROL_NOT_SUPPORTED  — critical/non-critical unsupported controls.
    //   BIND_ANON_MECH_EXT     — anonymous BIND with extended mech info.
    //   STARTTLS               — bare STARTTLS operation.
    //   DO_BIND_INVALID        — invalid DN in do_bind.
    //   LDAP_BACK_DOBIND_INT   — rebind failure without credentials.
    //   LDAP_BACK_RETRY        — retry of a backend connection.
    //   SLAPD_STARTING/STOPPED/SHUTDOWN, DAEMON_SHUTDOWN — server lifecycle.

    // critical/non-critical control (after conn/op parsed by RE_CONN_OP)
    if (std::regex_match(rest, m, slaplog_rx::RE_CONTROL_NOT_SUPPORTED)) {
        ev.kind = "CONTROL_NOT_SUPPORTED";
        ev.text = m[1].str() + std::string(" control \"") + m[2].str() + "\"";
        return ev;
    }
    // BIND anonymous with extended mech info
    if (std::regex_match(rest, m, slaplog_rx::RE_BIND_ANON_MECH_EXT)) {
        ev.kind = "BIND_ANON";
        ev.method = 0;
        return ev;
    }
    // STARTTLS operation
    if (std::regex_match(rest, m, slaplog_rx::RE_STARTTLS)) {
        ev.kind = "STARTTLS";
        return ev;
    }
    // do_bind: invalid dn
    if (std::regex_match(rest, m, slaplog_rx::RE_DO_BIND_INVALID)) {
        ev.kind = "DO_BIND_INVALID";
        ev.dn = m[1].str();
        return ev;
    }
    // ldap_back_dobind_int
    if (std::regex_match(rest, m, slaplog_rx::RE_LDAP_BACK_DOBIND_INT)) {
        ev.kind = "LDAP_BACK_DOBIND_INT";
        ev.dn = m[1].str();
        return ev;
    }
    // ldap_back_retry
    if (std::regex_match(rest, m, slaplog_rx::RE_LDAP_BACK_RETRY)) {
        ev.kind = "LDAP_BACK_RETRY";
        ev.text = m[1].str();
        ev.dn = m[2].str();
        return ev;
    }
    // slapd server events
    if (std::regex_match(rest, m, slaplog_rx::RE_SLAPD_STARTING)) {
        ev.kind = "SLAPD_STARTING";
        return ev;
    }
    if (std::regex_match(rest, m, slaplog_rx::RE_SLAPD_STOPPED)) {
        ev.kind = "SLAPD_STOPPED";
        return ev;
    }
    if (std::regex_match(rest, m, slaplog_rx::RE_SLAPD_SHUTDOWN)) {
        ev.kind = "SLAPD_SHUTDOWN";
        ev.text = m[1].str();
        return ev;
    }
    // daemon: shutdown
    if (std::regex_match(rest, m, slaplog_rx::RE_DAEMON_SHUTDOWN)) {
        ev.kind = "DAEMON_SHUTDOWN";
        return ev;
    }

    // ------------------------------------------------------------------
    // Stage 6 — Fallback: Unrecognised Line
    // ------------------------------------------------------------------
    // If none of the above patterns matched, classify the line as unknown
    // but preserve the remainder text in ev.rest for diagnostic purposes.
    ev.kind = "UNKNOWN_LINE";
    ev.rest = rest;
    return ev;
}

// =========================================================================
// update_aggregator — Fold one parsed Event into the running Aggregator
// =========================================================================
//
// This function is the second stage of the pipeline.  It takes a fully
// parsed Event (produced by parse_line()) and merges its data into the
// Aggregator, updating counters, per-connection state, per-operation
// state, timing statistics, top-N lists, and error breakdowns.
//
// The function is structured as a series of `if` branches on ev.kind.
// The order matters:
//   1. Unknown lines are counted and returned early.
//   2. Time bounds are updated for every line with a timestamp.
//   3. Connection-level events (ACCEPT, CLOSED, TLS) are handled first.
//   4. Connection-less events (TRACK, GLOBAL_CONTROL, SYNCPROV, CSN,
//      NOT_INDEXED, misc patterns) are handled next.
//   5. A guard checks that cid/opid are valid; if not, the line is unknown.
//   6. Operation-level events update per-op state and may finalise it.
//   7. Server events (start/stop/shutdown) are recorded last.

void update_aggregator(Aggregator& agg, const Event& ev,
                       std::ostream* unknown_out, std::mutex* unknown_mtx) {

    // ------------------------------------------------------------------
    // Unknown Line Handling
    // ------------------------------------------------------------------
    // Lines that parse_line() could not classify increment the unknown
    // counter and are stored raw in unknown_lines for later inspection.
    if (ev.kind == "UNKNOWN_LINE" || ev.kind == "UNKNOWN_OP") {
        agg.stats.unknown_lines++;
        agg.stats.lines++;
        if (unknown_out) {
            std::lock_guard<std::mutex> lock(*unknown_mtx);
            *unknown_out << ev.raw << '\n';
        } else if (agg.unknown_lines.size() < MAX_STORED_UNKNOWN_LINES) {
            agg.unknown_lines.push_back(ev.raw);
        }
        return;
    }

    // ------------------------------------------------------------------
    // Time Bounds
    // ------------------------------------------------------------------
    // Every line with a valid timestamp expands the overall time range
    // (agg.firsttime / agg.lasttime) tracked by the Aggregator.
    if (!ev.ts.empty()) update_time_bounds(agg, ev.ts);
    agg.stats.lines++;

    int cid = ev.conn.value_or(-1);
    int opid = ev.op.value_or(-1);

    // ==================================================================
    // Connection-Level Events
    // ==================================================================

    // --- ACCEPT (new client connection) ---
    // Increments the open-fd counter and active-connection count.
    // Stores the source address (IP:port or PATH=...) in conn_state
    // and in the src_by_conn lookup map.  Also updates the session
    // correlation entry's accept_ip if one exists.
    if (ev.kind == "ACCEPT") {
        agg.stats.fd_open++;
        agg.stats.conn_count++;
        agg.active_connections++;
        if (agg.active_connections > agg.peak_active_connections) {
            agg.peak_active_connections = agg.active_connections;
        }
        if (cid >= 0) {
            auto& conn = ensure_conn(agg, cid);
            conn.fd = ev.fd;
            conn.src = ev.src;
            agg.src_by_conn[cid] = ev.src;
            // Update session correlation accept_ip
            std::pair<int,int> sc_key{agg.restart_count, cid};
            auto scit = agg.session_correlations.find(sc_key);
            if (scit != agg.session_correlations.end() && scit->second.accept_ip.empty()) {
                scit->second.accept_ip = ev.src;
            }
        }
        return;
    }

    // --- CLOSED (connection terminated) ---
    // Decrements active connections and finalises the connection's
    // statistics (total runtime, top-N list).  The reason string
    // (e.g. "connection lost") is passed through to finalize_connection().
    if (ev.kind == "CLOSED") {
        agg.stats.fd_close++;
        if (agg.active_connections > 0) agg.active_connections--;
        if (cid >= 0) finalize_connection(agg, cid, ev.reason);
        return;
    }

    // --- TLS (TLS established on connection) ---
    if (ev.kind == "TLS") {
        agg.operation_count["TLS"]++;
        return;
    }

    // ==================================================================
    // Connection-Less Events (no per-op state required)
    // ==================================================================

    // --- TRACK (session tracking data) ---
    // Stores the key-value pairs from the session tracking control into
    // the connection state.  If USERNAME or NAME are present, they
    // override the "app" (application name) for this connection.
    if (ev.kind == "TRACK") {
        if (cid >= 0) {
            auto& conn = ensure_conn(agg, cid);
            conn.track = ev.track;
            if (conn.track.count("USERNAME") && !conn.track["USERNAME"].empty()) {
                conn.app = conn.track["USERNAME"];
            } else if (conn.track.count("NAME") && !conn.track["NAME"].empty()) {
                conn.app = conn.track["NAME"];
            }
        }
        return;
    }

    // --- GLOBAL_CONTROL (unrecognised control OID) ---
    if (ev.kind == "GLOBAL_CONTROL") {
        agg.operation_count["GLOBAL_CONTROL"]++;
        agg.global_control_oid_count[ev.oid]++;
        return;
    }

    // --- SYNCPROV (syncrepl provider message) ---
    if (ev.kind == "SYNCPROV") {
        agg.operation_count["SYNCPROV"]++;
        agg.stats.replication_logs++;
        return;
    }

    // --- CSN Events (replication sequence numbers) ---
    if (ev.kind == "CSN_GET") {
        agg.operation_count["CSN_GET"]++;
        agg.csn_event_count.get++;
        return;
    }

    if (ev.kind == "CSN_QUEUE") {
        agg.operation_count["CSN_QUEUE"]++;
        agg.csn_event_count.queue++;
        return;
    }

    if (ev.kind == "CSN_GRADUATE") {
        agg.operation_count["CSN_GRADUATE"]++;
        agg.csn_event_count.graduate++;
        return;
    }

    // --- NOT_INDEXED (unindexed search terms) ---
    if (ev.kind == "NOT_INDEXED") {
        agg.operation_count["NOT_INDEXED"]++;
        agg.not_indexed_count++;
        if (!ev.attrs.empty()) agg.not_indexed_attr[ev.attrs]++;
        return;
    }

    // ------------------------------------------------------------------
    // Misc Integrated Patterns (no cid/opid required, checked before guard)
    // ------------------------------------------------------------------
    // These are diagnostic messages that do not belong to a specific
    // connection+operation pair, so we handle them before the guard below.
    if (ev.kind == "CONTROL_NOT_SUPPORTED") {
        agg.control_not_supported_count++;
        return;
    }
    if (ev.kind == "STARTTLS") {
        agg.operation_count["STARTTLS"]++;
        return;
    }
    if (ev.kind == "DO_BIND_INVALID") {
        agg.invalid_dn_count++;
        return;
    }
    if (ev.kind == "LDAP_BACK_DOBIND_INT") {
        agg.rebind_failed_count++;
        return;
    }
    if (ev.kind == "LDAP_BACK_RETRY") {
        agg.retry_count++;
        return;
    }
    if (ev.kind == "CONN_DEFER") {
        agg.defer_count++;
        return;
    }
    if (ev.kind == "DAEMON_SHUTDOWN") {
        agg.server_events.daemon_shutdown_count++;
        agg.server_event_list.emplace_back(ev.ts, "daemon shutdown requested");
        return;
    }
    if (ev.kind == "SLAPD_SHUTDOWN") {
        agg.server_events.shutdown_count++;
        agg.server_event_list.emplace_back(ev.ts, "slapd shutdown (waiting for " + ev.text + " ops)");
        return;
    }
    if (ev.kind == "SLAPD_STARTING") {
        agg.server_events.start_count++;
        agg.restart_count++;
        agg.server_event_list.emplace_back(ev.ts, "slapd starting");
        return;
    }
    if (ev.kind == "SLAPD_STOPPED") {
        agg.server_events.stop_count++;
        agg.server_event_list.emplace_back(ev.ts, "slapd stopped");
        return;
    }

    // ==================================================================
    // Guard: cid and opid must both be present for operation processing
    // ==================================================================
    // If we reach this point, the event kind is one that requires a valid
    // connection and operation ID.  Without them, the line is unusable.
    if (cid < 0 || opid < 0) {
        agg.stats.unknown_lines++;
        agg.stats.lines++;
        if (unknown_out) {
            std::lock_guard<std::mutex> lock(*unknown_mtx);
            *unknown_out << ev.raw << '\n';
        } else if (agg.unknown_lines.size() < MAX_STORED_UNKNOWN_LINES) {
            agg.unknown_lines.push_back(ev.raw);
        }
        return;
    }

    auto& conn = ensure_conn(agg, cid);
    auto& op = ensure_op(agg, cid, opid);
    std::string who = app_for_conn(agg, cid);

    // ------------------------------------------------------------------
    // Session Tracking Save
    // ------------------------------------------------------------------
    // If the event carries session tracking data (IP, NAME, USERNAME),
    // persist it in the connection state and create/update a session
    // correlation entry.  The correlation entry is keyed by (restart_count,
    // conn) so that sessions survive server restarts without confusing
    // stale conn state.
    //
    // NOTE: conn state may be stale across restarts (same cid from a
    // different epoch), so binddn is always read from the event itself,
    // not from conn state.
    if (!ev.session_ip.empty() || !ev.session_name.empty() || !ev.session_username.empty()) {
        if (!ev.session_ip.empty()) conn.session_ip = ev.session_ip;
        if (!ev.session_name.empty()) conn.session_name = ev.session_name;
        if (!ev.session_username.empty()) conn.session_username = ev.session_username;

        // Create/update correlation entry — keyed by (restart_epoch, cid)
        std::pair<int,int> sc_key{agg.restart_count, cid};
        auto& entry = agg.session_correlations[sc_key];
        entry.restart = agg.restart_count;
        entry.conn = cid;
        if (entry.ts.empty()) entry.ts = ev.ts;
        entry.real_ip = conn.session_ip;
        entry.name = conn.session_name;
        entry.username = conn.session_username;
        auto src_it = agg.src_by_conn.find(cid);
        if (src_it != agg.src_by_conn.end()) entry.accept_ip = src_it->second;
    }

    // ==================================================================
    // Operation Handlers
    // ==================================================================
    // Each event kind maps to a handler that:
    //   1. Increments the appropriate operation counter.
    //   2. Marks as read or write for the read/write breakdown.
    //   3. Calls ensure_total_counted() to register the operation.
    //   4. Populates the OpState with relevant fields.
    //   5. For result events (RESULT, SEARCH_RESULT), finalises the op
    //      by recording timing, updating aggregator totals, and calling
    //      add_top_op() and conn.ops.erase().

    // --- BIND_AUTH (authenticated bind with authcid/authzid) ---
    // Records authentication and authorisation identities.  Updates both
    // the connection's authcid and binddn, and propagates the information
    // to the session correlation entry.
    if (ev.kind == "BIND_AUTH") {
        agg.operation_count["BIND"]++;
        agg.read_write_stats.read++;
        ensure_total_counted(agg, cid, opid);
        op.type = "BIND";
        op.authcid = ev.authcid;
        op.authzid = ev.authzid;
        if (!ev.authzid.empty() && op.binddn.empty()) op.binddn = ev.authzid;
        op.who = app_for_conn(agg, cid);
        if (!ev.authcid.empty()) conn.authcid = ev.authcid;
        if (!ev.authzid.empty()) { conn.binddn = ev.authzid; agg.binddn_by_conn[cid] = ev.authzid; }
        if (conn.app.empty() || conn.app == "unknown") conn.app = ev.authzid.empty() ? ev.authcid : ev.authzid;
        // Update session correlation binddn
        std::pair<int,int> sc_key{agg.restart_count, cid};
        auto scit = agg.session_correlations.find(sc_key);
        if (scit != agg.session_correlations.end() && scit->second.binddn.empty()) {
            scit->second.binddn = conn.binddn;
        }
        return;
    }

    // --- BIND_DN_INFO (bind with DN and optional mechanism) ---
    // Handles DN+method, DN+mech, and bare-DN bind lines.  Updates the
    // connection's binddn and app_name if not already set.
    if (ev.kind == "BIND_DN_INFO") {
        std::string dn = dequote(ev.dn);
        if (op.type.empty()) op.type = "BIND";
        if (op.dn.empty()) op.dn = dn;
        if (op.binddn.empty()) op.binddn = dn;
        if (op.who.empty()) op.who = app_for_conn(agg, cid);
        if (!dn.empty()) {
            conn.binddn = dn;
            agg.binddn_by_conn[cid] = dn;
            if (conn.app.empty() || conn.app == "unknown") conn.app = dn;
            // Update session correlation binddn
            std::pair<int,int> sc_key{agg.restart_count, cid};
            auto scit = agg.session_correlations.find(sc_key);
            if (scit != agg.session_correlations.end() && scit->second.binddn.empty()) {
                scit->second.binddn = dn;
            }
        }
        return;
    }

    // --- BIND_ANON (anonymous bind) ---
    // Counted separately as "BIND ANONYMOUS" for reporting purposes.
    if (ev.kind == "BIND_ANON") {
        agg.operation_count["BIND ANONYMOUS"]++;
        agg.read_write_stats.read++;
        ensure_total_counted(agg, cid, opid);
        op.type = "BIND";
        op.method = ev.method;
        op.who = app_for_conn(agg, cid);
        return;
    }

    // --- BIND (generic bind with optional DN, method, authcid, authzid) ---
    // A catch-all handler for bind lines that did not match the more
    // specific BIND_AUTH or BIND_DN_INFO patterns.  Sets binddn on the
    // connection and updates the session correlation.
    if (ev.kind == "BIND") {
        agg.operation_count["BIND"]++;
        agg.read_write_stats.read++;
        ensure_total_counted(agg, cid, opid);
        op.type = "BIND";
        op.who = who;
        std::string binddn = ev.binddn.empty() ? dequote(ev.dn) : ev.binddn;
        if (!binddn.empty()) {
            op.binddn = binddn;
            conn.binddn = binddn;
            agg.binddn_by_conn[cid] = binddn;
            if (conn.app.empty() || conn.app == "unknown") conn.app = binddn;
            // Update session correlation binddn
            std::pair<int,int> sc_key{agg.restart_count, cid};
            auto scit = agg.session_correlations.find(sc_key);
            if (scit != agg.session_correlations.end() && scit->second.binddn.empty()) {
                scit->second.binddn = binddn;
            }
        }
        if (!ev.authcid.empty()) {
            op.authcid = ev.authcid;
            conn.authcid = ev.authcid;
        }
        if (!ev.authzid.empty()) op.authzid = ev.authzid;
        if (ev.method.has_value()) op.method = ev.method;
        if (!ev.dn.empty()) op.dn = ev.dn;
        return;
    }

    // --- SRCH (search request) ---
    // Records the search base, scope, deref, and filter.  Both base and
    // filter are normalised (via normalize_filter) before being used as
    // aggregation keys.  Wildcard filters and unindexed "(?attr)" patterns
    // are tracked separately.
    if (ev.kind == "SRCH") {
        agg.operation_count["SRCH"]++;
        agg.read_write_stats.read++;
        ensure_total_counted(agg, cid, opid);
        op.type = "SRCH";
        op.who = who;
        op.base = ev.base.empty() ? "" : normalize_filter(ev.base);
        op.filter = ev.filter.empty() ? "" : normalize_filter(ev.filter);
        if (!op.base.empty()) agg.base_count[op.base]++;
        if (!op.filter.empty()) {
            agg.filter_count[op.filter]++;
            if (op.filter.find('*') != std::string::npos) agg.wildcard_filter_count[op.filter]++;
            track_qmark_filter(agg, ev.filter);
        }
        return;
    }

    // --- SRCH_ATTR (search requested attributes) ---
    // Records the requested attribute list.  Each attribute is lowercased
    // and counted individually in attr_count.  If the operation also has
    // a filter, a combined key of "filter || attrs" is created for the
    // norm_filter_attrs_count breakdown.
    if (ev.kind == "SRCH_ATTR") {
        agg.operation_count["SRCH ATTR"]++;
        if (!ev.attrs.empty()) {
            op.attrs = ev.attrs;
            std::istringstream iss(ev.attrs);
            std::string a;
            while (iss >> a) {
                std::string lower_a = a;
                std::transform(lower_a.begin(), lower_a.end(), lower_a.begin(), ::tolower);
                agg.attr_count[lower_a]++;
            }
            if (!op.filter.empty()) {
                std::string na = normalize_attrs(ev.attrs);
                std::string key = op.filter + " || " + na;
                if (!op.filter.empty() || !na.empty()) agg.norm_filter_attrs_count[key]++;
            }
        }
        return;
    }

    // --- SEARCH_RESULT (completion of a search operation) ---
    // This is the most data-rich handler.  It:
    //   1. Stores err, etime, qtime, nentries, tag, text on the OpState.
    //   2. Updates global timing accumulators (etime_total, qtime_total).
    //   3. Tracks per-connection total etime.
    //   4. Updates maxetime if this is the slowest op seen so far.
    //   5. Accumulates per-base and per-filter timing breakdowns.
    //   6. Tracks nentries==1 and nentries==0 counts per filter.
    //   7. Updates per-app operation count and timing.
    //   8. Adds the operation to the top-100 list.
    //   9. Removes the OpState from the connection's in-flight ops map.
    if (ev.kind == "SEARCH_RESULT") {
        agg.operation_count["SEARCH RESULT"]++;
        if (ev.err.has_value()) {
            op.err = ev.err;
            agg.error_count[*ev.err]++;
            agg.error_per_app[who][*ev.err]++;
        }
        if (ev.etime.has_value()) {
            op.etime = ev.etime;
            agg.etime_total += *ev.etime;
            conn.total_etime += *ev.etime;
            if (!agg.maxetime.has_value() || *ev.etime > *agg.maxetime) {
                agg.maxetime = ev.etime;
                agg.maxetimeusr = who;
                std::ostringstream desc;
                desc << "conn=" << cid << " op=" << opid << " type=" << op.type
                    << " base=" << op.base << " filter=" << op.filter
                    << " err=" << (op.err.has_value() ? std::to_string(*op.err) : "");
                agg.maxopdesc = desc.str();
            }
        }
        if (ev.qtime.has_value()) {
            op.qtime = ev.qtime;
            agg.qtime_total += *ev.qtime;
        }
        if (ev.nentries.has_value()) op.nentries = ev.nentries;
        if (ev.tag.has_value()) op.tag = ev.tag;
        if (!ev.text.empty()) op.text = ev.text;

        double etime = ev.etime.value_or(0.0);

        if (!op.base.empty()) agg.base_etime_total[op.base] += etime;

        if (!op.filter.empty()) {
            agg.filter_etime_total[op.filter] += etime;
            if (op.nentries.has_value()) {
                if (*op.nentries == 1) agg.norm_filter_n1_count[op.filter]++;
                if (*op.nentries == 0) agg.norm_filter_n0_count[op.filter]++;
            }
            if (!who.empty()) agg.filter_by_app[who][op.filter]++;
        }

        if (!who.empty()) {
            agg.app_count[who]++;
            agg.app_etime_total[who] += etime;
        }

        add_top_op(agg, TopOpRow{etime, cid, opid, op.type, who, op.base, op.filter, op.nentries, op.err});
        conn.completed_ops++;
        conn.ops.erase(opid);
        return;
    }

    // --- RESULT (completion of a non-search operation) ---
    // Structurally identical to SEARCH_RESULT but with a twist: it checks
    // op.type to determine whether this result belongs to a search (for
    // per-base and per-filter accounting).  Non-search results do not
    // contribute to base/filter breakdowns, but they still update timing,
    // error counts, and the top-ops list.
    if (ev.kind == "RESULT") {
        agg.operation_count["RESULT"]++;
        if (ev.err.has_value()) {
            op.err = ev.err;
            agg.error_count[*ev.err]++;
            agg.error_per_app[who][*ev.err]++;
        }
        if (ev.etime.has_value()) {
            op.etime = ev.etime;
            agg.etime_total += *ev.etime;
            conn.total_etime += *ev.etime;
            if (!agg.maxetime.has_value() || *ev.etime > *agg.maxetime) {
                agg.maxetime = ev.etime;
                agg.maxetimeusr = who;
                std::ostringstream desc;
                desc << "conn=" << cid << " op=" << opid << " type=" << op.type
                    << " base=" << op.base << " filter=" << op.filter
                    << " err=" << (op.err.has_value() ? std::to_string(*op.err) : "");
                agg.maxopdesc = desc.str();
            }
        }
        if (ev.qtime.has_value()) {
            op.qtime = ev.qtime;
            agg.qtime_total += *ev.qtime;
        }
        if (ev.nentries.has_value()) op.nentries = ev.nentries;
        if (ev.tag.has_value()) op.tag = ev.tag;
        if (!ev.text.empty()) op.text = ev.text;

        double etime = ev.etime.value_or(0.0);
        bool is_search = (op.type == "SRCH");

        if (is_search && !op.base.empty()) {
            agg.base_etime_total[op.base] += etime;
        }

        if (is_search && !op.filter.empty()) {
            agg.filter_etime_total[op.filter] += etime;
            if (op.nentries.has_value()) {
                if (*op.nentries == 1) agg.norm_filter_n1_count[op.filter]++;
                if (*op.nentries == 0) agg.norm_filter_n0_count[op.filter]++;
            }
            if (!who.empty()) agg.filter_by_app[who][op.filter]++;
        }

        if (!who.empty()) {
            agg.app_count[who]++;
            agg.app_etime_total[who] += etime;
        }

        add_top_op(agg, TopOpRow{etime, cid, opid, op.type, who, op.base, op.filter, op.nentries, op.err});
        conn.completed_ops++;
        conn.ops.erase(opid);
        return;
    }

    // --- EXT (extended operation) ---
    // Records the OID of the extended request.  OIDs are counted both in
    // operation_count["EXT"] and in ext_oid_count for per-OID breakdowns.
    if (ev.kind == "EXT") {
        agg.operation_count["EXT"]++;
        agg.read_write_stats.read++;
        ensure_total_counted(agg, cid, opid);
        op.type = "EXT";
        op.who = who;
        if (!ev.oid.empty()) {
            op.oid = ev.oid;
            agg.ext_oid_count[ev.oid]++;
        }
        return;
    }

    // --- ADD (add entry operation) ---
    if (ev.kind == "ADD") {
        agg.operation_count["ADD"]++;
        agg.read_write_stats.write++;
        ensure_total_counted(agg, cid, opid);
        op.type = "ADD";
        op.who = who;
        if (!ev.dn.empty()) op.dn = ev.dn;
        return;
    }

    // --- DEL (delete entry operation) ---
    if (ev.kind == "DEL") {
        agg.operation_count["DEL"]++;
        agg.read_write_stats.write++;
        ensure_total_counted(agg, cid, opid);
        op.type = "DEL";
        op.who = who;
        if (!ev.dn.empty()) op.dn = ev.dn;
        return;
    }

    // --- MOD (modify entry operation) ---
    // In addition to storing the DN, this handler also records the
    // modified attributes (from ev.attrs) in the overall attr_count map.
    if (ev.kind == "MOD") {
        agg.operation_count["MOD"]++;
        agg.read_write_stats.write++;
        ensure_total_counted(agg, cid, opid);
        op.type = "MOD";
        op.who = who;
        if (!ev.dn.empty()) op.dn = ev.dn;
        if (!ev.attrs.empty()) {
            std::istringstream iss(ev.attrs);
            std::string a;
            while (iss >> a) {
                std::string lower_a = a;
                std::transform(lower_a.begin(), lower_a.end(), lower_a.begin(), ::tolower);
                agg.attr_count[lower_a]++;
            }
        }
        return;
    }

    // --- MODRDN (modify RDN / rename operation) ---
    if (ev.kind == "MODRDN") {
        agg.operation_count["MODRDN"]++;
        agg.read_write_stats.write++;
        ensure_total_counted(agg, cid, opid);
        op.type = "MODRDN";
        op.who = who;
        if (!ev.dn.empty()) op.dn = ev.dn;
        return;
    }

    // --- CMP (compare operation) ---
    if (ev.kind == "CMP") {
        agg.operation_count["CMP"]++;
        agg.read_write_stats.read++;
        ensure_total_counted(agg, cid, opid);
        op.type = "CMP";
        op.who = who;
        if (!ev.dn.empty()) op.dn = ev.dn;
        return;
    }

    // --- COMPARE (alternate compare event kind) ---
    // Some log sources may emit "COMPARE" instead of "CMP".
    // This handler treats them identically.
    if (ev.kind == "COMPARE") {
        agg.operation_count["COMPARE"]++;
        agg.read_write_stats.read++;
        ensure_total_counted(agg, cid, opid);
        op.type = "COMPARE";
        op.who = who;
        if (!ev.dn.empty()) op.dn = ev.dn;
        return;
    }

    // --- ABANDON (abandon operation) ---
    if (ev.kind == "ABANDON") {
        agg.operation_count["ABANDON"]++;
        ensure_total_counted(agg, cid, opid);
        op.type = "ABANDON";
        op.who = who;
        return;
    }

    // --- UNBIND (unbind operation) ---
    if (ev.kind == "UNBIND") {
        agg.operation_count["UNBIND"]++;
        ensure_total_counted(agg, cid, opid);
        op.type = "UNBIND";
        op.who = who;
        return;
    }

    // --- SASL (SASL authentication failure) ---
    if (ev.kind == "SASL") {
        agg.operation_count["SASL"]++;
        return;
    }

    // --- Misc Integrated Patterns (duplicate guard for lines that may
    //     have been classified without cid/opid and reached here) ---
    if (ev.kind == "CONTROL_NOT_SUPPORTED") {
        agg.control_not_supported_count++;
        return;
    }
    if (ev.kind == "STARTTLS") {
        agg.operation_count["STARTTLS"]++;
        return;
    }
    if (ev.kind == "DO_BIND_INVALID") {
        agg.invalid_dn_count++;
        return;
    }
    if (ev.kind == "LDAP_BACK_DOBIND_INT") {
        agg.rebind_failed_count++;
        return;
    }
    if (ev.kind == "LDAP_BACK_RETRY") {
        agg.retry_count++;
        return;
    }
    if (ev.kind == "CONN_DEFER") {
        agg.defer_count++;
        return;
    }

    // ==================================================================
    // Server Events
    // ==================================================================
    // These events are recorded directly into the Aggregator's server
    // event tracking structures.  Normally they are handled before the
    // cid/opid guard, but we also handle them here as a fallback for
    // consistency.

    // Server events
    if (ev.kind == "DAEMON_SHUTDOWN") {
        agg.server_events.daemon_shutdown_count++;
        agg.server_event_list.emplace_back(ev.ts, "daemon shutdown requested");
        return;
    }
    if (ev.kind == "SLAPD_SHUTDOWN") {
        agg.server_events.shutdown_count++;
        agg.server_event_list.emplace_back(ev.ts, "slapd shutdown (waiting for " + ev.text + " ops)");
        return;
    }
    if (ev.kind == "SLAPD_STARTING") {
        agg.server_events.start_count++;
        agg.server_event_list.emplace_back(ev.ts, "slapd starting");
        return;
    }
    if (ev.kind == "SLAPD_STOPPED") {
        agg.server_events.stop_count++;
        agg.server_event_list.emplace_back(ev.ts, "slapd stopped");
        return;
    }

    // ==================================================================
    // Unknown Operation Type
    // ==================================================================
    // If the event kind does not match any of the known handlers above,
    // it is classified as unknown, counted, and stored for inspection.
    agg.stats.unknown_lines++;
    agg.stats.lines++;
    if (unknown_out) {
        std::lock_guard<std::mutex> lock(*unknown_mtx);
        *unknown_out << ev.raw << '\n';
    } else if (agg.unknown_lines.size() < MAX_STORED_UNKNOWN_LINES) {
        agg.unknown_lines.push_back(ev.raw);
    }
}

// =========================================================================
// merge_aggregators — Merge two Aggregator instances into one
// =========================================================================
//
// This function is used to combine the results of processing multiple log
// files (possibly in parallel).  `src` is merged into `dest` — after the
// call, `dest` contains the union of all statistics from both sources.
//
// Merge semantics:
//   - Scalar counters (stats, operation counts, timing totals) are summed.
//   - Per-connection and per-operation state maps are overwritten by `src`
//     (since conn IDs are unique across files in the same log set).
//   - Time ranges are widened (min of firsttime, max of lasttime).
//   - Top-N lists are concatenated, re-sorted, and truncated to 100.
//   - Session correlations are merged field-by-field (first-write-wins for
//     each field within a correlation key).
//   - Unknown lines and server event lists are concatenated.

void merge_aggregators(Aggregator& dest, const Aggregator& src) {

    // --- Scalar stats ---
    dest.stats.lines += src.stats.lines;
    dest.stats.unknown_lines += src.stats.unknown_lines;
    dest.stats.fd_open += src.stats.fd_open;
    dest.stats.fd_close += src.stats.fd_close;
    dest.stats.conn_count += src.stats.conn_count;
    dest.stats.replication_logs += src.stats.replication_logs;

    // --- Per-operation-type counts ---
    for (const auto& [k, v] : src.operation_count)
        dest.operation_count[k] += v;

    // --- Read/write breakdown ---
    dest.read_write_stats.read += src.read_write_stats.read;
    dest.read_write_stats.write += src.read_write_stats.write;

    // --- Per-connection state maps (overwrite — conn IDs are unique) ---
    for (const auto& [k, v] : src.conn_state)
        dest.conn_state[k] = v;
    for (const auto& [k, v] : src.binddn_by_conn)
        dest.binddn_by_conn[k] = v;
    for (const auto& [k, v] : src.src_by_conn)
        dest.src_by_conn[k] = v;

    // --- Time range (widen to cover both sources) ---
    if (!src.firsttime.empty() && (dest.firsttime.empty() || src.firsttime < dest.firsttime))
        dest.firsttime = src.firsttime;
    if (!src.lasttime.empty() && (dest.lasttime.empty() || src.lasttime > dest.lasttime))
        dest.lasttime = src.lasttime;

    // --- Slowest operation (keep the larger etime) ---
    if (src.maxetime.has_value()) {
        if (!dest.maxetime.has_value() || *src.maxetime > *dest.maxetime) {
            dest.maxetime = src.maxetime;
            dest.maxetimeusr = src.maxetimeusr;
            dest.maxopdesc = src.maxopdesc;
        }
    }

    // --- Slowest connection (keep the larger total_etime) ---
    if (src.maxconnetime.has_value()) {
        if (!dest.maxconnetime.has_value() || *src.maxconnetime > *dest.maxconnetime) {
            dest.maxconnetime = src.maxconnetime;
            dest.maxconnetimeusr = src.maxconnetimeusr;
            dest.maxconnopdesc = src.maxconnopdesc;
        }
    }

    // --- Cumulative timing totals ---
    dest.etime_total += src.etime_total;
    dest.qtime_total += src.qtime_total;

    // --- Per-app, per-base, per-filter breakdowns (maps are summed) ---
    for (const auto& [k, v] : src.app_count) dest.app_count[k] += v;
    for (const auto& [k, v] : src.app_etime_total) dest.app_etime_total[k] += v;
    for (const auto& [k, v] : src.base_count) dest.base_count[k] += v;
    for (const auto& [k, v] : src.base_etime_total) dest.base_etime_total[k] += v;
    for (const auto& [k, v] : src.filter_count) dest.filter_count[k] += v;
    for (const auto& [k, v] : src.filter_etime_total) dest.filter_etime_total[k] += v;
    for (const auto& [k, v] : src.norm_filter_attrs_count) dest.norm_filter_attrs_count[k] += v;
    for (const auto& [k, v] : src.norm_filter_n1_count) dest.norm_filter_n1_count[k] += v;
    for (const auto& [k, v] : src.norm_filter_n0_count) dest.norm_filter_n0_count[k] += v;
    for (const auto& [k, v] : src.wildcard_filter_count) dest.wildcard_filter_count[k] += v;
    for (const auto& [app, filters] : src.filter_by_app) {
        for (const auto& [filter, cnt] : filters)
            dest.filter_by_app[app][filter] += cnt;
    }
    for (const auto& [k, v] : src.attr_count) dest.attr_count[k] += v;

    // --- "?" filter (unindexed) tracking ---
    dest.qmark_filter_count += src.qmark_filter_count;
    for (const auto& [k, v] : src.qmark_filter_attr_count) dest.qmark_filter_attr_count[k] += v;

    // --- Error tracking ---
    for (const auto& [k, v] : src.error_count) dest.error_count[k] += v;
    for (const auto& [app, errs] : src.error_per_app) {
        for (const auto& [code, cnt] : errs)
            dest.error_per_app[app][code] += cnt;
    }

    // --- Extended operations and global control OIDs ---
    for (const auto& [k, v] : src.ext_oid_count) dest.ext_oid_count[k] += v;
    for (const auto& [k, v] : src.global_control_oid_count) dest.global_control_oid_count[k] += v;

    // --- CSN event counts ---
    dest.csn_event_count.get += src.csn_event_count.get;
    dest.csn_event_count.queue += src.csn_event_count.queue;
    dest.csn_event_count.graduate += src.csn_event_count.graduate;

    // --- Not-indexed counts ---
    dest.not_indexed_count += src.not_indexed_count;
    for (const auto& [k, v] : src.not_indexed_attr) dest.not_indexed_attr[k] += v;

    // --- Session correlations ---
    // Track the highest restart_count from either source.  Correlation
    // entries are merged field-by-field, keeping the first non-empty
    // value for each field (since entries with the same key may exist
    // in both sources and should not overwrite each other).
    if (src.restart_count > dest.restart_count) dest.restart_count = src.restart_count;
    for (const auto& [key, corr] : src.session_correlations) {
        auto& dest_entry = dest.session_correlations[key];
        dest_entry.restart = corr.restart;
        dest_entry.conn = corr.conn;
        if (dest_entry.ts.empty()) dest_entry.ts = corr.ts;
        if (dest_entry.accept_ip.empty()) dest_entry.accept_ip = corr.accept_ip;
        if (dest_entry.real_ip.empty()) dest_entry.real_ip = corr.real_ip;
        if (dest_entry.name.empty()) dest_entry.name = corr.name;
        if (dest_entry.username.empty()) dest_entry.username = corr.username;
        if (dest_entry.binddn.empty()) dest_entry.binddn = corr.binddn;
    }

    // --- Top-N slowest operations ---
    // Concatenate, sort descending by etime, keep top 100.
    dest.top_ops.insert(dest.top_ops.end(), src.top_ops.begin(), src.top_ops.end());
    if (dest.top_ops.size() > 100) {
        std::partial_sort(dest.top_ops.begin(), dest.top_ops.begin() + 100, dest.top_ops.end(),
            [](const TopOpRow& a, const TopOpRow& b) { return a.etime > b.etime; });
        dest.top_ops.resize(100);
    }

    // --- Top-N slowest connections ---
    // Concatenate, sort descending by total_etime, keep top 100.
    dest.top_conns.insert(dest.top_conns.end(), src.top_conns.begin(), src.top_conns.end());
    if (dest.top_conns.size() > 100) {
        std::partial_sort(dest.top_conns.begin(), dest.top_conns.begin() + 100, dest.top_conns.end(),
            [](const TopConnRow& a, const TopConnRow& b) { return a.total_etime > b.total_etime; });
        dest.top_conns.resize(100);
    }

    // --- Active / peak connections (take the higher of the two) ---
    if (src.active_connections > dest.active_connections)
        dest.active_connections = src.active_connections;
    if (src.peak_active_connections > dest.peak_active_connections)
        dest.peak_active_connections = src.peak_active_connections;

    // --- Misc counters ---
    dest.control_not_supported_count += src.control_not_supported_count;
    dest.invalid_dn_count += src.invalid_dn_count;
    dest.rebind_failed_count += src.rebind_failed_count;
    dest.retry_count += src.retry_count;
    dest.defer_count += src.defer_count;

    // --- Server events (sum counters, concatenate lists) ---
    dest.server_events.start_count += src.server_events.start_count;
    dest.server_events.stop_count += src.server_events.stop_count;
    dest.server_events.shutdown_count += src.server_events.shutdown_count;
    dest.server_events.daemon_shutdown_count += src.server_events.daemon_shutdown_count;
    dest.server_event_list.insert(dest.server_event_list.end(),
        src.server_event_list.begin(), src.server_event_list.end());

    // --- Unknown lines for diagnostic review ---
    // Cap at MAX_STORED_UNKNOWN_LINES to avoid unbounded memory growth
    // on large archives (the statistic is always accurate).
    if (dest.unknown_lines.size() < MAX_STORED_UNKNOWN_LINES) {
        size_t room = MAX_STORED_UNKNOWN_LINES - dest.unknown_lines.size();
        size_t take = std::min(src.unknown_lines.size(), room);
        dest.unknown_lines.insert(dest.unknown_lines.end(),
            src.unknown_lines.begin(), src.unknown_lines.begin() + take);
    }
}

// =========================================================================
// File Processing Functions — read, decompress, parse
// =========================================================================
//
// These functions handle the I/O layer: opening a file (possibly
// compressed), reading lines, and feeding them through the parse + update
// pipeline.  A progress counter (atomic<size_t>) is incremented as data
// is consumed, enabling the caller to report progress.

// ------------------------------------------------------------------
// process_file (dispatch)
// ------------------------------------------------------------------
// Inspects the file extension to choose an appropriate decompression
// handler.  Supports .gz (gzip), .bz2 (bzip2), .xz (lzma), and plain
// text (no compression).
//
// The extension check also accepts date-suffixed names like
// ".bz2_2026-03-01" which occur when rotated logs have a date
// appended after the compression extension.

static bool has_compression_ext(const std::string& filename, const std::string& ext) {
    auto pos = filename.rfind(ext);
    if (pos == std::string::npos) return false;
    size_t after = pos + ext.size();
    return after == filename.size() || filename[after] == '_';
}

void process_file(const std::string& filename, Aggregator& agg,
                  std::atomic<size_t>& progress,
                  std::ostream* unknown_out, std::mutex* unknown_mtx) {
    if (has_compression_ext(filename, ".gz")) process_gzip_file(filename, agg, progress, unknown_out, unknown_mtx);
    else if (has_compression_ext(filename, ".bz2")) process_bzip2_file(filename, agg, progress, unknown_out, unknown_mtx);
    else if (has_compression_ext(filename, ".xz")) process_xz_file(filename, agg, progress, unknown_out, unknown_mtx);
    else process_plain_file(filename, agg, progress, unknown_out, unknown_mtx);
}

// ------------------------------------------------------------------
// process_plain_file — Read a plain (uncompressed) text file
// ------------------------------------------------------------------
// Uses std::getline in a loop.  Each line is parsed and folded into
// the Aggregator.  Progress is tracked as the cumulative byte size
// (line length + 1 for the newline) of processed lines.

void process_plain_file(const std::string& filename, Aggregator& agg,
                        std::atomic<size_t>& progress,
                        std::ostream* unknown_out, std::mutex* unknown_mtx) {
    std::ifstream file(filename);
    if (!file) return;
    std::string line;
    while (std::getline(file, line)) {
        Event ev = parse_line(line);
        update_aggregator(agg, ev, unknown_out, unknown_mtx);
        progress += line.size() + 1;
    }
}

// ------------------------------------------------------------------
// process_gzip_file — Read a gzip-compressed (.gz) file
// ------------------------------------------------------------------
// Uses zlib's gzgets() API, which provides line-by-line reading
// semantics on top of gzip decompression.  Each line is processed
// identically to the plain-text path.

void process_gzip_file(const std::string& filename, Aggregator& agg,
                       std::atomic<size_t>& progress,
                       std::ostream* unknown_out, std::mutex* unknown_mtx) {
    gzFile file = gzopen(filename.c_str(), "rb");
    if (!file) return;
    char buffer[65536];
    std::string line;
    while (gzgets(file, buffer, sizeof(buffer))) {
        line = buffer;
        if (!line.empty() && line.back() == '\n') line.pop_back();
        Event ev = parse_line(line);
        update_aggregator(agg, ev, unknown_out, unknown_mtx);
        progress += line.size() + 1;
    }
    gzclose(file);
}

// ------------------------------------------------------------------
// process_bzip2_file — Read a bzip2-compressed (.bz2) file
// ------------------------------------------------------------------
// Uses libbzip2's streaming decompression API (BZ2_bzRead).  Since
// bzip2 does not offer a line-reading wrapper, we read fixed-size
// chunks into a buffer and split on '\n' manually.  Any remaining
// data after the final chunk is flushed as the last line.

void process_bzip2_file(const std::string& filename, Aggregator& agg,
                        std::atomic<size_t>& progress,
                        std::ostream* unknown_out, std::mutex* unknown_mtx) {
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) return;
    int bzerror;
    BZFILE* bzfile = BZ2_bzReadOpen(&bzerror, file, 0, 0, NULL, 0);
    if (bzerror != BZ_OK) { fclose(file); return; }
    char buffer[65536];
    std::string line;
    while (true) {
        int bytes = BZ2_bzRead(&bzerror, bzfile, buffer, sizeof(buffer));
        if (bytes <= 0) break;
        line.append(buffer, bytes);
        size_t pos;
        while ((pos = line.find('\n')) != std::string::npos) {
            std::string l = line.substr(0, pos);
            Event ev = parse_line(l);
            update_aggregator(agg, ev, unknown_out, unknown_mtx);
            progress += l.size() + 1;
            line.erase(0, pos + 1);
        }
    }
    if (!line.empty()) {
        Event ev = parse_line(line);
        update_aggregator(agg, ev, unknown_out, unknown_mtx);
        progress += line.size() + 1;
    }
    BZ2_bzReadClose(&bzerror, bzfile);
    fclose(file);
}

// ------------------------------------------------------------------
// process_xz_file — Read an xz-compressed (.xz) file
// ------------------------------------------------------------------
// Uses liblzma's streaming decoder (lzma_stream).  The decompression
// loop reads input from the file, feeds it through the LZMA decoder,
// and collects decompressed output in a buffer.  Lines are split on
// '\n' from the output buffer, and any trailing data after the final
// LZMA_STREAM_END is flushed as the last line.

void process_xz_file(const std::string& filename, Aggregator& agg,
                     std::atomic<size_t>& progress,
                     std::ostream* unknown_out, std::mutex* unknown_mtx) {
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) return;
    lzma_stream strm = LZMA_STREAM_INIT;
    if (lzma_stream_decoder(&strm, UINT64_MAX, LZMA_CONCATENATED) != LZMA_OK) {
        fclose(file);
        return;
    }
    char inbuf[65536];
    char outbuf[65536];
    strm.next_in = reinterpret_cast<const uint8_t*>(inbuf);
    strm.avail_in = 0;
    strm.next_out = reinterpret_cast<uint8_t*>(outbuf);
    strm.avail_out = sizeof(outbuf);
    std::string line;
    while (true) {
        if (strm.avail_in == 0) {
            strm.next_in = reinterpret_cast<const uint8_t*>(inbuf);
            strm.avail_in = fread(inbuf, 1, sizeof(inbuf), file);
        }
        lzma_ret ret = lzma_code(&strm, feof(file) ? LZMA_FINISH : LZMA_RUN);
        if (strm.avail_out == 0 || ret == LZMA_STREAM_END) {
            size_t write_size = sizeof(outbuf) - strm.avail_out;
            line.append((char*)outbuf, write_size);
            size_t pos;
            while ((pos = line.find('\n')) != std::string::npos) {
                std::string l = line.substr(0, pos);
                Event ev = parse_line(l);
                update_aggregator(agg, ev, unknown_out, unknown_mtx);
                progress += l.size() + 1;
                line.erase(0, pos + 1);
            }
            strm.next_out = reinterpret_cast<uint8_t*>(outbuf);
            strm.avail_out = sizeof(outbuf);
        }
        if (ret == LZMA_STREAM_END) break;
    }
    if (!line.empty()) {
        Event ev = parse_line(line);
        update_aggregator(agg, ev, unknown_out, unknown_mtx);
        progress += line.size() + 1;
    }
    lzma_end(&strm);
    fclose(file);
}
