// report.cpp

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
// Implementation of the three report-format functions declared in report.hpp.
// The file is organised into three layers:
//   1. An anonymous namespace containing shared helpers (colour support,
//      formatting, sorting, table printing).
//   2. print_text_report   – terminal-friendly output with ANSI colour.
//   3. print_html_report   – standalone HTML page with embedded CSS.
//   4. print_json_report   – structured JSON with the nlohmann library.

#include "report.hpp"
#include "html_chart.hpp"
#include "log_parser.hpp"
#include "utils.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <sstream>
#include <fstream>
#include <map>
#include <set>
#include <tuple>
#include <type_traits>
#include <nlohmann/json.hpp>

#include "version.hpp"

using json = nlohmann::json;

// -----------------------------------------------------------------------
// Anonymous namespace – internal linkage helpers
// -----------------------------------------------------------------------
namespace {

    // LDAP result code → human-readable name mapping.
    // Based on RFC 4511 and common LDAP practice.  Only the codes that
    // actually appear in production logs are listed; omitted codes will
    // fall back to "unknown".
    const std::unordered_map<int, std::string> LDAP_ERRORS = {
        {0, "success"}, {1, "operationsError"}, {2, "protocolError"}, {3, "timeLimitExceeded"},
        {4, "sizeLimitExceeded"}, {5, "compareFalse"}, {6, "compareTrue"}, {7, "authMethodNotSupported"},
        {8, "strongerAuthRequired"}, {10, "referral"}, {11, "adminLimitExceeded"},
        {12, "unavailableCriticalExtension"}, {13, "confidentialityRequired"}, {14, "saslBindInProgress"},
        {16, "noSuchAttribute"}, {17, "undefinedAttributeType"}, {18, "inappropriateMatching"},
        {19, "constraintViolation"}, {20, "attributeOrValueExists"}, {21, "invalidAttributeSyntax"},
        {32, "noSuchObject"}, {33, "aliasProblem"}, {34, "invalidDNSyntax"}, {36, "aliasDereferencingProblem"},
        {48, "inappropriateAuthentication"}, {49, "invalidCredentials"}, {50, "insufficientAccessRights"},
        {51, "busy"}, {52, "unavailable"}, {53, "unwillingToPerform"}, {54, "loopDetect"},
        {64, "namingViolation"}, {65, "objectClassViolation"}, {66, "notAllowedOnNonLeaf"},
        {67, "notAllowedOnRDN"}, {68, "entryAlreadyExists"}, {69, "objectClassModsProhibited"},
        {71, "affectsMultipleDSAs"}, {80, "other"}
    };

    // Well-known LDAP extended operation OIDs → short descriptive labels.
    // Used when printing or displaying extended-operations sections.
    const std::unordered_map<std::string, std::string> EXT_OID_NAME = {
        {"1.3.6.1.4.1.1466.20037", "StartTLS"},
        {"1.3.6.1.4.1.4203.1.11.1", "PasswordModify"},
        {"1.3.6.1.4.1.4203.1.11.3", "WhoAmI"},
        {"1.3.6.1.1.8", "Cancel"}
    };

    // -------------------------------------------------------------------
    // ANSI colour support
    // -------------------------------------------------------------------

    // Empty-string defaults → no colour.
    // Populated by set_color_output() below.
    std::string COLOR_RESET;
    std::string COLOR_RED;
    std::string COLOR_GREEN;
    std::string COLOR_YELLOW;
    std::string COLOR_BLUE;
    std::string COLOR_MAGENTA;
    std::string COLOR_CYAN;
    std::string COLOR_BOLD;
    std::string COLOR_WHITE_BRIGHT;
    std::string COLOR_RED_BRIGHT;

    // 0 = no colour, 1 = basic (only error-related), 2 = full (includes
    // execution-time gradient).
    int color_mode = 1;

    /**
     * set_color_output – Initialise the ANSI colour constants.
     *
     * In mode 0 every constant is cleared to the empty string so that
     * output contains no escapes whatsoever (useful when redirecting to
     * a file or piping to a pager that does not support colour).
     *
     * @param mode  0 = off, 1 = basic, 2 = full (same SGR codes either way).
     */
    void set_color_output(int mode) {
        color_mode = mode;
        if (mode == 0) {
            COLOR_RESET = COLOR_RED = COLOR_GREEN = COLOR_YELLOW = "";
            COLOR_BLUE = COLOR_MAGENTA = COLOR_CYAN = COLOR_BOLD = "";
            COLOR_WHITE_BRIGHT = COLOR_RED_BRIGHT = "";
        } else {
            COLOR_RESET = "\033[0m"; COLOR_RED = "\033[31m";
            COLOR_GREEN = "\033[32m"; COLOR_YELLOW = "\033[33m";
            COLOR_BLUE = "\033[34m"; COLOR_MAGENTA = "\033[35m";
            COLOR_CYAN = "\033[36m"; COLOR_BOLD = "\033[1m";
            COLOR_WHITE_BRIGHT = "\033[97m";
            COLOR_RED_BRIGHT = "\033[91m";
        }
    }

    /**
     * format_time – Convert a system_clock time_point to a locale-aware
     * date-time string (YYYY-MM-DD HH:MM:SS).
     */
    std::string format_time(SystemTimePoint tp) {
        auto in_time_t = std::chrono::system_clock::to_time_t(
            std::chrono::time_point_cast<std::chrono::system_clock::duration>(tp));
        std::stringstream ss;
        ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    /**
     * colorize_etime – Return an ANSI colour code based on an elapsed-time
     * threshold.  Used to give the reader a quick visual hint about latency.
     *
     * Colour gradient (requires color_mode >= 2):
     *   v > 5.0 s  → bright red   (critical)
     *   v > 1.0 s  → red          (slow)
     *   v > 0.5 s  → yellow       (degraded)
     *   v > 0.1 s  → cyan         (acceptable)
     *   else       → green        (fast)
     */
    std::string colorize_etime(double v) {
        if (color_mode < 2) return "";
        if (v > 5.0) return COLOR_RED_BRIGHT;
        if (v > 1.0) return COLOR_RED;
        if (v > 0.5) return COLOR_YELLOW;
        if (v > 0.1) return COLOR_CYAN;
        return COLOR_GREEN;
    }

    /**
     * fmt_double – Format a double with three decimal places (no colour).
     */
    std::string fmt_double(double v) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(3) << v;
        return oss.str();
    }

    /**
     * fmt_etime – Format a double as elapsed time, optionally wrapping it
     * in the ANSI colour obtained from colorize_etime().
     */
    std::string fmt_etime(double v) {
        std::string c = colorize_etime(v);
        std::string r = fmt_double(v);
        if (!c.empty()) r = c + r + COLOR_RESET;
        return r;
    }

    /**
     * fmt_int – Simple long-long-to-string conversion.
     */
    std::string fmt_int(long long v) {
        std::ostringstream oss;
        oss << v;
        return oss.str();
    }

    /**
     * fmt_pct – Format a share (count out of total) as a percentage.
     *
     * Four significant digits keep a rare share readable: 71.107 %, 3.571 %,
     * 0.002882 %.  A non-zero share below 0.01 % still scans as zero in a table
     * whose other rows read "71.107 %", so it is printed as "<0.01%" instead:
     * the count column carries the exact number, and the row can no longer be
     * mistaken for "nothing happened here".  A literal zero keeps its "0%".
     */
    std::string fmt_pct(long long count, long long total) {
        if (total <= 0) return "0%";
        const double pct = 100.0 * static_cast<double>(count) / total;
        if (count > 0 && pct < 0.01) return "<0.01%";
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.4g%%", pct);
        return buf;
    }

    /**
     * strip_ansi – Remove all ANSI escape sequences from a string.
     *
     * Walks the input one character at a time; when it encounters the
     * ESC byte (0x1B / '\033') it skips forward until the terminating 'm'.
     * Everything else is copied verbatim.
     *
     * Used by print_table() so that column widths are computed based on
     * visible character count, ignoring colour codes.
     */
    std::string strip_ansi(const std::string& s) {
        std::string r;
        r.reserve(s.size());
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '\033') {
                while (i < s.size() && s[i] != 'm') ++i;
            } else {
                r += s[i];
            }
        }
        return r;
    }

    /**
     * sort_map_by_value_desc – Sort a std::map<T, long long> by value
     * descending, breaking ties by key (ascending).
     *
     * Returns a vector of key-value pairs suitable for iteration.
     */
    template<typename T>
    std::vector<std::pair<T, long long>> sort_map_by_value_desc(const std::map<T, long long>& m) {
        std::vector<std::pair<T, long long>> v(m.begin(), m.end());
        std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second > b.second;
            return a.first < b.first;
        });
        return v;
    }

    /**
     * print_separator – Print a section heading underlined with '=' characters.
     *
     * Used by print_text_report to demarcate sections.
     */
    void print_separator(const std::string& title) {
        std::cout << "\n" << COLOR_BOLD << COLOR_CYAN << title << COLOR_RESET << "\n";
        std::cout << std::string(title.length(), '=') << "\n";
    }

    /**
     * print_kv – Print a single key-value pair, left-aligned at 40 chars
     * for the key, colon, then value.
     */
    void print_kv(const std::string& key, const std::string& value) {
        std::cout << COLOR_GREEN << std::left << std::setw(40) << key << COLOR_RESET << ": " << value << "\n";
    }

    /**
     * print_table – Render a table with a header row, separator lines,
     * and data rows.
     *
     * Column widths are computed from the visible (stripped) length of the
     * content so that ANSI colour codes do not skew alignment.
     *
     * Format:
     *   +------+------+
     *   | Col1 | Col2 |
     *   +------+------+
     *   | val  | val  |
     *   +------+------+
     */
    void print_table(const std::vector<std::string>& headers, const std::vector<std::vector<std::string>>& rows) {
        if (rows.empty()) return;
        
        std::vector<size_t> widths;
        for (size_t i = 0; i < headers.size(); ++i) {
            widths.push_back(strip_ansi(headers[i]).length());
            for (const auto& row : rows) {
                if (i < row.size()) {
                    widths[i] = std::max(widths[i], strip_ansi(row[i]).length());
                }
            }
        }

        auto print_cell = [&](const std::string& val, size_t col) {
            size_t vis = strip_ansi(val).length();
            std::cout << " " << val;
            if (vis < widths[col]) std::cout << std::string(widths[col] - vis, ' ');
            std::cout << " |";
        };

        // Print header
        std::cout << COLOR_BOLD << "+";
        for (size_t w : widths) std::cout << std::string(w + 2, '-') << "+";
        std::cout << "\n|";
        for (size_t i = 0; i < headers.size(); ++i) print_cell(headers[i], i);
        std::cout << "\n+";
        for (size_t w : widths) std::cout << std::string(w + 2, '-') << "+";
        std::cout << COLOR_RESET << "\n";

        // Print rows
        for (const auto& row : rows) {
            std::cout << "|";
            for (size_t i = 0; i < headers.size(); ++i) {
                std::string val = (i < row.size()) ? row[i] : "";
                print_cell(val, i);
            }
            std::cout << "\n";
        }

        // Print footer
        std::cout << "+";
        for (size_t w : widths) std::cout << std::string(w + 2, '-') << "+";
        std::cout << "\n";
    }

    /**
     * print_string_count_map – Print a sorted, limited table from a
     * string → count map.  Wraps print_separator + print_table.
     *
     * @param title  Section heading.
     * @param col1   Name of the first column.
     * @param m      Source map.
     * @param limit  Maximum number of rows to show.
     */
    void print_string_count_map(const std::string& title, const std::string& col1, 
                                 const std::map<std::string, long long>& m, int limit = 20) {
        if (m.empty()) return;
        print_separator(title);
        auto sorted = sort_map_by_value_desc(m);
        std::vector<std::vector<std::string>> rows;
        int count = 0;
        for (const auto& [key, val] : sorted) {
            if (count++ >= limit) break;
            rows.push_back({key, fmt_int(val)});
        }
        print_table({col1, "Count"}, rows);
    }

    /**
     * Overloads for combined AppInfo / BaseInfo / FilterInfo maps.
     * Each entry has both .count and .etime_total, so we sort by the
     * appropriate field and pass it to the existing formatters.
     */
    template<typename T>
    void print_string_count_map(const std::string& title, const std::string& col1,
                                const std::map<std::string, T>& m, int limit = 20) {
        if (m.empty()) return;
        print_separator(title);
        std::vector<std::pair<long long, std::string>> sorted;
        for (const auto& [k, v] : m) sorted.emplace_back(v.count, k);
        std::sort(sorted.begin(), sorted.end(), std::greater<>());
        std::vector<std::vector<std::string>> rows;
        int count = 0;
        for (const auto& [val, key] : sorted) {
            if (count++ >= limit) break;
            rows.push_back({key, fmt_int(val)});
        }
        print_table({col1, "Count"}, rows);
    }

    template<typename T>
    void print_string_double_map(const std::string& title, const std::string& col1,
                                 const std::map<std::string, T>& m, int limit = 20) {
        if (m.empty()) return;
        print_separator(title);
        std::vector<std::pair<double, std::string>> sorted;
        for (const auto& [k, v] : m) sorted.emplace_back(v.etime_total, k);
        std::sort(sorted.begin(), sorted.end(), std::greater<>());
        std::vector<std::vector<std::string>> rows;
        int count = 0;
        for (const auto& [val, key] : sorted) {
            if (count++ >= limit) break;
            rows.push_back({key, fmt_double(val)});
        }
        print_table({col1, "Total etime"}, rows);
    }
}

// =======================================================================
// print_text_report – Plain-text coloured terminal output
// =======================================================================

/**
 * print_text_report – Iterates over every section of the Aggregator and
 * prints a human-readable, ANSI-coloured report to std::cout.
 *
 * Sections are gated by the `has_section` lambda and the `sections` set:
 * each named section (or "all") controls which blocks execute.
 *
 * Colour gradient for elapsed-time values (color_mode >= 2):
 *   v > 5.0 s  → bright red     (critical)
 *   v > 1.0 s  → red            (slow)
 *   v > 0.5 s  → yellow         (degraded)
 *   v > 0.1 s  → cyan           (acceptable)
 *   else       → green          (fast)
 */
// Session-tracking names are free-form and usually carry a per-session
// identifier (e.g. "WL CED/EUDS 1.3.6.1.4.1.21008.108.63.1=sessionId-123456"),
// which makes every row unique.  Trailing whitespace-separated key=value tokens
// are dropped so that the same client groups together.
static std::string session_name_key(const std::string& name) {
    std::string out = name;
    size_t pos;
    while ((pos = out.rfind(' ')) != std::string::npos) {
        if (out.substr(pos + 1).find('=') == std::string::npos) break;
        out.erase(pos);
    }
    return out;
}

// The recorded ACCEPT address carries the client's source port — and often the
// listen address in parentheses — so counting the raw strings would just count
// the sessions again.  Reduce it to the host part to count distinct NAT
// addresses instead.
static std::string nat_host_key(const std::string& accept_ip) {
    std::string s = accept_ip.substr(0, accept_ip.find(' '));   // drop " (IP=…"
    const size_t colon = s.rfind(':');
    if (colon != std::string::npos && colon + 1 < s.size() &&
        s.find_first_not_of("0123456789", colon + 1) == std::string::npos) {
        s.erase(colon);                                         // drop ":port"
    }
    return s.empty() ? accept_ip : s;
}

// Short human-readable name for an LDAP result code.  Shared by the text and
// HTML reports (and by the charts), so the table lives in one place.
std::string ldap_error_name(int code) {
    auto it = LDAP_ERRORS.find(code);
    return (it != LDAP_ERRORS.end()) ? it->second : "unknown";
}

// Presentation of the result-code classes: the classification itself lives in
// log_parser.cpp, next to the aggregates it filters (see log_parser.hpp).
const char* ldap_code_class_name(LdapCodeClass c) {
    switch (c) {
        case LdapCodeClass::Info:           return "informational";
        case LdapCodeClass::Client:         return "client-side";
        case LdapCodeClass::Policy:         return "by configuration";
        case LdapCodeClass::PolicyOrClient: return "by configuration, or client-side";
        case LdapCodeClass::Server:         return "server-side";
    }
    return "unknown";
}

const char* ldap_code_class_color(LdapCodeClass c) {
    switch (c) {
        case LdapCodeClass::Info:           return "#27ae60";   // green
        case LdapCodeClass::Client:         return "#e67e22";   // amber
        // The dual class keeps violet as its base colour (the text, the tooltip,
        // the label) and adds amber as a hatch — see …_hatch_color().
        case LdapCodeClass::Policy:         return "#8e44ad";   // violet
        case LdapCodeClass::PolicyOrClient: return "#8e44ad";   // violet, hatched amber
        case LdapCodeClass::Server:         return "#cc0000";   // red
    }
    return "#7f8c8d";
}

const char* ldap_code_class_hatch_color(LdapCodeClass c) {
    return c == LdapCodeClass::PolicyOrClient ? "#e67e22" : nullptr;
}

// The hatch as an HTML background: an inline `style` is the only way to paint it
// outside SVG (the charts draw the same two colours as an SVG <pattern>).  Built
// from the same accessors as every other colour, so it cannot drift from them.
static std::string hatch_background_css() {
    return std::string("repeating-linear-gradient(45deg,") +
           ldap_code_class_color(LdapCodeClass::Policy) + " 0 3px," +
           ldap_code_class_hatch_color(LdapCodeClass::PolicyOrClient) + " 3px 6px)";
}

// The same hatch, pale, for a table cell background: the saturated pattern is
// legible as a 10 px swatch but would fight the code and its name, so the row is
// marked with a wash of the two colours instead and the text keeps its violet.
static const char* HATCH_CELL_BG =
    "repeating-linear-gradient(45deg,#f3e6f7 0 3px,#fdeee0 3px 6px)";

void print_text_report(const Aggregator& agg, double processing_time, bool compact, int color_mode, const std::set<std::string>& sections, const std::string& /*output_date_format*/, const std::string& custom_title) {
    set_color_output(color_mode);
    int limit = compact ? 5 : 20;

    auto has_section = [&](const std::string& name) {
        return sections.empty() || sections.count("all") || sections.count(name);
    };

    // Result codes are coloured by class (see ldap_code_class()): green when the
    // code is information, amber when the client is at fault, violet when the
    // configuration deliberately refused, red when slapd itself is at fault.  The
    // dual class shares the violet — ANSI has no hatch — and the text report
    // names no class, so only the HTML side carries the "either cause" reading.
    auto code_color = [&](int code) -> std::string {
        switch (ldap_code_class(code)) {
            case LdapCodeClass::Info:           return COLOR_GREEN;
            case LdapCodeClass::Client:         return COLOR_YELLOW;
            case LdapCodeClass::Policy:         return COLOR_MAGENTA;
            case LdapCodeClass::PolicyOrClient: return COLOR_MAGENTA;
            case LdapCodeClass::Server:         return COLOR_RED;
        }
        return COLOR_RED;
    };

    std::cout << COLOR_BOLD << COLOR_BLUE << "OpenLDAP Log Analysis Report" << COLOR_RESET;
    if (!custom_title.empty()) {
        std::cout << " - " << custom_title;
    }
    std::cout << "\n";
    std::cout << COLOR_BOLD << "=============================================" << COLOR_RESET << "\n";
    std::cout << "Generated on: " << format_time(std::chrono::system_clock::now()) << "\n";

    // Statistics (bordered table)
    // Shows processing metrics, connection counts, timing totals, and
    // read/write breakdown.
    if (has_section("stats")) {
        print_separator("Statistics");
        std::vector<std::vector<std::string>> st_rows;
        double speed = processing_time > 0 ? agg.stats.lines / processing_time : 0;
        st_rows.push_back({"Processing time", fmt_double(processing_time) + " s"});
        st_rows.push_back({"Processing speed", fmt_int(static_cast<long long>(speed)) + " lines/s"});
        st_rows.push_back({"Lines processed", fmt_int(agg.stats.lines)});
        st_rows.push_back({"Unknown lines", fmt_int(agg.stats.unknown_lines)});
        if (!agg.openldap_version.empty())
            st_rows.push_back({"OpenLDAP version", agg.openldap_version});
        if (!agg.servers.empty()) {
            std::string sv;
            for (const auto& s : agg.servers) {
                if (!sv.empty()) sv += ", ";
                sv += s;
            }
            st_rows.push_back({"Server(s)", sv});
        }
        st_rows.push_back({"Connections opened", fmt_int(agg.stats.conn_count)});
        st_rows.push_back({"FD open events", fmt_int(agg.stats.fd_open)});
        st_rows.push_back({"FD close events", fmt_int(agg.stats.fd_close)});
        st_rows.push_back({"Replication logs", fmt_int(agg.stats.replication_logs)});
        st_rows.push_back({"Peak active connections", fmt_int(agg.peak_active_connections)});
        if (!agg.firsttime.empty()) st_rows.push_back({"First timestamp", agg.firsttime});
        if (!agg.lasttime.empty()) st_rows.push_back({"Last timestamp", agg.lasttime});
        st_rows.push_back({"Total etime", fmt_etime(agg.etime_total)});
        st_rows.push_back({"Total qtime", fmt_etime(agg.qtime_total)});
        if (agg.maxetime.has_value()) {
            st_rows.push_back({"Max operation etime", fmt_etime(*agg.maxetime)});
            st_rows.push_back({"Max operation user", agg.maxetimeusr});
        }
        if (agg.maxconnetime.has_value()) {
            st_rows.push_back({"Max connection etime", fmt_etime(*agg.maxconnetime)});
            st_rows.push_back({"Max connection user", agg.maxconnetimeusr});
        }
        st_rows.push_back({"Read operations", fmt_int(agg.read_write_stats.read)});
        st_rows.push_back({"Write operations", fmt_int(agg.read_write_stats.write)});
        print_table({"Metric", "Value"}, st_rows);
    }

    // Load by server
    // A cluster's logs aggregated into one report: how the load splits across
    // the servers.  Shown only when there is more than one (see the HTML side);
    // the JSON carries the totals either way.
    if (has_section("load") && agg.servers.size() > 1) {
        print_separator("Load by Server");
        long long total_ops = 0;
        for (const auto& [s, n] : agg.ops_by_server) total_ops += n;
        std::vector<std::pair<long long, std::string>> by_ops;
        for (const auto& [s, n] : agg.ops_by_server) by_ops.emplace_back(n, s);
        std::sort(by_ops.begin(), by_ops.end(), std::greater<>());
        std::vector<std::vector<std::string>> load_rows;
        for (const auto& [n, s] : by_ops) {
            load_rows.push_back({
                s, fmt_int(n), fmt_pct(n, total_ops),
                fmt_etime(agg.etime_by_server.count(s) ? agg.etime_by_server.at(s) : 0.0),
                fmt_int(agg.conn_by_server.count(s) ? agg.conn_by_server.at(s) : 0),
                fmt_int(agg.results_by_server.count(s) ? agg.results_by_server.at(s) : 0)});
        }
        print_table({"Server", "Operations", "Share", "Total etime", "Connections", "Results"},
                    load_rows);
    }

    // Bind usage
    // How clients authenticated: method, transport the bind ran over, and the
    // SASL mechanism.  Absent when the log carries no BIND.
    if (has_section("bind") && agg.bind_total > 0) {
        print_separator("Bind Usage");
        auto dist = [&](const char* title, const std::map<std::string, long long>& m) {
            if (m.empty()) return;
            std::vector<std::vector<std::string>> rows;
            for (const auto& [key, n] : sort_map_by_value_desc(m)) {
                rows.push_back({key, fmt_int(n), fmt_pct(n, agg.bind_total)});
            }
            print_table({title, "Count", "Share"}, rows);
        };
        dist("Authentication method", agg.bind_method_count);
        dist("Transport", agg.bind_transport_count);
        dist("SASL mechanism", agg.bind_mech_count);
        if (agg.bind_session_control > 0)
            std::cout << "  " << agg.bind_session_control
                      << " bind request(s) carried the session-tracking control.\n";
    }

    // Operation counts
    // Lists every LDAP operation type (bind, search, add, modify, delete,
    // etc.) and how many times it was invoked.
    if (has_section("ops")) {
        print_separator("Operation Counts");
        std::vector<std::vector<std::string>> op_rows;
        for (const auto& [op, count] : agg.operation_count) {
            if (count > 0) op_rows.push_back({op, fmt_int(count)});
        }
        print_table({"Operation", "Count"}, op_rows);
    }

    // LDAP result codes
    // Lists every LDAP result code with its mnemonic name, coloured by class:
    // green when the code is information (success, compareFalse / compareTrue,
    // referral, saslBindInProgress), amber when the request was at fault,
    // violet when the configuration refused or limited the operation, red when
    // slapd itself failed.
    if (has_section("errors")) {
        print_separator("LDAP Result Codes");
        auto error_sorted = sort_map_by_value_desc(agg.error_count);
        std::vector<std::vector<std::string>> error_rows;
        std::string normal;                  // codes that are not failures
        for (const auto& [code, count] : error_sorted) {
            std::string name = ldap_error_name(code);
            std::string code_str = fmt_int(code);
            if (count > 0 && !ldap_code_is_error(code)) {
                if (!normal.empty()) normal += ", ";
                normal += code_str + " " + name;
            }
            if (color_mode >= 1) {
                std::string c = code_color(code);
                code_str = c + code_str + COLOR_RESET;
                name = c + name + COLOR_RESET;
            }
            // Include all error texts with their counts
            std::string text_col;
            if (agg.error_texts.count(code)) {
                for (const auto& [msg, msg_cnt] : agg.error_texts.at(code)) {
                    if (!text_col.empty()) text_col += " | ";
                    text_col += fmt_int(msg_cnt) + "x: " + msg;
                }
            }
            error_rows.push_back({code_str, name, fmt_int(count), text_col});
        }
        if (!normal.empty())
            std::cout << "  Not errors (informational): " << normal << "\n";
        if (color_mode >= 1) {
            std::cout << "  " << COLOR_GREEN << "green" << COLOR_RESET << " information   "
                      << COLOR_YELLOW << "amber" << COLOR_RESET << " requested by the client   "
                      << COLOR_MAGENTA << "violet" << COLOR_RESET << " refused by configuration   "
                      << COLOR_RED << "red" << COLOR_RESET << " slapd itself\n";
        }
        print_table({"Code", "Name", "Count", "Error Text"}, error_rows);
    }

    // Errors per application
    // Groups the error counts by the application ("who") field that
    // triggered the operation, making it easier to identify problematic
    // clients.
    if (has_section("errors_per_app") && !agg.error_per_app.empty()) {
        print_separator("Errors per Application");
        std::vector<std::vector<std::string>> err_rows;
        for (const auto& [app_name, errs] : agg.error_per_app) {
            auto sorted_errs = sort_map_by_value_desc(errs);
            for (const auto& [code, cnt] : sorted_errs) {
                std::string name = ldap_error_name(code);
                std::string code_str = fmt_int(code);
                if (color_mode >= 1) {
                    std::string c = code_color(code);
                    code_str = c + code_str + COLOR_RESET;
                    name = c + name + COLOR_RESET;
                }
                err_rows.push_back({app_name, code_str, name, fmt_int(cnt)});
            }
        }
        // Add Error Text column with all messages and counts
        std::vector<std::vector<std::string>> err_rows_with_text;
        err_rows_with_text.reserve(err_rows.size());
        for (const auto& row : err_rows) {
            int code = std::stoi(row[1].substr(row[1].find_first_not_of("\033[")));
            std::string text_col;
            if (agg.error_texts.count(code)) {
                for (const auto& [msg, msg_cnt] : agg.error_texts.at(code)) {
                    if (!text_col.empty()) text_col += " | ";
                    text_col += fmt_int(msg_cnt) + "x: " + msg;
                }
            }
            std::vector<std::string> new_row = {row[0], row[1], row[2], row[3], text_col};
            err_rows_with_text.push_back(std::move(new_row));
        }
        print_table({"App", "Code", "Name", "Count", "Error Text"}, err_rows_with_text);
    }

    // Paged searches
    // Searches that carried the pagedResultsControl.  slapd logs the control
    // only at loglevel trace, so this section is usually empty on logs taken
    // at the usual "stats" level.
    if (has_section("paged") && (agg.paged_search_count > 0 || !agg.paged_search_by_app.empty())) {
        print_separator("Paged Searches");
        auto paged_sorted = sort_map_by_value_desc(agg.paged_search_by_app);
        std::vector<std::vector<std::string>> paged_rows;
        for (const auto& [who, n] : paged_sorted)
            paged_rows.push_back({who, fmt_int(n)});
        print_table({"Who", "Paged searches"}, paged_rows);
    }

    // Top search bases
    // Shows the most frequently searched base DNs and the ones that
    // accumulated the most total elapsed time.
    if (has_section("bases")) {
        print_string_count_map("Top Search Bases (by count)", "Base", agg.base_stats, limit);
        print_string_double_map("Top Search Bases (by etime)", "Base", agg.base_stats, limit);
    }

    // Top filters
    // Most-used search filters, slowest filters, and specialised views
    // for single-hit / zero-hit / wildcard queries.
    if (has_section("filters")) {
        print_string_count_map("Top Filters (by count)", "Filter", agg.filter_stats, limit);
        print_string_double_map("Top Filters (by etime)", "Filter", agg.filter_stats, limit);
        print_string_count_map("Top Filters (nentries=1)", "Filter", agg.norm_filter_n1_count, limit);
        print_string_count_map("Top Filters (nentries=0)", "Filter", agg.norm_filter_n0_count, limit);
        print_string_count_map("Top Wildcard Filters", "Wildcard Filter", agg.wildcard_filter_count, limit);
    }

    // Filters per application (with alternating App colors and Count gradient)
    // Groups the most popular filters by client application.
    // The application column alternates between cyan and green for visual
    // grouping.  The count column uses a gradient:
    //   > 80 % of max → bright red
    //   > 50 %        → red
    //   > 30 %        → yellow
    //   else          → green
    if (has_section("filters_per_app") && !agg.filter_by_app.empty()) {
        auto gradient_color = [](double ratio) -> std::string {
            if (ratio > 0.8) return COLOR_RED_BRIGHT;
            if (ratio > 0.5) return COLOR_RED;
            if (ratio > 0.3) return COLOR_YELLOW;
            return COLOR_GREEN;
        };
        auto ascii_bar = [](double ratio) -> std::string {
            int n = static_cast<int>(ratio * 20 + 0.5);
            if (n < 1) n = 1;
            if (n > 20) n = 20;
            return std::string(n, '#');
        };
        print_separator("Filters per Application");
        std::vector<std::vector<std::string>> fa_rows;

        long long max_fa_count = 0;
        for (const auto& [key, cnt] : agg.filter_by_app)
            if (cnt > max_fa_count) max_fa_count = cnt;

        std::string current_app;
        int app_color_idx = 0;
        std::vector<std::pair<long long, std::string>> app_filters;
        for (const auto& [key, cnt] : agg.filter_by_app) {
            if (key.first != current_app) {
                if (!current_app.empty()) {
                    std::sort(app_filters.begin(), app_filters.end(), std::greater<>());
                    int rank = 0;
                    for (const auto& [fcnt, f] : app_filters) {
                        if (++rank > limit) break;
                        std::string app_display = current_app;
                        if (color_mode >= 1) {
                            std::string app_color = (app_color_idx % 2 == 0) ? COLOR_CYAN : COLOR_GREEN;
                            app_display = app_color + current_app + COLOR_RESET;
                        }
                        std::string color = (color_mode >= 1)
                            ? gradient_color(static_cast<double>(fcnt) / max_fa_count) : "";
                        std::string bar = (color_mode >= 1)
                            ? ascii_bar(static_cast<double>(fcnt) / max_fa_count) : "";
                        fa_rows.push_back({app_display, f, fmt_int(fcnt) + " " + color + bar});
                    }
                    app_filters.clear();
                }
                current_app = key.first;
                app_color_idx++;
            }
            app_filters.emplace_back(cnt, key.second);
        }
        if (!current_app.empty()) {
            std::sort(app_filters.begin(), app_filters.end(), std::greater<>());
            int rank = 0;
            for (const auto& [fcnt, f] : app_filters) {
                if (++rank > limit) break;
                std::string app_display = current_app;
                if (color_mode >= 1) {
                    std::string app_color = (app_color_idx % 2 == 0) ? COLOR_CYAN : COLOR_GREEN;
                    app_display = app_color + current_app + COLOR_RESET;
                }
                std::string color = (color_mode >= 1)
                    ? gradient_color(static_cast<double>(fcnt) / max_fa_count) : "";
                std::string bar = (color_mode >= 1)
                    ? ascii_bar(static_cast<double>(fcnt) / max_fa_count) : "";
                fa_rows.push_back({app_display, f, fmt_int(fcnt) + " " + color + bar});
            }
        }
        print_table({"Application", "Filter", "Count"}, fa_rows);
    }

    // Top requested attributes
    // Shows which LDAP attributes were most frequently requested in search
    // operations.
    if (has_section("attrs")) {
        print_string_count_map("Top Requested Attributes", "Attribute", agg.attr_count, limit);
    }

    // Top applications
    // Identifies which client applications (by "who" field) issued the
    // most operations and consumed the most server time.
    if (has_section("apps")) {
        print_string_count_map("Top Applications (by count)", "Application", agg.app_stats, limit);
        print_string_double_map("Top Applications (by etime)", "Application", agg.app_stats, limit);
    }

    // Extended operations
    // Shows which LDAP extended operations (StartTLS, PasswordModify, etc.)
    // were invoked and how often.
    if (has_section("extops")) {
        print_separator("Extended Operations");
        auto ext_sorted = sort_map_by_value_desc(agg.ext_oid_count);
        std::vector<std::vector<std::string>> ext_rows;
        for (const auto& [oid, count] : ext_sorted) {
            auto it = EXT_OID_NAME.find(oid);
            std::string name = (it != EXT_OID_NAME.end()) ? it->second : "";
            ext_rows.push_back({oid, name, fmt_int(count)});
        }
        print_table({"OID", "Name", "Count"}, ext_rows);
    }

    // Global control warnings
    // Lists OIDs of any unsolicited global controls that appeared in the
    // log, which often indicate operational warnings from the server.
    if (has_section("extops") && !agg.global_control_oid_count.empty()) {
        print_separator("Global Control Warnings");
        auto gc_sorted = sort_map_by_value_desc(agg.global_control_oid_count);
        std::vector<std::vector<std::string>> gc_rows;
        for (const auto& [oid, count] : gc_sorted) {
            gc_rows.push_back({oid, fmt_int(count)});
        }
        print_table({"OID", "Count"}, gc_rows);
    }

    // Question mark filters
    // Filters containing (?attr=) patterns — these are often indicators of
    // application bugs or misconfiguration.
    if (has_section("qmark")) {
        print_kv("Filters with (?attr=)", fmt_int(agg.qmark_filter_count));
        print_string_count_map("Question-mark filter attributes", "Attribute", agg.qmark_filter_attr_count, limit);
    }

    // CSN events
    // Context-Specific Name (CSN) events are internal to the LDAP server's
    // replication and synchronisation machinery.
    if (has_section("csn")) {
        print_separator("CSN Internal Events");
        print_kv("CSN get", fmt_int(agg.csn_event_count.get));
        print_kv("CSN queue", fmt_int(agg.csn_event_count.queue));
        print_kv("CSN graduate", fmt_int(agg.csn_event_count.graduate));
    }

    // Server start/stop events
    // Timestamped list of when the LDAP server started or stopped.
    if (!agg.server_event_list.empty()) {
        print_separator("Server Start / Stop Events");
        std::vector<std::vector<std::string>> sv_rows;
        for (const auto& [ts, event_type] : agg.server_event_list) {
            sv_rows.push_back({ts, event_type});
        }
        print_table({"Timestamp", "Event"}, sv_rows);
    }

    // Indexing diagnostics
    // Counts how many operations referenced unindexed attributes (a common
    // cause of poor search performance).
    if (has_section("index")) {
        print_separator("Indexing Diagnostics");
        print_kv("Not indexed occurrences", fmt_int(agg.not_indexed_count));
        print_string_count_map("Not indexed attributes", "Attribute", agg.not_indexed_attr, limit);
    }

    // Session tracking correlations
    // Maps client-visible (ACCEPT) IPs to real (proxy-pass-through) IPs
    // via the LDAP session tracking control.
    if (has_section("sessions") && !agg.session_correlations.empty()) {
        print_separator("Session Tracking Correlations");
        // Group by client rather than by session: the tracking name usually
        // carries a per-session identifier, so listing the raw correlations
        // gives one row per session — essentially all unique, and thousands
        // long on a busy log.  Grouping keeps the interesting part (which
        // clients, how many sessions, under which identity).
        struct Group { long long sessions = 0; std::set<std::string> nat_ips; };
        using Key = std::tuple<std::string, std::string, std::string, std::string>;
        std::map<Key, Group> grouped;
        for (const auto& [key, corr] : agg.session_correlations) {
            auto& g = grouped[std::make_tuple(session_name_key(corr.name), corr.real_ip,
                                              corr.username, corr.binddn)];
            g.sessions++;
            if (!corr.accept_ip.empty()) g.nat_ips.insert(nat_host_key(corr.accept_ip));
        }
        std::vector<std::pair<long long, std::vector<std::string>>> ordered;
        ordered.reserve(grouped.size());
        for (const auto& [k, g] : grouped) {
            ordered.push_back({g.sessions, {
                fmt_int(g.sessions),
                fmt_int(static_cast<long long>(g.nat_ips.size())),
                std::get<1>(k),   // real IP (the client behind the NAT)
                std::get<0>(k),   // session name, without the session id
                std::get<2>(k),   // username
                std::get<3>(k)}}); // bind DN
        }
        // Busiest clients first, then a deterministic order.
        std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
            if (a.first != b.first) return a.first > b.first;
            return a.second < b.second;
        });
        std::vector<std::vector<std::string>> st_rows;
        st_rows.reserve(ordered.size());
        for (auto& p : ordered) st_rows.push_back(std::move(p.second));
        if (!st_rows.empty()) {
            print_table({"Sessions", "NAT IPs", "Real IP", "Name", "Username", "BIND dn"},
                        st_rows);
        }
    }

    // Top operations by etime (with gradient)
    // Lists the slowest individual LDAP operations across the entire log.
    if (has_section("topops")) {
        print_separator("Top Long Operations");
        if (!agg.top_ops.empty()) {
            std::vector<std::vector<std::string>> top_op_rows;
            for (const auto& r : agg.top_ops) {
                std::string etime_str = fmt_double(r.etime);
                if (color_mode >= 2) etime_str = fmt_etime(r.etime);
                top_op_rows.push_back({
                    etime_str,
                    std::to_string(r.conn),
                    std::to_string(r.op),
                    r.type,
                    r.who,
                    r.nentries.has_value() ? std::to_string(*r.nentries) : "",
                    r.err.has_value() ? std::to_string(*r.err) : "",
                    r.base,
                    r.filter
                });
            }
            print_table({"etime", "conn", "op", "type", "who", "nentries", "err", "base", "filter"}, top_op_rows);
        }
    }

    // Top connections by cumulative etime (with gradient)
    // Shows which LDAP connections accumulated the most server time across
    // all their operations.
    if (has_section("topconns")) {
        if (!agg.top_conns.empty()) {
            print_separator("Top Connections by Cumulative etime");
            // A cluster's logs all number their connections from 1: the server
            // column is what keeps two conn=1 apart (see "Load by Server").
            const bool multi_server = agg.servers.size() > 1;
            std::vector<std::vector<std::string>> top_conn_rows;
            for (const auto& r : agg.top_conns) {
                std::string etime_str = fmt_double(r.total_etime);
                if (color_mode >= 2) etime_str = fmt_etime(r.total_etime);
                std::vector<std::string> row{etime_str};
                if (multi_server) row.push_back(r.server);
                row.push_back(std::to_string(r.conn));
                row.push_back(r.who);
                row.push_back(r.src);
                row.push_back(std::to_string(r.ops_count));
                row.push_back(r.binddn);
                top_conn_rows.push_back(std::move(row));
            }
            std::vector<std::string> header{"total etime"};
            if (multi_server) header.push_back("server");
            header.insert(header.end(), {"conn", "who", "src", "ops", "binddn"});
            print_table(header, top_conn_rows);
        }
    }
}

// =======================================================================
// print_html_report – Self-contained HTML page
// =======================================================================

/**
 * print_html_report – Emits a complete HTML5 document with embedded CSS to
 * std::cout.  The report is styled with a clean, modern design:
 *
 *   - Flexbox-based meta-info bar at the top.
 *   - Tables with subtle hover and alternating-row effects.
 *   - Server start/stop events highlighted with coloured left borders.
 *   - Responsive via a @media query for narrow viewports.
 *
 * Colour conventions (matching the ANSI gradient in the text report):
 *   > 5.0 s  → #ff4444 bold
 *   > 1.0 s  → #cc0000
 *   > 0.5 s  → #ccaa00
 *   > 0.1 s  → #00aaaa
 *   else     → #00aa00
 */
void print_html_report(const Aggregator& agg, double duration, bool /*compact*/, const std::string& /*output_date_format*/, const std::string& custom_title) {
    // Charts are placed under the section whose data they draw; nothing is
    // emitted (not even the stylesheet) when there is no chart to draw.
    const bool charts = html_charts_available(agg);
    auto etime_color = [](double v) -> std::string {
        if (v > 5.0) return "color:#ff4444;font-weight:bold";
        if (v > 1.0) return "color:#cc0000";
        if (v > 0.5) return "color:#ccaa00";
        if (v > 0.1) return "color:#00aaaa";
        return "color:#00aa00";
    };

    // A result code is coloured by class (see ldap_code_class()) — the same
    // colour its bar and its donut slice carry, so a code reads the same
    // everywhere on the page.  The dual class keeps its violet text (violet is
    // the class base) and gains a pale hatch behind it: the row is identifiable
    // at a glance without the saturated pattern hurting the legibility of the
    // code and its name.
    auto err_color = [](int code) -> std::string {
        const LdapCodeClass cls = ldap_code_class(code);
        std::string s = std::string("color:") + ldap_code_class_color(cls);
        if (cls == LdapCodeClass::PolicyOrClient) s += std::string(";background:") + HATCH_CELL_BG;
        return s;
    };

    // A colour key entry, built from the same colours so it cannot drift from the
    // tables and the charts.  The dual class shows the full-strength hatch here,
    // where a 10 px swatch is read as a colour, not behind text.
    auto code_swatch = [](LdapCodeClass c, const char* what) {
        const std::string bg = (c == LdapCodeClass::PolicyOrClient)
                                   ? hatch_background_css()
                                   : std::string(ldap_code_class_color(c));
        return std::string("<span style=\"display:inline-block;width:10px;height:10px;"
                           "border-radius:2px;background:") + bg + ";margin-right:5px\"></span>" + what;
    };

    auto gradient_ratio = [](long long val, long long maxv) -> std::string {
        if (maxv <= 0) return "color:#00aa00";
        double r = static_cast<double>(val) / maxv;
        if (r > 0.8) return "color:#ff4444;font-weight:bold";
        if (r > 0.5) return "color:#cc0000";
        if (r > 0.3) return "color:#ccaa00";
        return "color:#00aa00";
    };

    // Minimal HTML escaping for values that reach the page verbatim (host
    // names, bind DNs, application identities).
    auto html_escape = [](const std::string& s) {
        std::string o;
        o.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  o += "&amp;";  break;
                case '<':  o += "&lt;";   break;
                case '>':  o += "&gt;";   break;
                case '"':  o += "&quot;"; break;
                default:   o += c;
            }
        }
        return o;
    };

    std::cout << "<!DOCTYPE html>\n";
    std::cout << "<html lang=\"en\">\n";
    std::cout << "<head>\n";
    std::cout << "<meta charset=\"UTF-8\">\n";
    std::cout << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    std::cout << "<title>LDAP Log Analysis Report";
    if (!custom_title.empty()) {
        std::cout << " - " << custom_title;
    }
    std::cout << "</title>\n";
    // Inline CSS: uses a system-ui font stack, a dark h1 gradient header,
    // rounded corners, subtle shadows, and monospace table data cells.
    std::cout << "<style>\n";
    std::cout << "  * { margin:0; padding:0; box-sizing:border-box; }\n";
    std::cout << "  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace; ";
    std::cout << "background:#f5f6fa; color:#2c3e50; padding:20px; }\n";
    // Title bar: dark-to-blue gradient to draw immediate attention.
    std::cout << "  h1 { background:linear-gradient(135deg,#2c3e50,#3498db); color:#fff; ";
    std::cout << "padding:20px 30px; border-radius:8px; margin-bottom:20px; ";
    std::cout << "font-size:1.6em; box-shadow:0 2px 8px rgba(0,0,0,0.15); }\n";
    // Section headings: solid dark background, rounded, clear-fixed.
    std::cout << "  h2 { background:#2c3e50; color:#ecf0f1; padding:10px 20px; border-radius:6px; ";
    std::cout << "margin:20px 0 10px; font-size:1.2em; clear:both; }\n";
    // Meta info box: white card with flex layout for side-by-side stats.
    std::cout << "  .meta { background:#fff; border-radius:6px; padding:15px 20px; ";
    std::cout << "box-shadow:0 1px 4px rgba(0,0,0,0.08); margin-bottom:20px; ";
    std::cout << "display:flex; flex-wrap:wrap; gap:15px; }\n";
    std::cout << "  .meta-item { min-width:200px; }\n";
    std::cout << "  .meta-label { color:#7f8c8d; font-size:0.75em; text-transform:uppercase; ";
    std::cout << "letter-spacing:0.5px; }\n";
    std::cout << "  .meta-value { font-size:1.3em; font-weight:600; color:#2c3e50; }\n";
    // Tables: white background, collapsed borders, rounded via overflow hidden.
    std::cout << "  table { width:100%; border-collapse:collapse; background:#fff; ";
    std::cout << "border-radius:6px; overflow:hidden; box-shadow:0 1px 4px rgba(0,0,0,0.08); ";
    std::cout << "margin-bottom:20px; }\n";
    // Header cells: dark grey background, white uppercase text.
    std::cout << "  th { background:#34495e; color:#fff; padding:10px 14px; ";
    std::cout << "text-align:left; font-weight:600; font-size:0.85em; ";
    std::cout << "text-transform:uppercase; letter-spacing:0.5px; }\n";
    // Data cells: monospace, with a subtle bottom border for row separation.
    std::cout << "  td { padding:8px 14px; border-bottom:1px solid #ecf0f1; ";
    std::cout << "font-family:'Consolas','Courier New',monospace; font-size:0.85em; }\n";
    // Row hover: light grey background for readability.
    std::cout << "  tr:hover td { background:#f8f9fa; }\n";
    // Alternating row colours (even rows) for easier scanning.
    std::cout << "  tr:nth-child(even) td { background:#fafbfc; }\n";
    std::cout << "  tr:nth-child(even):hover td { background:#f0f1f2; }\n";
    std::cout << "  .alt-app td:first-child { font-weight:600; }\n";
    std::cout << "  .footer { text-align:center; color:#95a5a6; font-size:0.8em; ";
    std::cout << "padding:20px 0; border-top:1px solid #ecf0f1; margin-top:20px; }\n";
    // Server events: green left border for start, red for stop.
    std::cout << "  .server-event-start { border-left:4px solid #27ae60; padding-left:8px; }\n";
    std::cout << "  .server-event-stop { border-left:4px solid #e74c3c; padding-left:8px; }\n";
    // Responsive: tighten padding and font on small screens.
    std::cout << "  @media (max-width:768px) { body { padding:10px; } ";
    std::cout << "h1 { font-size:1.2em; padding:15px; } ";
    std::cout << "th,td { padding:6px 8px; font-size:0.75em; } }\n";
    // "Show more" button that reveals the tail of a long table.
    std::cout << "  .sl-more { display:block; margin:6px 0 16px; padding:6px 14px; font:inherit; ";
    std::cout << "font-size:0.85em; color:#34495e; background:#fff; border:1px solid #c8d0da; ";
    std::cout << "border-radius:5px; cursor:pointer; }\n";
    std::cout << "  .sl-more:hover { background:#eef2f7; border-color:#3498db; color:#2980b9; }\n";
    // Explanatory line under a section heading (e.g. result codes that are
    // informational rather than failures).
    std::cout << "  .note { color:#7f8c8d; font-size:0.85em; margin:-4px 0 10px; }\n";
    // Statistics: two label/value pairs per row, which halves the height of a
    // section that holds little data.  Full width, like every other section.
    std::cout << "  table.stats td.sl-stat-l { font-weight:600; color:#34495e; width:240px; }\n";
    // Floating section index, fixed in the top-right corner.  Built by script
    // from the h2[id] elements, so it never lists a section the report did not
    // draw and never drifts from the headings themselves.  It opens with the
    // report — the reader sees where he can go — then tucks itself away into a
    // three-line window on the section being read: the one before, the one the
    // reader is in, the one after.  It opens again when the pointer comes near,
    // and a click on the heading pins it open (the only way to reach it without
    // a pointer: touch, keyboard).
    std::cout << "  .sl-index { position:fixed; top:12px; right:12px; z-index:1000; max-width:260px; "
                 "background:#fff; border:1px solid #c8d0da; border-radius:6px; "
                 "box-shadow:0 2px 10px rgba(0,0,0,0.12); font-size:0.8em; }\n";
    std::cout << "  .sl-index-head { padding:6px 12px; background:#34495e; color:#fff; "
                 "font-weight:600; cursor:pointer; user-select:none; white-space:nowrap; "
                 "border-radius:5px 5px 0 0; }\n";
    std::cout << "  .sl-index-caret { display:inline-block; margin-left:7px; opacity:0.75; "
                 "transition:transform 0.2s; }\n";
    std::cout << "  .sl-index.open .sl-index-caret { transform:rotate(90deg); }\n";
    // The list is a window, not a disclosure: it always shows the row being read
    // and its neighbours, and grows to the whole index when the index opens.  The
    // window is a clipped, scrolled list rather than a shorter one, so the lines
    // do not change identity as it opens and closes — and both states are a pixel
    // height, which is what lets the change be animated.  The box is sized by all
    // the links either way, so its width never moves.
    std::cout << "  .sl-index-list { padding:6px 0; height:var(--sl-win,66px); overflow:hidden; "
                 "transition:height 0.32s ease; }\n";
    std::cout << "  .sl-index.open .sl-index-list { height:var(--sl-full,78vh); overflow:auto; }\n";
    // One line per row, so every row is the same height and the window can be
    // sized from a single measurement.
    std::cout << "  .sl-index-list a { display:block; padding:3px 12px; color:#2980b9; "
                 "text-decoration:none; white-space:nowrap; overflow:hidden; "
                 "text-overflow:ellipsis; }\n";
    std::cout << "  .sl-index-list a:hover { background:#eef2f7; }\n";
    std::cout << "  .sl-index-list a.active { background:#34495e; color:#fff; }\n";
    std::cout << "  @media (max-width:768px) { .sl-index { max-width:45vw; } }\n";
    std::cout << "</style>\n";
    if (charts) print_html_chart_style();
    std::cout << "</head>\n<body>\n";

    // Header
    std::cout << "<h1>OpenLDAP Log Analysis Report";
    if (!custom_title.empty()) {
        std::cout << " - " << custom_title;
    }
    std::cout << "</h1>\n";

    // Meta information
    // A flexbox row of key-value metadata at the top of the report.
    double speed = duration > 0 ? agg.stats.lines / duration : 0;
    std::cout << "<div class=\"meta\">\n";
    std::cout << "  <div class=\"meta-item\"><div class=\"meta-label\">Generated</div>";
    std::cout << "<div class=\"meta-value\">" << format_time(std::chrono::system_clock::now()) << "</div></div>\n";
    std::cout << "  <div class=\"meta-item\"><div class=\"meta-label\">Processing time</div>";
    std::cout << "<div class=\"meta-value\">" << fmt_double(duration) << " s</div></div>\n";
    std::cout << "  <div class=\"meta-item\"><div class=\"meta-label\">Lines processed</div>";
    std::cout << "<div class=\"meta-value\">" << agg.stats.lines << "</div></div>\n";
    std::cout << "  <div class=\"meta-item\"><div class=\"meta-label\">Unknown lines</div>";
    std::cout << "<div class=\"meta-value\">" << agg.stats.unknown_lines << "</div></div>\n";
    std::cout << "  <div class=\"meta-item\"><div class=\"meta-label\">Connections</div>";
    std::cout << "<div class=\"meta-value\">" << agg.stats.conn_count << "</div></div>\n";
    std::cout << "  <div class=\"meta-item\"><div class=\"meta-label\">Peak active</div>";
    std::cout << "<div class=\"meta-value\">" << agg.peak_active_connections << "</div></div>\n";
    if (!agg.openldap_version.empty()) {
        std::cout << "  <div class=\"meta-item\"><div class=\"meta-label\">OpenLDAP</div>";
        std::cout << "<div class=\"meta-value\">" << agg.openldap_version << "</div></div>\n";
    }
    // Which server(s) the analysed log lines name.  Empty for the "debug"
    // format, which carries no hostname — then the row is simply absent.
    if (!agg.servers.empty()) {
        std::string sv;
        for (const auto& s : agg.servers) {
            if (!sv.empty()) sv += ", ";
            sv += html_escape(s);
        }
        std::cout << "  <div class=\"meta-item\"><div class=\"meta-label\">"
                  << (agg.servers.size() == 1 ? "Server" : "Servers") << "</div>";
        std::cout << "<div class=\"meta-value\" title=\"" << sv << "\">";
        if (agg.servers.size() == 1) std::cout << html_escape(*agg.servers.begin());
        else std::cout << agg.servers.size() << " servers";
        std::cout << "</div></div>\n";
    }
    if (!agg.firsttime.empty()) {
        std::cout << "  <div class=\"meta-item\"><div class=\"meta-label\">First event</div>";
        std::cout << "<div class=\"meta-value\">" << agg.firsttime << "</div></div>\n";
    }
    if (!agg.lasttime.empty()) {
        std::cout << "  <div class=\"meta-item\"><div class=\"meta-label\">Last event</div>";
        std::cout << "<div class=\"meta-value\">" << agg.lasttime << "</div></div>\n";
    }
    std::cout << "  <div class=\"meta-item\"><div class=\"meta-label\">Speed</div>";
    std::cout << "<div class=\"meta-value\">" << static_cast<long long>(speed) << " lines/s</div></div>\n";
    std::cout << "</div>\n";

    // Statistics table
    // A two-column table (label, value) with the same metrics as the
    // text "stats" section.
    std::cout << "<h2 id=\"sec-statistics\">Statistics</h2>\n";
    // The metrics are laid out two per row: the section carries little data, and
    // a single column would make it three times taller than it needs to be.
    std::vector<std::pair<std::string, std::string>> stat_rows;
    auto add_stat = [&](const std::string& label, const std::string& val) {
        stat_rows.emplace_back(label, val);
    };
    add_stat("Processing time", fmt_double(duration) + " s");
    add_stat("Processing speed", fmt_int(static_cast<long long>(speed)) + " lines/s");
    add_stat("Lines processed", fmt_int(agg.stats.lines));
    add_stat("Unknown lines", fmt_int(agg.stats.unknown_lines));
    add_stat("Connections opened", fmt_int(agg.stats.conn_count));
    add_stat("FD open events", fmt_int(agg.stats.fd_open));
    add_stat("FD close events", fmt_int(agg.stats.fd_close));
    add_stat("Replication logs", fmt_int(agg.stats.replication_logs));
    add_stat("Peak active connections", fmt_int(agg.peak_active_connections));
    if (!agg.servers.empty()) {
        std::string sv;
        for (const auto& s : agg.servers) {
            if (!sv.empty()) sv += ", ";
            sv += html_escape(s);
        }
        add_stat("Server(s)", sv);
    }
    if (!agg.firsttime.empty()) add_stat("First timestamp", agg.firsttime);
    if (!agg.lasttime.empty()) add_stat("Last timestamp", agg.lasttime);
    add_stat("Total etime", "<span style=\"" + etime_color(agg.etime_total) + "\">" + fmt_double(agg.etime_total) + "</span>");
    add_stat("Total qtime", "<span style=\"" + etime_color(agg.qtime_total) + "\">" + fmt_double(agg.qtime_total) + "</span>");
    if (agg.maxetime.has_value()) {
        add_stat("Max operation etime", "<span style=\"" + etime_color(*agg.maxetime) + "\">" + fmt_double(*agg.maxetime) + "</span>");
        add_stat("Max operation user", agg.maxetimeusr);
    }
    if (agg.maxconnetime.has_value()) {
        add_stat("Max connection etime", "<span style=\"" + etime_color(*agg.maxconnetime) + "\">" + fmt_double(*agg.maxconnetime) + "</span>");
        add_stat("Max connection user", agg.maxconnetimeusr);
    }
    add_stat("Read operations", fmt_int(agg.read_write_stats.read));
    add_stat("Write operations", fmt_int(agg.read_write_stats.write));
    std::cout << "<table class=\"stats\">\n";
    for (size_t i = 0; i < stat_rows.size(); i += 2) {
        std::cout << "<tr><td class=\"sl-stat-l\">" << stat_rows[i].first << "</td><td>"
                  << stat_rows[i].second << "</td>";
        if (i + 1 < stat_rows.size())
            std::cout << "<td class=\"sl-stat-l\">" << stat_rows[i + 1].first << "</td><td>"
                      << stat_rows[i + 1].second << "</td>";
        else
            std::cout << "<td colspan=\"2\"></td>";
        std::cout << "</tr>\n";
    }
    std::cout << "</table>\n";

    // Load by server
    // A cluster's logs are aggregated into one report; this section shows how
    // the load splits across the servers.  Drawn only when there is more than
    // one: with a single server the split would be one row at 100 %, and the
    // *Statistics* section already carries that server's totals.
    if (agg.servers.size() > 1) {
        long long total_ops = 0;
        for (const auto& [s, n] : agg.ops_by_server) total_ops += n;
        std::cout << "<h2 id=\"sec-load\">Load by Server</h2>\n";
        std::cout << "<table>\n<tr><th>Server</th><th>Operations</th><th>Share</th>"
                     "<th>Total etime</th><th>Connections</th><th>Results</th></tr>\n";
        std::vector<std::pair<long long, std::string>> by_ops;
        for (const auto& [s, n] : agg.ops_by_server) by_ops.emplace_back(n, s);
        std::sort(by_ops.begin(), by_ops.end(), std::greater<>());
        for (const auto& [n, s] : by_ops) {
            const double et = agg.etime_by_server.count(s) ? agg.etime_by_server.at(s) : 0.0;
            std::cout << "<tr><td>" << html_escape(s) << "</td><td>" << n << "</td><td>"
                      << fmt_pct(n, total_ops) << "</td><td style=\"" << etime_color(et) << "\">"
                      << fmt_double(et) << "</td><td>"
                      << (agg.conn_by_server.count(s) ? agg.conn_by_server.at(s) : 0)
                      << "</td><td>"
                      << (agg.results_by_server.count(s) ? agg.results_by_server.at(s) : 0)
                      << "</td></tr>\n";
        }
        std::cout << "</table>\n";
        print_html_chart(agg, HtmlChart::LoadByServer);
    }

    // Each chart is emitted under the section whose data it draws; the first
    // one therefore sits right after the Statistics table.
    print_html_chart(agg, HtmlChart::Connections);

    // Operation counts
    std::cout << "<h2 id=\"sec-operations\">Operation Counts</h2>\n";
    std::cout << "<table>\n<tr><th>Operation</th><th>Count</th></tr>\n";
    for (const auto& [op, count] : agg.operation_count) {
        if (count > 0) std::cout << "<tr><td>" << op << "</td><td>" << count << "</td></tr>\n";
    }
    std::cout << "</table>\n";
    print_html_chart(agg, HtmlChart::OperationTypes);

    // Bind usage
    // How clients authenticated: the method slapd logged, the transport the
    // connection was on when the bind ran, and the SASL mechanism.  The whole
    // section is absent when the log carries no BIND.
    if (agg.bind_total > 0) {
        std::cout << "<h2 id=\"sec-bind\">Bind Usage</h2>\n";
        std::cout << "<p class=\"note\">Every BIND request, split three ways.  "
                     "The <b>method</b> is what slapd decoded: 128 is the simple "
                     "method, 163 is SASL, and a simple bind with an empty DN is "
                     "anonymous.  The <b>transport</b> is read from the handshake "
                     "that preceded the bind: TLS with no STARTTLS was implicit "
                     "<code>ldaps</code>, TLS after a STARTTLS operation was "
                     "<code>ldap + StartTLS</code>, no TLS at all was plain "
                     "<code>ldap</code>.  The <b>mechanism</b> is the SASL "
                     "mechanism slapd named when the bind succeeded.</p>\n";
        auto dist = [&](const char* title, const std::map<std::string, long long>& m,
                        long long total) {
            if (m.empty()) return;
            std::cout << "<table>\n<tr><th>" << title << "</th><th>Count</th>"
                         "<th>Share</th></tr>\n";
            for (const auto& [key, n] : sort_map_by_value_desc(m)) {
                std::cout << "<tr><td>" << html_escape(key) << "</td><td>" << n
                          << "</td><td>" << fmt_pct(n, total) << "</td></tr>\n";
            }
            std::cout << "</table>\n";
        };
        dist("Authentication method", agg.bind_method_count, agg.bind_total);
        dist("Transport", agg.bind_transport_count, agg.bind_total);
        dist("SASL mechanism", agg.bind_mech_count, agg.bind_total);
        if (agg.bind_session_control > 0)
            std::cout << "<p class=\"note\">" << agg.bind_session_control
                      << " bind request(s) carried the session-tracking control.</p>\n";
        print_html_chart(agg, HtmlChart::BindMethod);
    }

    // LDAP result codes
    // Every LDAP result code, coloured by class, with the codes that are *not*
    // failures recalled in a note so a green row is never mistaken for a silent
    // error, and a colour key so the kinds of refusal read apart: what the client
    // asked, what the configuration allows, the refusals the log cannot attribute
    // to either side (drawn hatched, both colours), and what slapd failed to do.
    std::cout << "<h2 id=\"sec-result-codes\">LDAP Result Codes</h2>\n";
    auto error_sorted = sort_map_by_value_desc(agg.error_count);
    std::string normal;
    for (const auto& [code, count] : error_sorted) {
        if (count > 0 && !ldap_code_is_error(code)) {
            if (!normal.empty()) normal += ", ";
            normal += fmt_int(code) + " " + ldap_error_name(code);
        }
    }
    if (!normal.empty())
        std::cout << "<p class=\"note\">Kept as information, not counted as "
                     "failures: " << normal << ".</p>\n";
    std::cout << "<p class=\"note\">Colour key: "
              << code_swatch(LdapCodeClass::Info, "informational")
              << " &middot; " << code_swatch(LdapCodeClass::Client, "client-side")
              << " &middot; " << code_swatch(LdapCodeClass::Policy, "refused by configuration")
              << " &middot; " << code_swatch(LdapCodeClass::PolicyOrClient,
                                             "refused by configuration &mdash; or a client-side mistake")
              << " &middot; " << code_swatch(LdapCodeClass::Server, "slapd itself")
              << ".</p>\n";
    std::cout << "<table>\n<tr><th>Code</th><th>Name</th><th>Count</th><th>Error Text</th></tr>\n";
    for (const auto& [code, count] : error_sorted) {
        std::string text_col;
        if (agg.error_texts.count(code)) {
            for (const auto& [msg, msg_cnt] : agg.error_texts.at(code)) {
                if (!text_col.empty()) text_col += " | ";
                text_col += fmt_int(msg_cnt) + "x: " + html_escape(msg);
            }
        }
        std::cout << "<tr><td style=\"" << err_color(code) << "\">" << code << "</td>"
                  << "<td style=\"" << err_color(code) << "\">" << ldap_error_name(code) << "</td>"
                  << "<td>" << count << "</td>"
                  << "<td>" << text_col << "</td></tr>\n";
    }
    std::cout << "</table>\n";
    // Right under the table it belongs to: every code, successful ones included,
    // as bars with the cumulative share on the right.  Then the donut, which
    // answers the narrower question — of what actually failed, what failed how?
    print_html_chart(agg, HtmlChart::ResultCodeBreakdown);
    print_html_chart(agg, HtmlChart::ResultCodes);
    print_html_chart(agg, HtmlChart::ErrorsOverTime);

    // Errors per application
    if (!agg.error_per_app.empty()) {
        std::cout << "<h2 id=\"sec-errors-app\">Errors per Application</h2>\n";
        std::cout << "<table>\n<tr><th>App</th><th>Code</th><th>Name</th><th>Count</th><th>Error Text</th></tr>\n";
        for (const auto& [app_name, errs] : agg.error_per_app) {
            auto sorted_errs = sort_map_by_value_desc(errs);
            for (const auto& [code, cnt] : sorted_errs) {
                auto it = LDAP_ERRORS.find(code);
                std::string name = (it != LDAP_ERRORS.end()) ? it->second : "unknown";
                std::string text_col;
                if (agg.error_texts.count(code)) {
                    for (const auto& [msg, msg_cnt] : agg.error_texts.at(code)) {
                        if (!text_col.empty()) text_col += " | ";
                        text_col += fmt_int(msg_cnt) + "x: " + html_escape(msg);
                    }
                }
                std::cout << "<tr><td>" << app_name << "</td>"
                          << "<td style=\"" << err_color(code) << "\">" << code << "</td>"
                          << "<td style=\"" << err_color(code) << "\">" << name << "</td>"
                          << "<td>" << cnt << "</td>"
                          << "<td>" << text_col << "</td></tr>\n";
            }
        }
        std::cout << "</table>\n";
    }

    // Top search bases
    // Paged searches (RFC 2696)
    // OpenLDAP logs the pagedResultsControl only at loglevel trace, as
    //   => get_ctrls: oid="1.2.840.113556.1.4.319" (critical)
    // so this section is absent from a report built from logs taken at the
    // usual "stats" level.  When it is present, the count is broken down by
    // the identity that issued the search.
    if (agg.paged_search_count > 0 || !agg.paged_search_by_app.empty()) {
        std::cout << "<h2 id=\"sec-paged\">Paged Searches</h2>\n";
        std::cout << "<p class=\"note\">Searches that used the pagedResultsControl"
                     " (1.2.840.113556.1.4.319), counted two ways: by shape — one"
                     " connection repeating the same request, every page returning"
                     " the same count until a smaller last page — and, at loglevel"
                     " <code>trace</code>, from the explicit"
                     " <code>=&gt; get_ctrls</code> line. The shape is a match, not"
                     " a proof: an application that repeats one search and then"
                     " stops looks the same.</p>\n";
        std::cout << "<table>\n<tr><th>Who</th><th>Paged searches</th></tr>\n";
        auto paged_sorted = sort_map_by_value_desc(agg.paged_search_by_app);
        for (const auto& [who, n] : paged_sorted)
            std::cout << "<tr><td>" << html_escape(who) << "</td><td>" << n << "</td></tr>\n";
        std::cout << "</table>\n";
    }

    // Anchor id for a section heading, so the floating index can link to it.
    // Derived from the title, which keeps the index in step with the sections
    // even when a heading is renamed.
    auto section_id = [](const std::string& title) {
        std::string id = "sec-";
        for (char c : title) {
            const unsigned char u = static_cast<unsigned char>(c);
            if (std::isalnum(u)) id += static_cast<char>(std::tolower(u));
            else if (c == ' ' || c == '-' || c == '_' || c == '(' || c == ')') id += '-';
        }
        // Collapse the runs of dashes a title like "Top Filters (nentries=1)"
        // would otherwise produce, and trim the ends.
        std::string clean;
        for (char c : id) {
            if (c == '-' && !clean.empty() && clean.back() == '-') continue;
            clean += c;
        }
        while (!clean.empty() && clean.back() == '-') clean.pop_back();
        return clean;
    };
    auto print_h_count_table = [&](const std::string& title, const std::string& col1, const auto& m, int limit = 20) {
        if (m.empty()) return;
        std::cout << "<h2 id=\"" << section_id(title) << "\">" << title << "</h2>\n<table>\n<tr><th>" << col1 << "</th><th>Count</th></tr>\n";
        std::vector<std::pair<long long, std::string>> sorted;
        for (const auto& [key, val] : m) {
            if constexpr (std::is_arithmetic_v<std::decay_t<decltype(val)>>)
                sorted.emplace_back(val, key);
            else
                sorted.emplace_back(val.count, key);
        }
        std::sort(sorted.begin(), sorted.end(), std::greater<>());
        int cnt = 0;
        for (const auto& [c, key] : sorted) {
            if (cnt++ >= limit) break;
            std::cout << "<tr><td>" << key << "</td><td>" << c << "</td></tr>\n";
        }
        std::cout << "</table>\n";
    };
    auto print_h_double_table = [&](const std::string& title, const std::string& col1, const auto& m, int limit = 20) {
        if (m.empty()) return;
        std::cout << "<h2 id=\"" << section_id(title) << "\">" << title << "</h2>\n<table>\n<tr><th>" << col1 << "</th><th>Total etime</th></tr>\n";
        std::vector<std::pair<double, std::string>> sorted;
        for (const auto& [key, val] : m) {
            if constexpr (std::is_same_v<std::decay_t<decltype(val)>, double>)
                sorted.emplace_back(val, key);
            else
                sorted.emplace_back(val.etime_total, key);
        }
        std::sort(sorted.begin(), sorted.end(), std::greater<>());
        int cnt = 0;
        for (const auto& [t, key] : sorted) {
            if (cnt++ >= limit) break;
            std::cout << "<tr><td>" << key << "</td><td><span style=\"" << etime_color(t) << "\">" << fmt_double(t) << "</span></td></tr>\n";
        }
        std::cout << "</table>\n";
    };

    print_h_count_table("Top Search Bases (by count)", "Base", agg.base_stats);
    print_h_double_table("Top Search Bases (by etime)", "Base", agg.base_stats);

    print_h_count_table("Top Filters (by count)", "Filter", agg.filter_stats);
    print_h_double_table("Top Filters (by etime)", "Filter", agg.filter_stats);
    print_h_count_table("Top Filters (nentries=1)", "Filter", agg.norm_filter_n1_count);
    print_h_count_table("Top Filters (nentries=0)", "Filter", agg.norm_filter_n0_count);
    print_h_count_table("Top Wildcard Filters", "Wildcard Filter", agg.wildcard_filter_count);

    // Top requested attributes
    print_h_count_table("Top Requested Attributes", "Attribute", agg.attr_count);

    // Top applications
    print_h_count_table("Top Applications (by count)", "Application", agg.app_stats);
    print_h_double_table("Top Applications (by etime)", "Application", agg.app_stats);
    print_html_chart(agg, HtmlChart::Accounts);

    // Filters per application
    // HTML version of the per-app filter table; count cells are coloured
    // with the same gradient ratio as the text version.
    if (!agg.filter_by_app.empty()) {
        std::cout << "<h2 id=\"sec-filters-app\">Filters per Application</h2>\n<table>\n<tr><th>App</th><th>Filter</th><th>Count</th></tr>\n";
        long long max_fa_count = 0;
        for (const auto& [key, cnt] : agg.filter_by_app)
            if (cnt > max_fa_count) max_fa_count = cnt;

        std::string current_app;
        std::vector<std::pair<long long, std::string>> app_filters;
        for (const auto& [key, cnt] : agg.filter_by_app) {
            if (key.first != current_app) {
                if (!current_app.empty()) {
                    std::sort(app_filters.begin(), app_filters.end(), std::greater<>());
                    int rank = 0;
                    for (const auto& [fcnt, f] : app_filters) {
                        if (++rank > 20) break;
                        std::cout << "<tr><td>" << current_app << "</td><td>" << f
                                  << "</td><td style=\"" << gradient_ratio(fcnt, max_fa_count)
                                  << "\">" << fcnt << "</td></tr>\n";
                    }
                    app_filters.clear();
                }
                current_app = key.first;
            }
            app_filters.emplace_back(cnt, key.second);
        }
        if (!current_app.empty()) {
            std::sort(app_filters.begin(), app_filters.end(), std::greater<>());
            int rank = 0;
            for (const auto& [fcnt, f] : app_filters) {
                if (++rank > 20) break;
                std::cout << "<tr><td>" << current_app << "</td><td>" << f
                          << "</td><td style=\"" << gradient_ratio(fcnt, max_fa_count)
                          << "\">" << fcnt << "</td></tr>\n";
            }
        }
        std::cout << "</table>\n";
    }

    // Extended operations
    if (!agg.ext_oid_count.empty()) {
        std::cout << "<h2 id=\"sec-ext\">Extended Operations</h2>\n<table>\n<tr><th>OID</th><th>Name</th><th>Count</th></tr>\n";
        auto ext_sorted = sort_map_by_value_desc(agg.ext_oid_count);
        for (const auto& [oid, count] : ext_sorted) {
            auto it = EXT_OID_NAME.find(oid);
            std::string name = (it != EXT_OID_NAME.end()) ? it->second : "";
            std::cout << "<tr><td>" << oid << "</td><td>" << name << "</td><td>" << count << "</td></tr>\n";
        }
        std::cout << "</table>\n";
    }

    // Global control warnings
    if (!agg.global_control_oid_count.empty()) {
        std::cout << "<h2 id=\"sec-gc\">Global Control Warnings</h2>\n<table>\n<tr><th>OID</th><th>Count</th></tr>\n";
        auto gc_sorted = sort_map_by_value_desc(agg.global_control_oid_count);
        for (const auto& [oid, count] : gc_sorted) {
            std::cout << "<tr><td>" << oid << "</td><td>" << count << "</td></tr>\n";
        }
        std::cout << "</table>\n";
    }

    // CSN events
    std::cout << "<h2 id=\"sec-csn\">CSN Internal Events</h2>\n<table>\n<tr><th>Event</th><th>Count</th></tr>\n";
    std::cout << "<tr><td>CSN get</td><td>" << agg.csn_event_count.get << "</td></tr>\n";
    std::cout << "<tr><td>CSN queue</td><td>" << agg.csn_event_count.queue << "</td></tr>\n";
    std::cout << "<tr><td>CSN graduate</td><td>" << agg.csn_event_count.graduate << "</td></tr>\n";
    std::cout << "</table>\n";

    // Indexing diagnostics
    std::cout << "<h2 id=\"sec-indexing\">Indexing Diagnostics</h2>\n<table>\n";
    std::cout << "<tr><td style=\"font-weight:600\">Not indexed occurrences</td><td>" << agg.not_indexed_count << "</td></tr>\n";
    std::cout << "</table>\n";
    print_h_count_table("Not indexed attributes", "Attribute", agg.not_indexed_attr);

    // Question mark filters
    std::cout << "<h2 id=\"sec-qmark\">Question-mark Filters</h2>\n<table>\n";
    std::cout << "<tr><td style=\"font-weight:600\">Filters with (?attr=)</td><td>" << agg.qmark_filter_count << "</td></tr>\n";
    std::cout << "</table>\n";
    print_h_count_table("Question-mark filter attributes", "Attribute", agg.qmark_filter_attr_count);

    // Server events
    if (!agg.server_event_list.empty()) {
        std::cout << "<h2 id=\"sec-server-events\">Server Start / Stop Events</h2>\n<table>\n<tr><th>Timestamp</th><th>Event</th></tr>\n";
        for (const auto& [ts, event_type] : agg.server_event_list) {
            std::string cls = (event_type.find("start") != std::string::npos) ? "server-event-start" : "server-event-stop";
            std::cout << "<tr class=\"" << cls << "\"><td>" << ts << "</td><td>" << event_type << "</td></tr>\n";
        }
        std::cout << "</table>\n";
    }

    // Session tracking correlations, grouped by client (see the text report).
    if (!agg.session_correlations.empty()) {
        struct Group { long long sessions = 0; std::set<std::string> nat_ips; };
        using Key = std::tuple<std::string, std::string, std::string, std::string>;
        std::map<Key, Group> grouped;
        for (const auto& [key, corr] : agg.session_correlations) {
            auto& g = grouped[std::make_tuple(session_name_key(corr.name), corr.real_ip,
                                              corr.username, corr.binddn)];
            g.sessions++;
            if (!corr.accept_ip.empty()) g.nat_ips.insert(nat_host_key(corr.accept_ip));
        }
        std::vector<std::pair<long long, std::vector<std::string>>> ordered;
        ordered.reserve(grouped.size());
        for (const auto& [k, g] : grouped) {
            ordered.push_back({g.sessions, {
                fmt_int(g.sessions),
                fmt_int(static_cast<long long>(g.nat_ips.size())),
                std::get<1>(k), std::get<0>(k), std::get<2>(k), std::get<3>(k)}});
        }
        std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
            if (a.first != b.first) return a.first > b.first;
            return a.second < b.second;
        });

        std::cout << "<h2 id=\"sec-session\">Session Tracking Correlations</h2>\n";
        std::cout << "<table>\n<tr><th>Sessions</th><th>NAT IPs</th><th>Real IP</th>"
                     "<th>Name</th><th>Username</th><th>BIND dn</th></tr>\n";
        for (const auto& [n, cells] : ordered) {
            std::cout << "<tr>";
            for (const auto& c : cells) std::cout << "<td>" << c << "</td>";
            std::cout << "</tr>\n";
        }
        std::cout << "</table>\n";
    }

    // Top operations
    // The slowest individual operations, with elapsed-time colouring.
    std::cout << "<h2 id=\"sec-top-ops\">Top Long Operations</h2>\n";
    std::cout << "<table>\n<tr><th>etime</th><th>conn</th><th>op</th><th>type</th><th>who</th><th>base</th><th>filter</th></tr>\n";
    for (const auto& r : agg.top_ops) {
        std::cout << "<tr><td style=\"" << etime_color(r.etime) << "\">" << fmt_double(r.etime) << "</td>"
                  << "<td>" << r.conn << "</td><td>" << r.op
                  << "</td><td>" << r.type << "</td><td>" << r.who
                  << "</td><td>" << r.base << "</td><td>" << r.filter << "</td></tr>\n";
    }
    std::cout << "</table>\n";

    print_html_chart(agg, HtmlChart::Latency);
    print_html_chart(agg, HtmlChart::LatencyDensity);

    // Top connections
    // Connections sorted by cumulative elapsed time.
    std::cout << "<h2 id=\"sec-top-conns\">Top Connections by Cumulative etime</h2>\n";
    // A cluster's logs all number their connections from 1: the server column is
    // what keeps two conn=1 apart.  A single-server log does not need it.
    const bool multi_server = agg.servers.size() > 1;
    std::cout << "<table>\n<tr><th>total etime</th>";
    if (multi_server) std::cout << "<th>server</th>";
    std::cout << "<th>conn</th><th>who</th><th>src</th><th>ops</th></tr>\n";
    for (const auto& r : agg.top_conns) {
        std::cout << "<tr><td style=\"" << etime_color(r.total_etime) << "\">" << fmt_double(r.total_etime) << "</td>";
        if (multi_server) std::cout << "<td>" << html_escape(r.server) << "</td>";
        std::cout << "<td>" << r.conn << "</td><td>" << r.who
                  << "</td><td>" << r.src << "</td><td>" << r.ops_count << "</td></tr>\n";
    }
    std::cout << "</table>\n";

    // Footer
    std::cout << "<div class=\"footer\">slaplog v" << SLAPLOG_VERSION << " &mdash; OpenLDAP Log Analysis Report</div>\n";
    // Long tables are collapsed client-side: the first rows are shown, the tail
    // is revealed by a button.  Doing it generically here means every section
    // benefits without the emitters having to know about it.
    std::cout << R"HTML(<script>
(function(){
  var LIMIT = 25;
  var tables = document.querySelectorAll('table');
  for (var i = 0; i < tables.length; i++) { (function(t){
    var rows = [], trs = t.querySelectorAll('tr');
    for (var j = 0; j < trs.length; j++) if (trs[j].querySelector('td')) rows.push(trs[j]);
    if (rows.length <= LIMIT) return;
    var rest = rows.slice(LIMIT);
    for (var k = 0; k < rest.length; k++) rest[k].style.display = 'none';
    var b = document.createElement('button');
    b.className = 'sl-more';
    b.textContent = 'show ' + rest.length + ' more row(s)';
    b.onclick = function(){
      var hidden = rest[0].style.display === 'none';
      for (var m = 0; m < rest.length; m++) rest[m].style.display = hidden ? '' : 'none';
      b.textContent = hidden ? ('hide ' + rest.length + ' row(s)')
                             : ('show ' + rest.length + ' more row(s)');
    };
    t.parentNode.insertBefore(b, t.nextSibling);
  })(tables[i]); }

  // Floating section index: built from the h2[id] elements, so it lists exactly
  // the sections the report drew — charts have no id and stay out of it.  It
  // opens with the report, then tucks itself into a three-line window around the
  // section being read (the one before, the one read, the one after).  It opens
  // again when the pointer comes near, and a click on the heading pins it open,
  // the only way to reach it without a pointer (touch, keyboard).  Clicking a
  // link scrolls to that section.
  var hs = document.querySelectorAll('h2[id]');
  if (hs.length) {
    var box = document.createElement('div');
    box.className = 'sl-index';
    var head = document.createElement('div');
    head.className = 'sl-index-head';
    head.appendChild(document.createTextNode('Index'));
    var caret = document.createElement('span');
    caret.className = 'sl-index-caret';
    caret.appendChild(document.createTextNode('\u25B8'));   // ▸, rotated when open
    head.appendChild(caret);
    var list = document.createElement('div');
    list.className = 'sl-index-list';
    var rows = [];
    for (var i = 0; i < hs.length; i++) {
      var a = document.createElement('a');
      a.href = '#' + hs[i].id;
      a.appendChild(document.createTextNode(hs[i].textContent));
      list.appendChild(a);
      rows.push(a);
    }
    box.appendChild(head);
    box.appendChild(list);
    document.body.appendChild(box);

    // --- the window on the section being read ----------------------------
    // One list, two heights: closed, the box clips it to WIN rows and scrolls it
    // to the section being read, so those three lines are always the ones in
    // view; open, it shows the lot.  Heights are pixels in both states, which is
    // what makes the change animatable; only the box is measured, never the text.
    var WIN = 3;                       // rows visible when closed
    var PAD = 12;                      // the list's own 6px top and bottom
    var open = false, pinned = false, intro = true, queued = false, ticking = false;
    var px = -1, py = -1, active = 0, top0 = 0;

    function measure() {
      var row = rows[0].offsetHeight || 22;
      var win = row * Math.min(WIN, rows.length) +
                (window.getComputedStyle(list).boxSizing === 'content-box' ? 0 : PAD);
      var full = Math.min(Math.round(window.innerHeight * 0.78), list.scrollHeight || win);
      box.style.setProperty('--sl-win', win + 'px');
      box.style.setProperty('--sl-full', Math.max(full, win) + 'px');
    }
    // Put the window on the active row: a contiguous three-row run containing it,
    // clamped to the list, scrolled to the top of the box.  Open, the list is the
    // reader's to scroll, so it is left alone.
    function place() {
      top0 = rows[0].offsetTop;
      if (open) return;
      var start = Math.max(0, Math.min(active - 1, rows.length - WIN));
      list.scrollTop = rows[start].offsetTop - top0;
    }
    function setOpen(v) {
      if (v === open) return;
      measure();
      open = v;
      box.classList.toggle('open', v);
      if (v) place();                                        // no scrolling left over
      else { anchor = head.getBoundingClientRect(); place(); }
    }

    // --- open on approach, close on leave --------------------------------
    // The reference is the *collapsed* box: its top-right anchor never moves, the
    // list growing down from it.  Measuring the live box instead would make the
    // test chase the box it is itself opening, and flap.
    var anchor = head.getBoundingClientRect();
    var NEAR = 48;    // how close the pointer must come to open
    var KEEP = 110;   // how far it must leave before closing again (hysteresis)

    function apply() {
      if (pinned) { setOpen(true); return; }
      if (px < 0) { if (!intro) setOpen(false); return; }
      var r = box.getBoundingClientRect();
      // Inside the box — the opened list included — always counts as near.
      if (px >= r.left && px <= r.right && py >= r.top && py <= r.bottom) { setOpen(true); return; }
      // The opening view is the reader's to look at: it is not cut short by a
      // pointer that merely happens to be far away.
      if (intro) return;
      var d = open ? KEEP : NEAR;
      setOpen(px >= anchor.left - d && px <= anchor.right + d &&
              py >= anchor.top - d && py <= anchor.bottom + d);
    }
    function onMove(x, y) {
      px = x; py = y;
      if (queued) return;
      queued = true;
      window.requestAnimationFrame(function(){ queued = false; apply(); });
    }
    head.onclick = function() {
      pinned = !pinned;
      if (pinned) setOpen(true); else apply();
    };
    document.addEventListener('mousemove', function(e){ onMove(e.clientX, e.clientY); });
    // Leaving the window must not leave the list hanging open.
    document.addEventListener('mouseleave', function(){ px = -1; py = -1; apply(); });
    window.addEventListener('resize', function(){ measure(); if (!open) anchor = head.getBoundingClientRect(); place(); });

    // Highlight the section the reader is in — the last heading whose top has
    // passed the offset — and move the window onto it, so the index doubles as a
    // position indicator even while it is tucked away.
    var updateActive = function() {
      active = 0;
      for (var i = 0; i < hs.length; i++)
        if (hs[i].getBoundingClientRect().top <= 100) active = i;
      for (var i = 0; i < rows.length; i++) rows[i].classList.toggle('active', i === active);
      place();
    };
    window.addEventListener('scroll', function() {
      if (ticking) return;
      ticking = true;
      window.requestAnimationFrame(function() { updateActive(); ticking = false; });
    });
    updateActive();
    setOpen(true);          // it opens with the report…
    window.setTimeout(function(){ intro = false; apply(); }, 3000);   // …then tucks itself away
  }
})();
</script>
)HTML";
    if (charts) print_html_chart_script();
    std::cout << "</body>\n</html>\n";
}

// =======================================================================
// print_json_report – Machine-readable JSON output
// =======================================================================

/**
 * print_json_report – Serialises the Aggregator data as a JSON object using
 * the nlohmann/json library, printed to std::cout with 2-space indentation.
 *
 * Top-level JSON structure:
 * {
 *   "processing_time":          double,
 *   "lines":                    long long,
 *   "connections_opened":       long long,
 *   "peak_active_connections":  long long,
 *   "first_timestamp":          string,
 *   "last_timestamp":           string,
 *   "etime_total":              double,
 *   "qtime_total":              double,
 *   "max_etime":                double (optional),
 *   "read_operations":          long long,
 *   "write_operations":         long long,
 *   "operation_counts":         { op_name: count, ... },
 *   "error_counts":             { code: { name, count }, ... },
 *   "top_bases":                [ { base, count, etime_total? }, ... ],
 *   "top_filters":              [ { filter, count, etime_total? }, ... ],
 *   "top_operations":           [ { etime, conn, op, type, who, base, filter, nentries?, err? }, ... ],
 *   "session_correlations":     [ { restart, conn, timestamp, accept_ip, real_ip, name, username, binddn }, ... ],
 *   "top_connections":          [ { total_etime, conn, who, src, ops_count, binddn }, ... ],
 *   "extended_operations":      { oid: { name, count }, ... },
 *   "global_control_warnings":  { oid: count, ... },
 *   "csn_events":               { get, queue, graduate },
 *   "not_indexed_count":        long long,
 *   "not_indexed_attributes":   { attr: count, ... },
 *   "qmark_filter_count":       long long,
 *   "qmark_filter_attributes":  { attr: count, ... }
 * }
 */
void print_json_report(const Aggregator& agg, double duration, bool /*compact*/, const std::string& /*output_date_format*/, const std::string& custom_title) {
    json report;
    report["title"] = "OpenLDAP Log Analysis Report";
    if (!custom_title.empty()) {
        report["title"] += " - " + custom_title;
    }

    // Top-level scalar metrics
    report["processing_time"] = duration;
    report["lines"] = agg.stats.lines;
    report["unknown_lines"] = agg.stats.unknown_lines;
    if (!agg.openldap_version.empty()) report["openldap_version"] = agg.openldap_version;
    // The servers the log lines carry (syslog/rfc3339 hostnames); empty when
    // the "debug" format was used, which names no host.
    if (!agg.servers.empty())
        report["servers"] = std::vector<std::string>(agg.servers.begin(), agg.servers.end());
    if (!agg.ops_by_server.empty()) {
        json load = json::object();
        for (const auto& [srv, n] : agg.ops_by_server) {
            load[srv] = {
                {"operations", n},
                {"etime_total", agg.etime_by_server.count(srv) ? agg.etime_by_server.at(srv) : 0.0},
                {"connections", agg.conn_by_server.count(srv) ? agg.conn_by_server.at(srv) : 0},
                {"results", agg.results_by_server.count(srv) ? agg.results_by_server.at(srv) : 0},
            };
        }
        report["load_by_server"] = load;
    }
    // The window each server's own log covers, as the raw timestamps the log
    // carried: the pair the charts draw as coverage lanes, and the only way to
    // tell that a fall in a time series is the edge of a file.  Same shape as
    // first_timestamp / last_timestamp, one entry per host.
    if (!agg.time_by_server.empty()) {
        json coverage = json::object();
        for (const auto& [srv, w] : agg.time_by_server) {
            if (w.first.empty() || w.last.empty()) continue;
            coverage[srv] = { {"first_timestamp", w.first},
                              {"last_timestamp", w.last} };
        }
        if (!coverage.empty()) report["time_by_server"] = coverage;
    }
    if (agg.bind_total > 0) {
        json bind = json::object();
        bind["total"] = agg.bind_total;
        bind["by_method"] = agg.bind_method_count;
        bind["by_transport"] = agg.bind_transport_count;
        if (!agg.bind_mech_count.empty()) bind["by_mechanism"] = agg.bind_mech_count;
        if (agg.bind_session_control > 0) bind["session_tracking"] = agg.bind_session_control;
        report["bind_usage"] = bind;
    }
    report["paged_search_count"] = agg.paged_search_count;
    if (!agg.paged_search_by_app.empty()) report["paged_search_by_app"] = agg.paged_search_by_app;
    report["connections_opened"] = agg.stats.conn_count;
    report["peak_active_connections"] = agg.peak_active_connections;
    report["first_timestamp"] = agg.firsttime;
    report["last_timestamp"] = agg.lasttime;
    report["etime_total"] = agg.etime_total;
    report["qtime_total"] = agg.qtime_total;

    // Optional maxima
    if (agg.maxetime.has_value()) {
        report["max_etime"] = *agg.maxetime;
        report["max_etime_user"] = agg.maxetimeusr;
        report["max_etime_desc"] = agg.maxopdesc;
    }

    if (agg.maxconnetime.has_value()) {
        report["max_conn_etime"] = *agg.maxconnetime;
        report["max_conn_etime_user"] = agg.maxconnetimeusr;
        report["max_conn_etime_desc"] = agg.maxconnopdesc;
    }

    // Read / write breakdown
    report["read_operations"] = agg.read_write_stats.read;
    report["write_operations"] = agg.read_write_stats.write;

    // Operation counts
    // Object keyed by operation name (Bind, Search, Add, etc.).
    json ops = json::object();
    for (const auto& [op, count] : agg.operation_count) {
        if (count > 0) ops[op] = count;
    }
    report["operation_counts"] = ops;

    // Error counts
    // Object keyed by numeric error code string, each containing a
    // human-readable "name", the "count", and an array of "texts" with
    // each unique error message and its occurrence count.
    json errors = json::object();
    for (const auto& [code, count] : agg.error_count) {
        auto it = LDAP_ERRORS.find(code);
        std::string name = (it != LDAP_ERRORS.end()) ? it->second : "unknown";
        json texts = json::array();
        if (agg.error_texts.count(code)) {
            for (const auto& [msg, msg_cnt] : agg.error_texts.at(code)) {
                texts.push_back({{"text", msg}, {"count", msg_cnt}});
            }
        }
        errors[std::to_string(code)] = {{"name", name}, {"count", count}, {"texts", texts}};
    }
    report["error_counts"] = errors;

    // Top bases
    // Array of objects sorted by count descending (limit 20).
    json bases = json::array();
    std::vector<std::pair<long long, std::string>> bases_sorted;
    for (const auto& [k, v] : agg.base_stats) bases_sorted.emplace_back(v.count, k);
    std::sort(bases_sorted.begin(), bases_sorted.end(), std::greater<>());
    int count = 0;
    for (const auto& [c, base] : bases_sorted) {
        if (count++ >= 20) break;
        json entry;
        entry["base"] = base;
        entry["count"] = c;
        auto it = agg.base_stats.find(base);
        if (it != agg.base_stats.end()) entry["etime_total"] = it->second.etime_total;
        bases.push_back(entry);
    }
    report["top_bases"] = bases;

    // Top filters
    // Array of objects sorted by count descending (limit 20).
    json filters = json::array();
    std::vector<std::pair<long long, std::string>> filters_sorted;
    for (const auto& [k, v] : agg.filter_stats) filters_sorted.emplace_back(v.count, k);
    std::sort(filters_sorted.begin(), filters_sorted.end(), std::greater<>());
    count = 0;
    for (const auto& [c, filter] : filters_sorted) {
        if (count++ >= 20) break;
        json entry;
        entry["filter"] = filter;
        entry["count"] = c;
        auto it = agg.filter_stats.find(filter);
        if (it != agg.filter_stats.end()) entry["etime_total"] = it->second.etime_total;
        filters.push_back(entry);
    }
    report["top_filters"] = filters;

    // Top operations
    // Array of the longest-running individual operations.
    json top_ops = json::array();
    for (const auto& r : agg.top_ops) {
        json entry;
        entry["etime"] = r.etime;
        entry["conn"] = r.conn;
        entry["op"] = r.op;
        entry["type"] = r.type;
        entry["who"] = r.who;
        entry["base"] = r.base;
        entry["filter"] = r.filter;
        if (r.nentries.has_value()) entry["nentries"] = *r.nentries;
        if (r.err.has_value()) entry["err"] = *r.err;
        top_ops.push_back(entry);
    }
    report["top_operations"] = top_ops;

    // Session correlations
    // Array of objects mapping client IPs through session tracking.
    // Duplicate entries (same accept_ip/real_ip/name/username/binddn)
    // are suppressed to keep the list concise.
    json session_corrs = json::array();
    {
        std::set<std::tuple<std::string,std::string,std::string,std::string,std::string>> seen;
        for (const auto& [key, corr] : agg.session_correlations) {
            auto tup = std::make_tuple(corr.accept_ip, corr.real_ip, corr.name,
                                       corr.username, corr.binddn);
            if (seen.insert(tup).second) {
                json entry;
                entry["restart"] = corr.restart;
                if (agg.servers.size() > 1) entry["server"] = corr.server;
                entry["conn"] = corr.conn;
                entry["timestamp"] = corr.ts;
                entry["accept_ip"] = corr.accept_ip;
                entry["real_ip"] = corr.real_ip;
                entry["name"] = corr.name;
                entry["username"] = corr.username;
                entry["binddn"] = corr.binddn;
                session_corrs.push_back(entry);
            }
        }
    }
    report["session_correlations"] = session_corrs;

    // Top connections
    // Array of the connections with the highest cumulative elapsed time.
    json top_conns = json::array();
    for (const auto& r : agg.top_conns) {
        json entry;
        entry["total_etime"] = r.total_etime;
        // Only when it says something: a single-server log numbers its
        // connections uniquely, and its JSON keeps the flat shape it always had.
        if (agg.servers.size() > 1) entry["server"] = r.server;
        entry["conn"] = r.conn;
        entry["who"] = r.who;
        entry["src"] = r.src;
        entry["ops_count"] = r.ops_count;
        entry["binddn"] = r.binddn;
        top_conns.push_back(entry);
    }
    report["top_connections"] = top_conns;

    // Extended operations
    // Object keyed by OID, each containing a "name" and "count".
    json ext_ops = json::object();
    for (const auto& [oid, c] : agg.ext_oid_count) {
        auto it = EXT_OID_NAME.find(oid);
        std::string name = (it != EXT_OID_NAME.end()) ? it->second : "";
        ext_ops[oid] = {{"name", name}, {"count", c}};
    }
    report["extended_operations"] = ext_ops;

    // Global control warnings
    // Object keyed by OID, with the warning count as value.
    json gc = json::object();
    for (const auto& [oid, c] : agg.global_control_oid_count) {
        gc[oid] = c;
    }
    report["global_control_warnings"] = gc;

    // CSN events
    report["csn_events"] = {
        {"get", agg.csn_event_count.get},
        {"queue", agg.csn_event_count.queue},
        {"graduate", agg.csn_event_count.graduate}
    };

    // Not indexed
    report["not_indexed_count"] = agg.not_indexed_count;
    json ni = json::object();
    for (const auto& [attr, c] : agg.not_indexed_attr) {
        ni[attr] = c;
    }
    report["not_indexed_attributes"] = ni;

    // Question mark filters
    report["qmark_filter_count"] = agg.qmark_filter_count;
    json qm = json::object();
    for (const auto& [attr, c] : agg.qmark_filter_attr_count) {
        qm[attr] = c;
    }
    report["qmark_filter_attributes"] = qm;

    // Pretty-print with 2-space indentation
    std::cout << report.dump(2) << "\n";
}

void print_replay_report(const Aggregator& agg, double /*duration*/, const std::string& output_date_format, const std::string& separator) {
    const char* sep = separator.c_str();
    std::cout << "timestamp" << sep << "conn" << sep << "op" << sep << "type" << sep << "base" << sep << "filter" << sep << "attrs" << sep << "scope" << sep << "deref" << sep << "binddn" << sep << "authcid" << sep << "authzid" << sep << "err" << sep << "etime" << sep << "qtime" << sep << "nentries" << sep << "text\n";

    long long dropped = get_replay_ops_dropped();
    if (dropped > 0) {
        std::cerr << "WARNING: " << dropped << " operations dropped due to --replay-limit. "
                  << "Use --replay-limit 0 for unlimited.\n";
    }

    std::string path = get_replay_tempfile_path();
    if (path.empty()) return;

    close_replay_tempfile();

    std::ifstream in(path);
    if (!in.is_open()) return;

    struct ReplayRow {
        double etime; int conn; int op;
        std::string type, who, base, filter, attrs;
        std::string scope, deref;
        std::string binddn, authcid, authzid;
        std::string nentries, err, qtime;
        std::string text, timestamp;
        size_t seq = 0;   // input position, used as the final sort key
    };

    std::vector<ReplayRow> rows;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::istringstream ss(line);
        ReplayRow r{};
        std::string etime_s;
        std::getline(ss, etime_s, '\t'); r.etime = 0.0;
        if (!etime_s.empty()) { try { r.etime = std::stod(etime_s); } catch (...) {} }
        std::string conn_s, op_s;
        std::getline(ss, conn_s, '\t'); r.conn = 0;
        if (!conn_s.empty()) { try { r.conn = std::stoi(conn_s); } catch (...) {} }
        std::getline(ss, op_s, '\t'); r.op = 0;
        if (!op_s.empty()) { try { r.op = std::stoi(op_s); } catch (...) {} }
        std::getline(ss, r.type, '\t');
        std::getline(ss, r.who, '\t');
        std::getline(ss, r.base, '\t');
        std::getline(ss, r.filter, '\t');
        std::getline(ss, r.attrs, '\t');
        std::getline(ss, r.scope, '\t');
        std::getline(ss, r.deref, '\t');
        std::getline(ss, r.binddn, '\t');
        std::getline(ss, r.authcid, '\t');
        std::getline(ss, r.authzid, '\t');
        std::getline(ss, r.nentries, '\t');
        std::getline(ss, r.err, '\t');
        std::getline(ss, r.qtime, '\t');
        std::getline(ss, r.text, '\t');
        std::getline(ss, r.timestamp, '\t');
        r.seq = rows.size();
        rows.push_back(std::move(r));
    }
    in.close();

    // Sort by timestamp, then connection, then operation.  Rows agreeing on all
    // three are ordered chronologically (by input position): plain std::sort is
    // not stable, so the relative order of such ties used to depend on the sort
    // implementation — and libstdc++ (GCC) and libc++ (clang/Emscripten) order
    // them differently.  Breaking the tie on 'seq' makes the ordering total,
    // hence reproducible on any standard library, while keeping the original
    // log order for equal-keyed rows.
    std::sort(rows.begin(), rows.end(),
        [](const ReplayRow& a, const ReplayRow& b) {
            if (a.timestamp != b.timestamp) return a.timestamp < b.timestamp;
            if (a.conn != b.conn) return a.conn < b.conn;
            if (a.op != b.op) return a.op < b.op;
            return a.seq < b.seq;
        });

    auto scope_to_str = [](const std::string& s) -> std::string {
        if (s.empty()) return "";
        try {
            switch (std::stoi(s)) {
                case 0: return "base";
                case 1: return "one";
                case 2: return "sub";
                default: return s;
            }
        } catch (...) { return s; }
    };

    for (const auto& r : rows) {
        std::string timestamp = r.timestamp.empty() ? agg.firsttime : r.timestamp;
        std::string ts = timestamp;
        if (output_date_format != "preserve") {
            auto tp = parse_any_timestamp(timestamp);
            if (tp != SystemTimePoint{}) {
                ts = format_timestamp(tp, output_date_format);
            }
        }
        std::ostringstream out;
        out << ts << sep;
        out << r.conn << sep;
        out << r.op << sep;
        out << r.type << sep;
        out << r.base << sep;
        out << r.filter << sep;
        out << r.attrs << sep;
        out << scope_to_str(r.scope) << sep;
        out << r.deref << sep;
        out << r.binddn << sep;
        out << r.authcid << sep;
        out << r.authzid << sep;
        out << r.err << sep;
        out << fmt_double(r.etime) << sep;
        out << r.qtime << sep;
        out << r.nentries << sep;
        out << r.text;
        std::cout << out.str() << "\n";
    }
}
