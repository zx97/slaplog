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
#include "log_parser.hpp"
#include "utils.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <map>
#include <set>
#include <tuple>
#include <type_traits>
#include <nlohmann/json.hpp>

#ifndef SLAPLOG_VERSION
#define SLAPLOG_VERSION "3.1.0"
#endif

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
    std::string format_time(std::chrono::system_clock::time_point tp) {
        auto in_time_t = std::chrono::system_clock::to_time_t(tp);
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
void print_text_report(const Aggregator& agg, double processing_time, bool compact, int color_mode, const std::set<std::string>& sections) {
    set_color_output(color_mode);
    int limit = compact ? 5 : 20;

    auto has_section = [&](const std::string& name) {
        return sections.empty() || sections.count("all") || sections.count(name);
    };

    std::cout << COLOR_BOLD << COLOR_BLUE << "OpenLDAP Log Analysis Report" << COLOR_RESET << "\n";
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

    // Error counts
    // Shows LDAP result codes with their mnemonic names.
    // "Success" and other non-error codes (compareTrue, referral, etc.)
    // are coloured green; all others are red.
    if (has_section("errors")) {
        print_separator("Error Counts");
        auto error_sorted = sort_map_by_value_desc(agg.error_count);
        std::vector<std::vector<std::string>> error_rows;
        for (const auto& [code, count] : error_sorted) {
            auto it = LDAP_ERRORS.find(code);
            std::string name = (it != LDAP_ERRORS.end()) ? it->second : "unknown";
            std::string code_str = fmt_int(code);
            if (color_mode >= 1) {
                bool ok = (code == 0 || code == 5 || code == 6 || code == 10 || code == 14);
                std::string c = ok ? COLOR_GREEN : COLOR_RED;
                code_str = c + code_str + COLOR_RESET;
                name = c + name + COLOR_RESET;
            }
            error_rows.push_back({code_str, name, fmt_int(count)});
        }
        print_table({"Code", "Name", "Count"}, error_rows);
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
                auto it = LDAP_ERRORS.find(code);
                std::string name = (it != LDAP_ERRORS.end()) ? it->second : "unknown";
                std::string code_str = fmt_int(code);
                if (color_mode >= 1) {
                    bool ok = (code == 0 || code == 5 || code == 6 || code == 10 || code == 14);
                    std::string c = ok ? COLOR_GREEN : COLOR_RED;
                    code_str = c + code_str + COLOR_RESET;
                    name = c + name + COLOR_RESET;
                }
                err_rows.push_back({app_name, code_str, name, fmt_int(cnt)});
            }
        }
        print_table({"App", "Code", "Name", "Count"}, err_rows);
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
        std::set<std::tuple<std::string,std::string,std::string,std::string,std::string>> seen;
        std::vector<std::vector<std::string>> st_rows;
        for (const auto& [key, corr] : agg.session_correlations) {
            auto tup = std::make_tuple(corr.accept_ip, corr.real_ip, corr.name,
                                       corr.username, corr.binddn);
            if (seen.insert(tup).second) {
                st_rows.push_back({
                    corr.accept_ip,
                    corr.real_ip,
                    corr.name,
                    corr.username,
                    corr.binddn
                });
            }
        }
        if (!st_rows.empty()) {
            print_table({"ACCEPT IP", "Real IP", "Name", "Username", "BIND dn"}, st_rows);
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
            std::vector<std::vector<std::string>> top_conn_rows;
            for (const auto& r : agg.top_conns) {
                std::string etime_str = fmt_double(r.total_etime);
                if (color_mode >= 2) etime_str = fmt_etime(r.total_etime);
                top_conn_rows.push_back({
                    etime_str,
                    std::to_string(r.conn),
                    r.who,
                    r.src,
                    std::to_string(r.ops_count),
                    r.binddn
                });
            }
            print_table({"total etime", "conn", "who", "src", "ops", "binddn"}, top_conn_rows);
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
void print_html_report(const Aggregator& agg, double duration, bool /*compact*/) {
    auto etime_color = [](double v) -> std::string {
        if (v > 5.0) return "color:#ff4444;font-weight:bold";
        if (v > 1.0) return "color:#cc0000";
        if (v > 0.5) return "color:#ccaa00";
        if (v > 0.1) return "color:#00aaaa";
        return "color:#00aa00";
    };

    auto err_color = [](int code) -> std::string {
        bool ok = (code == 0 || code == 5 || code == 6 || code == 10 || code == 14);
        return ok ? "color:#00aa00" : "color:#cc0000";
    };

    auto gradient_ratio = [](long long val, long long maxv) -> std::string {
        if (maxv <= 0) return "color:#00aa00";
        double r = static_cast<double>(val) / maxv;
        if (r > 0.8) return "color:#ff4444;font-weight:bold";
        if (r > 0.5) return "color:#cc0000";
        if (r > 0.3) return "color:#ccaa00";
        return "color:#00aa00";
    };

    std::cout << "<!DOCTYPE html>\n";
    std::cout << "<html lang=\"en\">\n";
    std::cout << "<head>\n";
    std::cout << "<meta charset=\"UTF-8\">\n";
    std::cout << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    std::cout << "<title>LDAP Log Analysis Report</title>\n";
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
    std::cout << "</style>\n";
    std::cout << "</head>\n<body>\n";

    // Header
    std::cout << "<h1>OpenLDAP Log Analysis Report</h1>\n";

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
    std::cout << "<h2>Statistics</h2>\n";
    std::cout << "<table>\n";
    auto print_stat = [&](const std::string& label, const std::string& val) {
        std::cout << "<tr><td style=\"font-weight:600;color:#34495e;width:260px\">" << label << "</td><td>" << val << "</td></tr>\n";
    };
    print_stat("Processing time", fmt_double(duration) + " s");
    print_stat("Processing speed", fmt_int(static_cast<long long>(speed)) + " lines/s");
    print_stat("Lines processed", fmt_int(agg.stats.lines));
    print_stat("Unknown lines", fmt_int(agg.stats.unknown_lines));
    print_stat("Connections opened", fmt_int(agg.stats.conn_count));
    print_stat("FD open events", fmt_int(agg.stats.fd_open));
    print_stat("FD close events", fmt_int(agg.stats.fd_close));
    print_stat("Replication logs", fmt_int(agg.stats.replication_logs));
    print_stat("Peak active connections", fmt_int(agg.peak_active_connections));
    if (!agg.firsttime.empty()) print_stat("First timestamp", agg.firsttime);
    if (!agg.lasttime.empty()) print_stat("Last timestamp", agg.lasttime);
    print_stat("Total etime", "<span style=\"" + etime_color(agg.etime_total) + "\">" + fmt_double(agg.etime_total) + "</span>");
    print_stat("Total qtime", "<span style=\"" + etime_color(agg.qtime_total) + "\">" + fmt_double(agg.qtime_total) + "</span>");
    if (agg.maxetime.has_value()) {
        print_stat("Max operation etime", "<span style=\"" + etime_color(*agg.maxetime) + "\">" + fmt_double(*agg.maxetime) + "</span>");
        print_stat("Max operation user", agg.maxetimeusr);
    }
    if (agg.maxconnetime.has_value()) {
        print_stat("Max connection etime", "<span style=\"" + etime_color(*agg.maxconnetime) + "\">" + fmt_double(*agg.maxconnetime) + "</span>");
        print_stat("Max connection user", agg.maxconnetimeusr);
    }
    print_stat("Read operations", fmt_int(agg.read_write_stats.read));
    print_stat("Write operations", fmt_int(agg.read_write_stats.write));
    std::cout << "</table>\n";

    // Operation counts
    std::cout << "<h2>Operation Counts</h2>\n";
    std::cout << "<table>\n<tr><th>Operation</th><th>Count</th></tr>\n";
    for (const auto& [op, count] : agg.operation_count) {
        if (count > 0) std::cout << "<tr><td>" << op << "</td><td>" << count << "</td></tr>\n";
    }
    std::cout << "</table>\n";

    // Error counts
    std::cout << "<h2>Error Counts</h2>\n";
    std::cout << "<table>\n<tr><th>Code</th><th>Name</th><th>Count</th></tr>\n";
    auto error_sorted = sort_map_by_value_desc(agg.error_count);
    for (const auto& [code, count] : error_sorted) {
        auto it = LDAP_ERRORS.find(code);
        std::string name = (it != LDAP_ERRORS.end()) ? it->second : "unknown";
        std::cout << "<tr><td style=\"" << err_color(code) << "\">" << code << "</td>"
                  << "<td style=\"" << err_color(code) << "\">" << name << "</td>"
                  << "<td>" << count << "</td></tr>\n";
    }
    std::cout << "</table>\n";

    // Errors per application
    if (!agg.error_per_app.empty()) {
        std::cout << "<h2>Errors per Application</h2>\n";
        std::cout << "<table>\n<tr><th>App</th><th>Code</th><th>Name</th><th>Count</th></tr>\n";
        for (const auto& [app_name, errs] : agg.error_per_app) {
            auto sorted_errs = sort_map_by_value_desc(errs);
            for (const auto& [code, cnt] : sorted_errs) {
                auto it = LDAP_ERRORS.find(code);
                std::string name = (it != LDAP_ERRORS.end()) ? it->second : "unknown";
                std::cout << "<tr><td>" << app_name << "</td>"
                          << "<td style=\"" << err_color(code) << "\">" << code << "</td>"
                          << "<td style=\"" << err_color(code) << "\">" << name << "</td>"
                          << "<td>" << cnt << "</td></tr>\n";
            }
        }
        std::cout << "</table>\n";
    }

    // Top search bases
    auto print_h_count_table = [&](const std::string& title, const std::string& col1, const auto& m, int limit = 20) {
        if (m.empty()) return;
        std::cout << "<h2>" << title << "</h2>\n<table>\n<tr><th>" << col1 << "</th><th>Count</th></tr>\n";
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
        std::cout << "<h2>" << title << "</h2>\n<table>\n<tr><th>" << col1 << "</th><th>Total etime</th></tr>\n";
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

    // Filters per application
    // HTML version of the per-app filter table; count cells are coloured
    // with the same gradient ratio as the text version.
    if (!agg.filter_by_app.empty()) {
        std::cout << "<h2>Filters per Application</h2>\n<table>\n<tr><th>App</th><th>Filter</th><th>Count</th></tr>\n";
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
        std::cout << "<h2>Extended Operations</h2>\n<table>\n<tr><th>OID</th><th>Name</th><th>Count</th></tr>\n";
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
        std::cout << "<h2>Global Control Warnings</h2>\n<table>\n<tr><th>OID</th><th>Count</th></tr>\n";
        auto gc_sorted = sort_map_by_value_desc(agg.global_control_oid_count);
        for (const auto& [oid, count] : gc_sorted) {
            std::cout << "<tr><td>" << oid << "</td><td>" << count << "</td></tr>\n";
        }
        std::cout << "</table>\n";
    }

    // CSN events
    std::cout << "<h2>CSN Internal Events</h2>\n<table>\n<tr><th>Event</th><th>Count</th></tr>\n";
    std::cout << "<tr><td>CSN get</td><td>" << agg.csn_event_count.get << "</td></tr>\n";
    std::cout << "<tr><td>CSN queue</td><td>" << agg.csn_event_count.queue << "</td></tr>\n";
    std::cout << "<tr><td>CSN graduate</td><td>" << agg.csn_event_count.graduate << "</td></tr>\n";
    std::cout << "</table>\n";

    // Indexing diagnostics
    std::cout << "<h2>Indexing Diagnostics</h2>\n<table>\n";
    std::cout << "<tr><td style=\"font-weight:600\">Not indexed occurrences</td><td>" << agg.not_indexed_count << "</td></tr>\n";
    std::cout << "</table>\n";
    print_h_count_table("Not indexed attributes", "Attribute", agg.not_indexed_attr);

    // Question mark filters
    std::cout << "<h2>Question-mark Filters</h2>\n<table>\n";
    std::cout << "<tr><td style=\"font-weight:600\">Filters with (?attr=)</td><td>" << agg.qmark_filter_count << "</td></tr>\n";
    std::cout << "</table>\n";
    print_h_count_table("Question-mark filter attributes", "Attribute", agg.qmark_filter_attr_count);

    // Server events
    if (!agg.server_event_list.empty()) {
        std::cout << "<h2>Server Start / Stop Events</h2>\n<table>\n<tr><th>Timestamp</th><th>Event</th></tr>\n";
        for (const auto& [ts, event_type] : agg.server_event_list) {
            std::string cls = (event_type.find("start") != std::string::npos) ? "server-event-start" : "server-event-stop";
            std::cout << "<tr class=\"" << cls << "\"><td>" << ts << "</td><td>" << event_type << "</td></tr>\n";
        }
        std::cout << "</table>\n";
    }

    // Session tracking correlations
    if (!agg.session_correlations.empty()) {
        std::set<std::tuple<std::string,std::string,std::string,std::string,std::string>> seen;
        std::cout << "<h2>Session Tracking Correlations</h2>\n";
        std::cout << "<table>\n<tr><th>ACCEPT IP</th><th>Real IP</th><th>Name</th><th>Username</th><th>BIND dn</th></tr>\n";
        for (const auto& [key, corr] : agg.session_correlations) {
            auto tup = std::make_tuple(corr.accept_ip, corr.real_ip, corr.name,
                                       corr.username, corr.binddn);
            if (seen.insert(tup).second) {
                std::cout << "<tr><td>" << corr.accept_ip << "</td><td>" << corr.real_ip
                          << "</td><td>" << corr.name << "</td><td>" << corr.username
                          << "</td><td>" << corr.binddn << "</td></tr>\n";
            }
        }
        std::cout << "</table>\n";
    }

    // Top operations
    // The slowest individual operations, with elapsed-time colouring.
    std::cout << "<h2>Top Long Operations</h2>\n";
    std::cout << "<table>\n<tr><th>etime</th><th>conn</th><th>op</th><th>type</th><th>who</th><th>base</th><th>filter</th></tr>\n";
    for (const auto& r : agg.top_ops) {
        std::cout << "<tr><td style=\"" << etime_color(r.etime) << "\">" << fmt_double(r.etime) << "</td>"
                  << "<td>" << r.conn << "</td><td>" << r.op
                  << "</td><td>" << r.type << "</td><td>" << r.who
                  << "</td><td>" << r.base << "</td><td>" << r.filter << "</td></tr>\n";
    }
    std::cout << "</table>\n";

    // Top connections
    // Connections sorted by cumulative elapsed time.
    std::cout << "<h2>Top Connections by Cumulative etime</h2>\n";
    std::cout << "<table>\n<tr><th>total etime</th><th>conn</th><th>who</th><th>src</th><th>ops</th></tr>\n";
    for (const auto& r : agg.top_conns) {
        std::cout << "<tr><td style=\"" << etime_color(r.total_etime) << "\">" << fmt_double(r.total_etime) << "</td>"
                  << "<td>" << r.conn << "</td><td>" << r.who
                  << "</td><td>" << r.src << "</td><td>" << r.ops_count << "</td></tr>\n";
    }
    std::cout << "</table>\n";

    // Footer
    std::cout << "<div class=\"footer\">slaplog v" << SLAPLOG_VERSION << " &mdash; OpenLDAP Log Analysis Report</div>\n";
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
void print_json_report(const Aggregator& agg, double duration, bool /*compact*/) {
    json report;

    // Top-level scalar metrics
    report["processing_time"] = duration;
    report["lines"] = agg.stats.lines;
    report["unknown_lines"] = agg.stats.unknown_lines;
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
    // human-readable "name" and the "count".
    json errors = json::object();
    for (const auto& [code, count] : agg.error_count) {
        auto it = LDAP_ERRORS.find(code);
        std::string name = (it != LDAP_ERRORS.end()) ? it->second : "unknown";
        errors[std::to_string(code)] = {{"name", name}, {"count", count}};
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
