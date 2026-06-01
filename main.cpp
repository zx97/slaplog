// main.cpp

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
// This file is the CLI entry point for the OpenLDAP log analysis tool (slaplog).
// It handles argument parsing, input file collection (both flat and recursive
// directory traversal with deduplication), and orchestrates parallel log
// processing using a thread-per-file model. A progress bar thread provides
// real-time feedback on stderr. After all threads complete, per-thread
// aggregators are merged and the final report is printed in the requested
// format (text, textcolor, html, or json).

// log_parser.hpp     -- Core log parsing logic: process_file() and Aggregator struct
#include "log_parser.hpp"
// report.hpp         -- Report printers: print_text_report(), print_json_report(), print_html_report()
#include "report.hpp"
// utils.hpp          -- Shared utility functions (merge_aggregators, etc.)
#include "utils.hpp"
// embedded.hpp       -- Embedded LICENSE and documentation text
#include "embedded.hpp"

#include <iostream>       // std::cerr, std::cout for CLI output and progress bar
#include <vector>         // std::vector for storing file lists and thread handles
#include <string>         // std::string for path and argument handling
#include <atomic>         // std::atomic for lock-free progress tracking across threads
#include <thread>         // std::thread for parallel file processing and progress bar
#include <filesystem>     // std::filesystem for directory iteration and file queries
#include <chrono>         // std::chrono for timing and progress-thread sleep
#include <mutex>          // std::mutex (included for completeness; not directly used here)
#include <sys/stat.h>     // POSIX stat (included for potential future file checks)
#include <iomanip>        // std::setprecision, std::fixed for progress-bar formatting
#include <algorithm>      // std::transform for case-insensitive filename matching
#include <set>            // std::set for deduplicating input files
#include <fstream>        // std::ofstream for writing unknown-lines output file
#include <memory>         // std::shared_ptr etc. (available for smart pointer usage)
#include <ostream>        // std::ostream base class
#include <sstream>        // std::istringstream for parsing comma-separated --section values
#include <regex>          // std::regex (included for potential regex-based filtering)
#include <unistd.h>       // isatty() — auto-disable progress bar / colors on non-TTY

#define SLAPLOG_VERSION "3.1.0"
#ifndef BUILD_NUMBER
#define BUILD_NUMBER 0
#endif
#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)
#define SLAPLOG_BUILD __DATE__ " " __TIME__ " build " STRINGIFY(BUILD_NUMBER)

namespace fs = std::filesystem;

// print_progress
//
// Displays a command-line progress bar on stderr using a carriage-return (\r)
// to overwrite the current line. The bar shows:
//   - A 50-character progress bar with = segments and a > head
//   - Percentage complete (one decimal place)
//   - MB processed out of total MB (total_size)
//   - Files processed out of total files (files_done / total_files)
//
// Both progress and files_done are atomic because they are updated from
// worker threads and read from the progress thread without synchronization.
// The file sizes are read up front (before any processing), so total_size
// may over-estimate progress for compressed or sparse logs; but on average
// it gives a smooth visual indicator.
void print_progress(std::atomic<size_t>& progress, size_t total_size, 
                    std::atomic<size_t>& files_done, size_t total_files) {
    size_t current = progress.load();
    float percent = (total_size > 0) ? (100.0 * current / total_size) : 100.0;
    if (percent > 100.0) percent = 100.0;
    int bar_width = 50;

    std::cerr << "\r[";
    int pos = (int)(bar_width * percent / 100);
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) std::cerr << "=";
        else if (i == pos) std::cerr << ">";
        else std::cerr << " ";
    }
    std::cerr << "] " << std::fixed << std::setprecision(1) << percent << "% "
              << (current / (1024 * 1024)) << "/" << (total_size / (1024 * 1024)) << " MB"
              << " | Files: " << files_done.load() << "/" << total_files;
    std::cerr.flush();
}

// wanted_log_file
//
// Determines whether a given file path should be included in the analysis.
// The function applies the following inclusion criteria:
//   1. The path must be non-empty, a regular file, and have non-zero size.
//   2. Hidden files (starting with '.') are excluded.
//   3. Temporary / backup / editor swap files (~, .swp, .tmp, .bak, .old,
//      .disabled) are excluded via case-insensitive substring checks.
//   4. Inclusion requires at least one of these substrings in the filename:
//        - "slapd"
//        - "ldap"
//        - ".log"
static bool wanted_log_file(const std::string& path) {
    if (path.empty()) return false;
    if (!fs::is_regular_file(path)) return false;
    if (fs::file_size(path) == 0) return false;

    std::string base = fs::path(path).filename().string();
    std::string lower = base;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (!base.empty() && base[0] == '.') return false;
    if (lower.find("~") != std::string::npos) return false;
    if (lower.find(".swp") != std::string::npos) return false;
    if (lower.find(".tmp") != std::string::npos) return false;
    if (lower.find(".bak") != std::string::npos) return false;
    if (lower.find(".old") != std::string::npos) return false;
    if (lower.find(".disabled") != std::string::npos) return false;

    if (base.find("slapd") != std::string::npos || lower.find("slapd") != std::string::npos) return true;
    if (lower.find("ldap") != std::string::npos) return true;
    if (lower.find(".log") != std::string::npos) return true;

    return false;
}

// file_mtime_seconds
//
// Returns the last-modification time of a file expressed as seconds since the
// system_clock epoch.  std::filesystem::last_write_time returns a
// file_clock time_point whose epoch is unspecified, so it is converted to
// system_clock via the portable duration-based approach.  On any error the
// function returns 0 (epoch), which sorts the file as "oldest".
static long long file_mtime_seconds(const std::string& path) {
    std::error_code ec;
    auto ftime = fs::last_write_time(path, ec);
    if (ec) return 0;
    // Convert file_time_type to system_clock::time_point in a portable way.
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
    return std::chrono::duration_cast<std::chrono::seconds>(
        sctp.time_since_epoch()).count();
}

// collect_input_files
//
// Converts the raw command-line arguments (which may be individual files or
// directories) into a flat, deduplicated vector of log file paths.
//
// For each input path:
//   - If it is a regular file (with non-zero size), it is added directly.
//   - If it is a directory, the directory is scanned:
//       * When recursive == true, fs::recursive_directory_iterator is used
//         to walk all subdirectories.
//       * When recursive == false, only the top-level entries are inspected.
//       * Each entry is checked via wanted_log_file() before being added.
//
// Deduplication is achieved by inserting paths into a std::set first, then
// converting the set to a vector at the end. This handles the case where
// the same file is specified multiple times or discovered via both explicit
// path and directory traversal.
//
// Time-based filtering and limiting:
//   - mtime_days > 0    : keep only files modified within the last
//                         mtime_days * 24h (mirrors find(1) -mtime semantics
//                         in spirit: "modified in the last N days").
//   - max_files > 0     : after sorting by modification time (newest first),
//                         keep only the max_files most recent files.
// When neither limit is active the result preserves the deduplicated,
// lexicographically-sorted order from the std::set.
static std::vector<std::string> collect_input_files(const std::vector<std::string>& inputs,
                                                    bool recursive,
                                                    int max_files,
                                                    int mtime_days) {
    std::set<std::string> uniq;
    for (const auto& path : inputs) {
        if (path.empty()) continue;
        std::error_code ec;
        if (fs::is_regular_file(path, ec)) {
            if (!ec && fs::file_size(path, ec) > 0) uniq.insert(path);
            continue;
        }
        if (!fs::is_directory(path, ec) || ec) continue;
        if (recursive) {
            for (auto const& entry : fs::recursive_directory_iterator(path)) {
                if (!entry.is_regular_file()) continue;
                std::string full = entry.path().string();
                if (wanted_log_file(full)) uniq.insert(full);
            }
        } else {
            for (auto const& entry : fs::directory_iterator(path)) {
                if (!entry.is_regular_file()) continue;
                std::string full = entry.path().string();
                if (wanted_log_file(full)) uniq.insert(full);
            }
        }
    }

    std::vector<std::string> result(uniq.begin(), uniq.end());

    // If no time-based filtering or limiting is requested, return early to
    // preserve the existing (lexicographically-sorted) behaviour.
    if (max_files <= 0 && mtime_days <= 0) {
        return result;
    }

    // Pair each file with its modification time so we can filter / sort.
    std::vector<std::pair<std::string, long long>> with_mtime;
    with_mtime.reserve(result.size());
    for (const auto& f : result) {
        with_mtime.emplace_back(f, file_mtime_seconds(f));
    }

    // mtime filtering: drop files older than the cutoff (now - mtime_days).
    if (mtime_days > 0) {
        long long now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        long long cutoff = now - static_cast<long long>(mtime_days) * 24 * 60 * 60;
        std::vector<std::pair<std::string, long long>> filtered;
        for (const auto& p : with_mtime) {
            if (p.second >= cutoff) filtered.push_back(p);
        }
        with_mtime.swap(filtered);
    }

    // max_files limiting: sort newest-first and keep the top N.
    if (max_files > 0 && static_cast<int>(with_mtime.size()) > max_files) {
        std::sort(with_mtime.begin(), with_mtime.end(),
                  [](const std::pair<std::string, long long>& a,
                     const std::pair<std::string, long long>& b) {
                      return a.second > b.second;  // newest first
                  });
        with_mtime.resize(max_files);
    }

    // Re-sort the surviving files lexicographically for stable, predictable
    // processing order (matches the non-filtered code path).
    std::vector<std::string> out;
    out.reserve(with_mtime.size());
    for (const auto& p : with_mtime) out.push_back(p.first);
    std::sort(out.begin(), out.end());
    return out;
}

// usage
//
// Prints the help text describing all available CLI options:
//
//   -o, --output FORMAT        Select output format: text, textcolor, html, or json.
//   -c, --compact              Limit lists to top 5 instead of the default top 20.
//   -r, --recursive            Recurse into subdirectories when scanning directories.
//   -q, --quiet                Suppress the progress bar (batch / non-interactive use).
//   -n, --max-files N          Analyze only the N most recently modified files.
//   -m, --mtime DAYS           Analyze only files modified within the last DAYS days.
//   -s, --section LIST         Comma-separated list of report sections to include.
//   --unknown-lines FILE       Write unparseable log lines to a file, then generate report.
//   --unknown-lines-only FILE  Same as above but skip the final report (extraction mode).
//   -d, --debug                Enable verbose diagnostic output.
//   -D, --documentation        Print the documentation to stdout and exit.
//   -h, --help                 Display this help message and exit.
//   -V, --version              Display version information and exit.
static void usage(const char* prog) {
    std::cerr << prog << " - an OpenLDAP Log Analyzer v" << SLAPLOG_VERSION << "\n";
    std::cerr << "Copyright (c) 2026 Manuel FLURY\n";
    std::cerr << "License: GNU Affero General Public License v3.0 or later (https://www.gnu.org/licenses/agpl-3.0.html)\n";
    std::cerr << "Usage: " << prog << " [options] <logfile|directory> [file|dir ...]\n";
    std::cerr << "Options:\n";
    std::cerr << "  -o, --output FORMAT        Output format: text | textcolor | html | json\n";
    std::cerr << "  -c, --compact              Compact output (top 5 instead of top 20)\n";
    std::cerr << "  -r, --recursive            Recurse into directories\n";
    std::cerr << "  -q, --quiet                Suppress the progress bar (batch mode)\n";
    std::cerr << "  -n, --max-files N          Analyze only the N most recently modified files\n";
    std::cerr << "  -m, --mtime DAYS           Analyze only files modified in the last DAYS days\n";
    std::cerr << "  -j, --jobs N               Worker threads (default: CPU cores - 1)\n";
    std::cerr << "  -s, --section LIST         Sections to show (comma-sep): all,\n";
    std::cerr << "                             stats,ops,errors,errors_per_app,\n";
    std::cerr << "                             bases,filters,wildcards,\n";
    std::cerr << "                             filters_per_app,attrs,apps,extops,\n";
    std::cerr << "                             qmark,csn,server,index,sessions,\n";
    std::cerr << "                             topops,topconns\n";
    std::cerr << "  --unknown-lines FILE       Write unknown lines to FILE\n";
    std::cerr << "  --unknown-lines-only FILE  Like --unknown-lines, no final report\n";
    std::cerr << "  -D, --documentation        Print documentation to stdout\n";
    std::cerr << "  -l, --licence              Print license to stdout\n";
    std::cerr << "  -d, --debug                Enable debug mode with verbose traces\n";
    std::cerr << "  -h, --help                 Show this help\n";
    std::cerr << "  -V, --version              Show version\n";
}

static int print_licence() {
    std::cout << embedded::LICENSE_TEXT;
    return 0;
}

static int print_documentation() {
    std::cout << embedded::DOCUMENTATION_TEXT;
    return 0;
}

int main(int argc, char* argv[]) {
    // ------------------------------------------------------------------
    // If no arguments are given, show usage and exit with an error code.
    // ------------------------------------------------------------------
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    // ------------------------------------------------------------------
    // Declare option variables with their defaults.
    //
    // inputs              -- positional arguments (files / directories)
    // recursive           -- whether to traverse directories recursively
    // output_format       -- "text", "textcolor" (default), "html", "json"
    // compact_mode        -- if true, show top 5 instead of top 20
    // unknown_lines_file  -- path for writing unparseable lines (empty = disabled)
    // unknown_lines_only  -- if true, skip the final report after writing unknowns
    // debug               -- enable extra diagnostic output on stderr
    // color_mode          -- 0 = plain text, 2 = ANSI color (derived from output_format)
    // enabled_sections    -- set of report sections; defaults to {"all"}
    // ------------------------------------------------------------------
    std::vector<std::string> inputs;
    bool recursive = false;
    std::string output_format = "textcolor";
    bool compact_mode = false;
    std::string unknown_lines_file;
    bool unknown_lines_only = false;
    bool show_documentation = false;
    bool show_licence = false;
    bool debug = false;
    bool quiet = false;        // -q/--quiet: suppress the progress bar
    int max_files = 0;         // --max-files N: keep N most recent files (0 = unlimited)
    int mtime_days = 0;        // --mtime DAYS: keep files from last DAYS days (0 = no limit)
    int jobs = 0;              // -j N: worker thread count (0 = auto: hw_concurrency - 1)
    int color_mode = 2;
    std::set<std::string> enabled_sections = {"all"};

    // ------------------------------------------------------------------
    // Argument parsing loop.
    //
    // Iterates over argv[1..argc-1] and dispatches each flag.  Flags with
    // a required value (--output, --section, --unknown-lines,
    // --unknown-lines-only) consume the next argument.  Everything that
    // is not a recognised flag is treated as an input path.
    // ------------------------------------------------------------------
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            output_format = argv[++i];
            if (output_format == "text") { color_mode = 0; }
            else if (output_format == "textcolor") { color_mode = 2; }
        } else if (arg == "-c" || arg == "--compact") {
            compact_mode = true;
        } else if (arg == "-r" || arg == "--recursive") {
            recursive = true;
        } else if (arg == "-q" || arg == "--quiet") {
            quiet = true;
        } else if ((arg == "-n" || arg == "--max-files") && i + 1 < argc) {
            // Keep only the N most recently modified files in a directory scan.
            try {
                max_files = std::stoi(argv[++i]);
            } catch (const std::exception&) {
                std::cerr << "Error: invalid value for " << arg << " (expected integer)\n";
                return 1;
            }
            if (max_files < 0) max_files = 0;
        } else if ((arg == "-m" || arg == "--mtime") && i + 1 < argc) {
            try {
                mtime_days = std::stoi(argv[++i]);
            } catch (const std::exception&) {
                std::cerr << "Error: invalid value for " << arg << " (expected integer)\n";
                return 1;
            }
            if (mtime_days < 0) mtime_days = 0;
        } else if ((arg == "-j" || arg == "--jobs") && i + 1 < argc) {
            try {
                jobs = std::stoi(argv[++i]);
            } catch (const std::exception&) {
                std::cerr << "Error: invalid value for " << arg << " (expected integer)\n";
                return 1;
            }
            if (jobs < 1) { std::cerr << "Error: " << arg << " must be >= 1\n"; return 1; }
        } else if ((arg == "-s" || arg == "--section") && i + 1 < argc) {
            // When --section is used, the default "all" is removed from the
            // set so that only the explicitly requested sections are shown.
            enabled_sections.erase("all");
            std::string val = argv[++i];
            std::istringstream iss(val);
            std::string tok;
            while (std::getline(iss, tok, ',')) {
                if (!tok.empty()) enabled_sections.insert(tok);
            }
        } else if (arg == "--unknown-lines" && i + 1 < argc) {
            unknown_lines_file = argv[++i];
        } else if (arg == "--unknown-lines-only" && i + 1 < argc) {
            unknown_lines_file = argv[++i];
            unknown_lines_only = true;
        } else if (arg == "-D" || arg == "--documentation") {
            show_documentation = true;
        } else if (arg == "-l" || arg == "--licence") {
            show_licence = true;
        } else if (arg == "-d" || arg == "--debug") {
            debug = true;
        } else if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            return 0;
        } else if (arg == "-V" || arg == "--version") {
            std::cout << "slaplog v" << SLAPLOG_VERSION << " (built " << SLAPLOG_BUILD << ") - an OpenLDAP log Analyzer\n";
            std::cout << "Copyright (c) 2026 Manuel FLURY\n";
            std::cout << "License: GNU Affero General Public License v3.0 or later\n";
            return 0;
        } else {
            inputs.push_back(arg);
        }
    }

    // ------------------------------------------------------------------
    // Auto-detect non-TTY output.
    //
    // When stderr is not a terminal (e.g. piped to a file or running in
    // cron / systemd), suppress the progress bar automatically so that
    // log files don't get filled with \r-based noise.
    //
    // When stdout is not a terminal, the default textcolor format drops
    // ANSI colour codes so the report is readable when redirected.
    // An explicit -o textcolor still forces colour regardless.
    // ------------------------------------------------------------------
    if (!isatty(STDERR_FILENO) && !quiet) {
        // User did not explicitly pass --quiet; auto-silence the bar.
        quiet = true;
    }
    if (!isatty(STDOUT_FILENO) && output_format == "textcolor") {
        output_format = "text";
        color_mode = 0;
    }

    // ------------------------------------------------------------------
    // Generation-only flags: --documentation / --licence.
    // When active, print the requested content to stdout and exit early
    // without requiring input files or generating a report.
    // ------------------------------------------------------------------
    if (show_documentation) {
        return print_documentation();
    }
    if (show_licence) {
        return print_licence();
    }

    // ------------------------------------------------------------------
    // Validate input: at least one file or directory must be provided.
    // ------------------------------------------------------------------
    if (inputs.empty()) {
        std::cerr << "Error: No input files specified\n";
        return 1;
    }

    // ------------------------------------------------------------------
    // File collection: expand directories into individual log files.
    // ------------------------------------------------------------------
    auto files = collect_input_files(inputs, recursive, max_files, mtime_days);
    if (files.empty()) {
        std::cerr << "Error: No valid log files found\n";
        return 1;
    }

    if (debug) {
        std::cerr << "Found " << files.size() << " log files\n";
    }

    // ------------------------------------------------------------------
    // Pre-compute total file size for progress-bar estimation.
    // ------------------------------------------------------------------
    size_t total_size = 0;
    for (const auto& f : files) {
        std::error_code ec;
        auto size = fs::file_size(f, ec);
        if (!ec) total_size += size;
    }

    // ------------------------------------------------------------------
    // Set up the unknown-lines output.
    //
    // When --unknown-lines (or --unknown-lines-only) is active we open the
    // output file now and pass the stream directly to worker threads via
    // update_aggregator().  Unparseable lines are written as they are
    // encountered instead of being stored in the Aggregator's unknown_lines
    // vector — this keeps memory usage bounded regardless of input size.
    // ------------------------------------------------------------------
    std::ofstream unknown_stream;
    std::mutex unknown_mtx;
    if (!unknown_lines_file.empty()) {
        unknown_stream.open(unknown_lines_file);
        if (!unknown_stream) {
            std::cerr << "Error: cannot open " << unknown_lines_file << "\n";
            return 1;
        }
    }
    std::ostream* unknown_out = unknown_stream.is_open() ? &unknown_stream : nullptr;
    std::mutex* unknown_mtx_ptr = unknown_out ? &unknown_mtx : nullptr;

    // ------------------------------------------------------------------
    // Aggregator and worker orchestration.
    //
    // We maintain a single final_agg that accumulates results from ALL
    // files.  Each worker thread creates a private local Aggregator for
    // its file, processes it, then merges into final_agg under a mutex
    // before destroying the local copy.  This keeps peak memory at
    //   size_of(final_agg) + num_workers × size_of(one_file_agg)
    // instead of holding N-file-sized Aggregators until a separate merge
    // phase.  The per-connection working maps (conn_state etc.) are
    // cleared on every merge so they only live for one file at a time.
    // ------------------------------------------------------------------
    Aggregator final_agg;
    std::mutex merge_mtx;
    std::atomic<size_t> progress(0);
    std::atomic<size_t> files_done(0);
    auto start_time = std::chrono::system_clock::now();

    // ------------------------------------------------------------------
    // Progress bar thread.
    //
    // Polls files_done every 100 ms and calls print_progress to update a
    // single-line bar on stderr.  After all files are processed the final
    // bar is printed followed by a newline so subsequent output starts on
    // a fresh line.
    // ------------------------------------------------------------------
    // When --quiet is active the progress thread is not started at all, so the
    // bar never appears on stderr (useful for batch/cron runs and log capture).
    std::thread progress_thread;
    if (!quiet) {
        progress_thread = std::thread([&]() {
            while (files_done.load() < files.size()) {
                print_progress(progress, total_size, files_done, files.size());
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            print_progress(progress, total_size, files_done, files.size());
            std::cerr << "\n";
        });
    }

    // ------------------------------------------------------------------
    // Worker threads: bounded thread pool.
    //
    // Spawning one thread per file is the simplest model and works well
    // for a handful of files.  On large directories with hundreds of
    // files, however, it creates resource pressure (memory, fd limits)
    // that can lead to allocation failures and std::terminate.
    //
    // Instead we cap the pool at a configurable concurrency level
    // (-j / --jobs, default hardware_concurrency - 1, at least 1),
    // and farm out files via an atomic work-stealing index.
    //
    // Memory-adaptive throttling:
    // Before picking up a new file, each worker checks the system's
    // available memory (via /proc/meminfo).  If it drops below a
    // threshold (12.5% of total RAM) the worker waits a few seconds
    // before proceeding.  This gives active workers time to finish
    // and free their per-file Aggregator, preventing OOM crashes.
    // ------------------------------------------------------------------

    // Returns available memory in megabytes by parsing /proc/meminfo.
    // Returns a large dummy value on non-Linux or if the file cannot
    // be read, so throttling is simply not applied.
    static auto available_memory_mb = []() -> long long {
        std::ifstream meminfo("/proc/meminfo");
        if (!meminfo) return 32768;
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.compare(0, 12, "MemAvailable:") == 0) {
                long long val = 0;
                std::sscanf(line.c_str() + 12, "%lld", &val);
                return val / 1024;
            }
        }
        return 32768;
    };
    // Threshold: throttle when available memory drops below 12.5% of total
    // (read from /proc/meminfo MemTotal).  This scales with the machine:
    // ~1 GB on 8 GB host, ~8 GB on 64 GB host, etc.
    static auto mem_threshold_mb = []() -> long long {
        std::ifstream meminfo("/proc/meminfo");
        if (!meminfo) return 1024;
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.compare(0, 8, "MemTotal:") == 0) {
                long long val = 0;
                std::sscanf(line.c_str() + 8, "%lld", &val);
                return val / 1024 / 8;  // 12.5 % of total, in MB
            }
        }
        return 1024;
    }();
    size_t num_workers;
    if (jobs > 0) {
        num_workers = static_cast<size_t>(jobs);
    } else {
        num_workers = std::thread::hardware_concurrency();
        if (num_workers > 1) num_workers -= 1;  // leave one core free
        if (num_workers == 0) num_workers = 1;
    }
    if (num_workers > files.size()) num_workers = files.size();

    if (debug) {
        std::cerr << "Total size: " << (total_size / (1024*1024)) << " MB\n";
        if (mtime_days > 0) std::cerr << "Mtime filter: last " << mtime_days << " days\n";
        if (max_files > 0) std::cerr << "Max files: " << max_files << "\n";
        std::cerr << "Workers: " << num_workers << " (hw_concurrency="
                  << std::thread::hardware_concurrency() << ")\n";
        std::cerr << "Memory threshold: " << mem_threshold_mb << " MB ("
                  << (mem_threshold_mb * 100 / (mem_threshold_mb * 8)) << "% of total)\n";
        if (unknown_out)
            std::cerr << "Unknown lines: streaming to " << unknown_lines_file << "\n";
        else
            std::cerr << "Unknown lines: in-memory (capped at " << MAX_STORED_UNKNOWN_LINES << ")\n";
    }

    std::vector<std::thread> workers(num_workers);
    std::atomic<size_t> next_file(0);

    for (auto& t : workers) {
        t = std::thread([&]() {
            for (;;) {
                size_t i;
                // Memory-adaptive throttling: before picking up more work,
                // wait if the system is running low on available memory.
                for (int tries = 0; tries < 10; ++tries) {
                    if (available_memory_mb() >= mem_threshold_mb) break;
                    if (debug && tries == 0) {
                        std::lock_guard<std::mutex> lock(merge_mtx);
                        std::cerr << "[debug] Memory low (" << available_memory_mb()
                                  << " MB < " << mem_threshold_mb << " MB), throttling\n";
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
                try {
                    i = next_file.fetch_add(1, std::memory_order_relaxed);
                    if (i >= files.size()) break;
                    if (debug) {
                        std::lock_guard<std::mutex> lock(merge_mtx);
                        std::cerr << "[debug] Processing " << files[i] << " ("
                                  << (i + 1) << "/" << files.size() << ")\n";
                    }
                    Aggregator local_agg;
                    process_file(files[i], local_agg, progress,
                                 unknown_out, unknown_mtx_ptr);
                    {
                        std::lock_guard<std::mutex> lock(merge_mtx);
                        merge_aggregators(final_agg, local_agg);
                    }
                } catch (const std::exception& e) {
                    std::cerr << "\nError processing " << files[i] << ": "
                              << e.what()
                              << "\nTry -m DAYS or -n FILES to limit scope, "
                                 "or use --unknown-lines-only.\n";
                    if (debug) {
                        long long mem = available_memory_mb();
                        std::lock_guard<std::mutex> lock(merge_mtx);
                        std::cerr << "[debug] Memory: " << mem << " MB free (threshold: "
                                  << mem_threshold_mb << " MB), workers: "
                                  << num_workers << "\n";
                    }
                    // Mark this file as done so the progress bar advances
                    // even on failure, then continue to the next file.
                    files_done++;
                    continue;
                } catch (...) {
                    std::cerr << "\nUnknown error processing " << files[i] << "\n";
                    files_done++;
                    continue;
                }
                files_done++;
            }
        });
    }

    // ------------------------------------------------------------------
    // Wait for all worker threads to finish, then join the progress thread.
    // ------------------------------------------------------------------
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }

    // Ensure the progress thread exits even if some workers aborted
    // before reaching files_done == files.size().
    files_done.store(files.size());

    if (progress_thread.joinable()) progress_thread.join();

    // ------------------------------------------------------------------
    // Calculate elapsed wall-clock time for the report footer.
    // ------------------------------------------------------------------
    auto end_time = std::chrono::system_clock::now();
    double duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count() / 1000.0;

    // ------------------------------------------------------------------
    // Discard per-connection working maps.
    //
    // These are only used during parsing (update_aggregator) and are NOT
    // referenced by any report printer.  They are overwritten on every
    // merge (so they only hold data from the last file), but we clear
    // them here for good measure before the report phase.
    // ------------------------------------------------------------------
    final_agg.conn_state.clear();
    final_agg.binddn_by_conn.clear();
    final_agg.src_by_conn.clear();

    // ------------------------------------------------------------------
    // Unknown lines output.
    //
    // If --unknown-lines or --unknown-lines-only was specified, write every
    // unparseable line from the combined Aggregator to a text file.
    // If --unknown-lines-only is active, the program exits early without
    // producing a report; otherwise it continues to report generation so
    // the unknowns file serves as supplementary data alongside the report.
    // ------------------------------------------------------------------
    if (!unknown_lines_file.empty()) {
        if (unknown_out) {
            // Direct-to-file mode: unknown lines were already written by
            // worker threads during processing.  Close the stream and
            // report the total count from the accurate statistic.
            unknown_stream.close();
            std::cerr << "Wrote " << final_agg.stats.unknown_lines << " unknown lines to "
                      << unknown_lines_file << "\n";
        } else {
            // In-memory mode: write the saved lines from final_agg now.
            std::ofstream ofs(unknown_lines_file);
            if (ofs) {
                for (const auto& line : final_agg.unknown_lines) {
                    ofs << line << "\n";
                }
                std::cerr << "Wrote " << final_agg.unknown_lines.size() << " unknown lines to "
                          << unknown_lines_file;
                if (final_agg.unknown_lines.size() < static_cast<size_t>(final_agg.stats.unknown_lines))
                    std::cerr << " (" << (final_agg.stats.unknown_lines - final_agg.unknown_lines.size())
                              << " omitted, see --help about unknown-lines memory limit)";
                std::cerr << "\n";
            } else {
                std::cerr << "Error: cannot write " << unknown_lines_file << "\n";
            }
        }
        // Free the raw text now — not needed for the report (in-memory mode
        // cleared above; direct mode was already empty).
        final_agg.unknown_lines.clear();
        final_agg.unknown_lines.shrink_to_fit();
        if (unknown_lines_only) {
            std::cerr << "Scan completed in " << duration << " s\n";
            return 0;
        }
    }

    // ------------------------------------------------------------------
    // Report generation.
    //
    // Dispatch to the appropriate printer based on the --output format:
    //   - textcolor  -> print_text_report()   with color_mode=2 (ANSI)
    //   - json       -> print_json_report()
    //   - html       -> print_html_report()
    //   - text       -> print_text_report()   with color_mode=0 (no colour)
    // ------------------------------------------------------------------
    try {
        if (output_format == "textcolor") {
            print_text_report(final_agg, duration, compact_mode, 2, enabled_sections);
        } else if (output_format == "json") {
            print_json_report(final_agg, duration, compact_mode);
        } else if (output_format == "html") {
            print_html_report(final_agg, duration, compact_mode);
        } else {
            print_text_report(final_agg, duration, compact_mode, color_mode, enabled_sections);
        }
    } catch (const std::exception& e) {
        std::cerr << "\nFatal error during report generation: " << e.what()
                  << "\nThe data was too large to format in the requested "
                     "output mode.\n";
        return 1;
    }

    return 0;
}
