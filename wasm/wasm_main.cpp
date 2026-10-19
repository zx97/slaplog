// wasm/wasm_main.cpp
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// WebAssembly entry point for slaplog.
//
// WHY THIS FILE EXISTS
// --------------------
// The native CLI entry point (main.cpp) is intentionally left untouched by
// the WASM port.  main.cpp relies on std::thread (a browser can't use pthreads
// without SharedArrayBuffer + COOP/COEP headers) and peeks at the Linux-only
// /proc/meminfo.  Rather than sprinkle #ifdef __EMSCRIPTEN__ through it, the
// WASM build compiles THIS file instead of main.cpp.  It reuses the very same
// parser (log_parser.cpp) and report writers (report.cpp), unmodified.
//
// TWO APIs
// --------
//  1. One-shot, mirroring the CLI:
//         slaplog_run("-o html -q /work/a.log /work/b.log")
//
//  2. Session API, which is what the browser page uses so that it can show
//     progress and keep the tab responsive:
//         slaplog_begin("-o html -q")      // options only, no input files
//         slaplog_add_file("/work/a.log")  // one file (plain or compressed)
//         slaplog_add_text(ptr, len)       // one chunk of plain text
//         ...                              // any number of add calls, all
//                                          // aggregated into a single report
//         slaplog_end()                    // emit the report
//
//     Splitting a plain log into chunks at line boundaries and feeding them
//     through slaplog_add_text() yields exactly the same report as processing
//     the whole file in one go — the parser keeps no per-file state, only the
//     per-connection state carried in the Aggregator, which the session holds.
//
// DIFFERENCES FROM main.cpp
// -------------------------
//   - Single-threaded: files are processed sequentially.
//   - No isatty() probing, no /proc/meminfo, no progress bar.
//   - The report goes to stdout, which the page captures through Module.print.

#include "log_parser.hpp"
#include "report.hpp"
#include "state_io.hpp"
#include "version.hpp"

#include <emscripten.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

// Split a string on runs of whitespace, respecting quoted strings.
// The page may pass option values with spaces (e.g. --title "Acceptance - Proxy")
// which are quoted in the JavaScript buildArgs() function.
// This tokenizer respects double-quoted strings and escapes.
std::vector<std::string> split_whitespace(const std::string& s) {
    std::vector<std::string> out;
    std::string tok;
    bool in_quote = false;
    char quote_char = 0;
    
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (!in_quote) {
            if (c == '"' || c == '\'') {
                in_quote = true;
                quote_char = c;
            } else if (std::isspace(static_cast<unsigned char>(c))) {
                if (!tok.empty()) {
                    out.push_back(tok);
                    tok.clear();
                }
            } else {
                tok.push_back(c);
            }
        } else {
            if (c == quote_char) {
                in_quote = false;
                quote_char = 0;
            } else if (c == '\\' && i + 1 < s.size()) {
                // Handle escaped characters inside quotes
                char next = s[i + 1];
                if (next == '"' || next == '\'' || next == '\\') {
                    tok.push_back(next);
                    ++i;
                } else {
                    tok.push_back(c);
                }
            } else {
                tok.push_back(c);
            }
        }
    }
    if (!tok.empty()) out.push_back(tok);
    return out;
}

// Options shared by both APIs.  Mirrors the flag handling of main.cpp for the
// subset that applies in WASM (every flag keeps the same name and meaning).
struct Options {
    bool compact = false;
    bool no_graph = false;
    bool no_version = false;
    std::string output_format = "text";
    std::set<std::string> sections = {"all"};
    std::string log_format = "auto";
    std::string output_date_format = "rfc3339";
    std::string replay_separator = "|";
    int replay_limit = 1000000;
    std::string custom_title;
    std::string resume;      // state file to start from (--resume)
    std::vector<std::string> inputs;   // positional arguments
};

Options parse_options(const std::vector<std::string>& argv) {
    Options o;
    for (size_t i = 0; i < argv.size(); ++i) {
        const std::string& arg = argv[i];
        // Consume the following token as this option's value, if present.
        auto take_value = [&](std::string& dst) {
            if (i + 1 < argv.size()) dst = argv[++i];
        };

        if (arg == "-o" || arg == "--output") {
            take_value(o.output_format);
        } else if (arg == "-c" || arg == "--compact") {
            o.compact = true;
        } else if (arg == "--no-graph") {
            o.no_graph = true;
        } else if (arg == "--no-version") {
            o.no_version = true;
        } else if (arg == "--resume") {
            take_value(o.resume);
        } else if ((arg == "--title") && i + 1 < argv.size()) {
            take_value(o.custom_title);
        } else if (arg == "-s" || arg == "--section") {
            std::string val;
            take_value(val);
            o.sections.erase("all");
            std::istringstream iss(val);
            std::string tok;
            while (std::getline(iss, tok, ',')) {
                if (!tok.empty()) o.sections.insert(tok);
            }
        } else if (arg == "--log-format") {
            take_value(o.log_format);
        } else if (arg == "--output-date-format") {
            take_value(o.output_date_format);
        } else if (arg == "--replay-separator") {
            take_value(o.replay_separator);
        } else if (arg == "--replay-limit") {
            std::string val;
            take_value(val);
            try { o.replay_limit = std::stoi(val); }
            catch (const std::exception&) { o.replay_limit = 1000000; }
            if (o.replay_limit < 0) o.replay_limit = 0;
        } else if (arg == "-q" || arg == "--quiet") {
            // Always quiet in WASM: there is no terminal to draw onto.
        } else if (!arg.empty() && arg[0] == '-') {
            // Unknown flag: ignore rather than abort; the page may evolve
            // ahead of this binary.
        } else {
            o.inputs.push_back(arg);
        }
    }
    if (o.replay_separator == "tab") o.replay_separator = "\t";
    else if (o.replay_separator == "comma") o.replay_separator = ",";
    return o;
}

// A running analysis: one option set plus the aggregators it fills.
//
// Each input file is parsed into its own working Aggregator which is then
// merged into the running total — exactly what the native build does, where
// every worker thread owns a local Aggregator and merge_aggregators() folds it
// into the shared one.  Sharing a single Aggregator across files would be
// wrong: per-connection state (bound DN, open connection count) would leak
// from one file into the next, and the floating-point sums would round
// differently.
struct Session {
    Options opts;
    Aggregator total;            // accumulates the merged per-file results
    Aggregator current;          // working aggregator for the input in progress
    bool input_open = false;     // true between input_begin() and input_end()
    std::atomic<size_t> progress{0};   // bytes consumed so far
    std::chrono::system_clock::time_point start;
};

std::unique_ptr<Session> g_session;

void teardown_session() {
    if (!g_session) return;
    cleanup_replay_tempfile();
    g_session.reset();
}

bool start_session(Options opts) {
    teardown_session();   // drop any session left over from a previous run
    set_log_format(parse_log_format(opts.log_format));
    if (opts.output_format == "tab-html") opts.output_format = "tabhtml";
    // The charts need extra data collected while parsing.  Collect it whatever
    // the report format: the page can download a state file
    // (slaplog_save_state), and that state must support a later HTML report.
    // Only --no-graph turns the chart work off.
    set_collect_graph_data(!opts.no_graph);
    set_show_version(!opts.no_version);
    auto s = std::make_unique<Session>();
    s->start = std::chrono::system_clock::now();
    s->opts = std::move(opts);
    if (s->opts.output_format == "replay") {
        init_replay_tempfile();
        set_replay_ops_limit(s->opts.replay_limit);
    }
    g_session = std::move(s);
    if (!g_session->opts.resume.empty()) {
        std::string err;
        if (!load_state(g_session->total, g_session->opts.resume, err)) {
            std::cerr << "slaplog(wasm): cannot resume: " << err << "\n";
            teardown_session();
            return false;
        }
    }
    return true;
}

// Open a new input: fold any previous one into the total and start a fresh
// working aggregator.
void begin_input() {
    if (g_session->input_open) {
        merge_aggregators(g_session->total, g_session->current);
    }
    g_session->current = Aggregator{};
    g_session->input_open = true;
}

// Close the current input and fold it into the total.
void end_input() {
    if (!g_session->input_open) return;
    merge_aggregators(g_session->total, g_session->current);
    g_session->current = Aggregator{};
    g_session->input_open = false;
}

// Feed a block of plain text to the parser, one line at a time.  This mirrors
// process_plain_file() exactly: '\n' terminates a line, '\r' is kept, and a
// final line without a trailing newline is processed too.  Callers must split
// only at line boundaries so that a line is never broken across two calls.
size_t feed_text(const char* data, size_t len) {
    if (!g_session->input_open) begin_input();
    size_t lines = 0;
    const char* end = data + len;
    const char* start = data;
    for (const char* p = data; p < end; ++p) {
        if (*p == '\n') {
            std::string line(start, static_cast<size_t>(p - start));
            Event ev = parse_line(line);
            update_aggregator(g_session->current, ev, nullptr, nullptr);
            g_session->progress += line.size() + 1;
            ++lines;
            start = p + 1;
        }
    }
    if (start < end) {
        std::string line(start, static_cast<size_t>(end - start));
        Event ev = parse_line(line);
        update_aggregator(g_session->current, ev, nullptr, nullptr);
        g_session->progress += line.size() + 1;
        ++lines;
    }
    return lines;
}

int emit_report() {
    end_input();   // fold the last input in, if the caller forgot
    Session& s = *g_session;
    auto end_time = std::chrono::system_clock::now();
    double duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end_time - s.start)
            .count() / 1000.0;

    // Same teardown order as main.cpp: flush in-flight ops for the replay
    // format, then drop the per-connection working maps (unused by reports).
    if (s.opts.output_format == "replay") {
        flush_inflight_ops(s.total);
    }
    s.total.conn_state.clear();
    s.total.binddn_by_conn.clear();
    s.total.src_by_conn.clear();

    // The run's own concurrent-connection peak (see finalize_connection_counts).
    finalize_connection_counts(s.total);

    const Options& o = s.opts;
    try {
        if (o.output_format == "json") {
            print_json_report(s.total, duration, o.compact, o.output_date_format, o.custom_title);
        } else if (o.output_format == "html") {
            print_html_report(s.total, duration, o.compact, o.output_date_format, o.custom_title);
        } else if (o.output_format == "tabhtml") {
            print_html_report(s.total, duration, o.compact, o.output_date_format, o.custom_title, true);
        } else if (o.output_format == "replay") {
            print_replay_report(s.total, duration, o.output_date_format, o.replay_separator);
        } else {
            // color_mode 0: no ANSI escapes in the browser.
            print_text_report(s.total, duration, o.compact, 0, o.sections, o.output_date_format, o.custom_title);
        }
    } catch (const std::exception& e) {
        std::cerr << "slaplog(wasm): report generation failed: " << e.what() << "\n";
        teardown_session();
        return 1;
    }
    // The session stays alive until the next slaplog_begin(), so the caller can
    // still write its state (slaplog_save_state) after reading the report.  It
    // is the aggregate the run already holds, not an extra copy, and the next
    // begin() tears it down.
    return 0;
}

} // namespace

// ---------------------------------------------------------------------------
// Session API (used by the browser page)
// ---------------------------------------------------------------------------

// Start a session from a space-separated option string.  Positional arguments
// are accepted for symmetry but ignored: files are added with slaplog_add_*().
extern "C" EMSCRIPTEN_KEEPALIVE int slaplog_begin(const char* args) {
    return start_session(parse_options(split_whitespace(args ? args : ""))) ? 0 : 1;
}

// Load a state file (--save-state) from the module's filesystem into the
// running total.  The page calls this before adding the new logs, which is what
// lets a browser session continue one that ended earlier.
extern "C" EMSCRIPTEN_KEEPALIVE int slaplog_resume(const char* path) {
    if (!g_session || !path) return -1;
    std::string err;
    if (!load_state(g_session->total, path, err)) {
        std::cerr << "slaplog(wasm): cannot resume: " << err << "\n";
        return 1;
    }
    return 0;
}

// Start a new input.  Required before a series of slaplog_add_text() calls that
// belong to the same file; slaplog_add_file() does it implicitly.
extern "C" EMSCRIPTEN_KEEPALIVE int slaplog_input_begin(void) {
    if (!g_session) return -1;
    begin_input();
    return 0;
}

// Finish the current input and fold it into the running total.
extern "C" EMSCRIPTEN_KEEPALIVE int slaplog_input_end(void) {
    if (!g_session) return -1;
    end_input();
    return 0;
}

// Process one whole file (plain, .gz, .bz2 or .xz — detected from its magic
// bytes) as a single input.
extern "C" EMSCRIPTEN_KEEPALIVE int slaplog_add_file(const char* path) {
    if (!g_session || !path) return -1;
    begin_input();
    process_file(path, g_session->current, g_session->progress, nullptr, nullptr);
    end_input();
    return 0;
}

// Process a chunk of plain text, held in the caller-allocated WASM heap block
// [data, data+len).  Chunks of the same file must be bracketed by
// slaplog_input_begin()/slaplog_input_end().  The chunk must start at a line
// start and end right after a newline (a trailing partial line is allowed, for
// the last chunk).
extern "C" EMSCRIPTEN_KEEPALIVE int slaplog_add_text(const char* data, int len) {
    if (!g_session || !data || len <= 0) return -1;
    feed_text(data, static_cast<size_t>(len));
    return 0;
}

// Emit the aggregated report to stdout and close the session.
extern "C" EMSCRIPTEN_KEEPALIVE int slaplog_end(void) {
    if (!g_session) return -1;
    return emit_report();
}

// Write the session's aggregate as a state file (--save-state), so a browser
// session can be resumed later, or handed to the command-line build.  Called
// after slaplog_end(), which is when the report itself is complete.
extern "C" EMSCRIPTEN_KEEPALIVE int slaplog_save_state(const char* path) {
    if (!g_session || !path) return -1;
    std::string err;
    if (!save_state(g_session->total, path, err)) {
        std::cerr << "slaplog(wasm): cannot save the state: " << err << "\n";
        return 1;
    }
    return 0;
}

// Version of the engine actually running, so the page can show it in its
// footer instead of hard-coding a number that would drift from version.hpp.
extern "C" EMSCRIPTEN_KEEPALIVE const char* slaplog_version(void) {
    return SLAPLOG_VERSION;
}

// Set a custom title for the report (appended after default, separated by " - ").
extern "C" EMSCRIPTEN_KEEPALIVE void slaplog_set_title(const char* title) {
    if (!g_session) return;
    g_session->opts.custom_title = title ? title : "";
}

// ---------------------------------------------------------------------------
// One-shot API: options plus positional input files in a single call.
// Kept for CLI-style callers (and the Node test harness).
// ---------------------------------------------------------------------------
extern "C" EMSCRIPTEN_KEEPALIVE int slaplog_run(const char* args) {
    Options opts = parse_options(split_whitespace(args ? args : ""));
    std::vector<std::string> inputs = opts.inputs;
    if (inputs.empty() && opts.resume.empty()) {
        std::cerr << "slaplog(wasm): no input file given\n";
        return 1;
    }
    if (!start_session(std::move(opts))) return 1;
    for (const auto& f : inputs) {
        begin_input();
        process_file(f, g_session->current, g_session->progress, nullptr, nullptr);
        end_input();
    }
    return emit_report();
}

// Conventional entry point, retained for completeness (e.g. when wiring the
// module up with callMain).  The page normally uses the session API.
int main(int argc, char** argv) {
    std::vector<std::string> args;
    args.reserve(static_cast<size_t>(argc > 0 ? argc - 1 : 0));
    for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
    Options opts = parse_options(args);
    if (opts.inputs.empty() && opts.resume.empty()) {
        std::cerr << "slaplog(wasm): no input file given\n";
        return 1;
    }
    std::vector<std::string> inputs = opts.inputs;
    if (!start_session(std::move(opts))) return 1;
    for (const auto& f : inputs) {
        begin_input();
        process_file(f, g_session->current, g_session->progress, nullptr, nullptr);
        end_input();
    }
    return emit_report();
}
