# slaplog — OpenLDAP Access Log Analyzer

**SPDX-License-Identifier:** AGPL-3.0-or-later  
**License:** GNU Affero General Public License v3.0 (https://www.gnu.org/licenses/agpl-3.0.txt)  
**Version:** 3.0.2  
**Author:** Manuel FLURY  
**Copyright:** © 2026 Manuel FLURY. All rights reserved.

This file is part of slaplog - an OpenLDAP Log Analysis Tool.

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later).
See the LICENSE file distributed with this work for full license text.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Table of Contents

1. [Overview](#overview)
2. [Supported Log Formats](#supported-log-formats)
3. [Build & Install](#build--install)
4. [Usage](#usage)
5. [Command-Line Options](#command-line-options)
6. [Report Sections](#report-sections)
7. [Output Formats](#output-formats)
8. [Session Tracking](#session-tracking)
9. [Architecture](#architecture)
10. [File-by-File Guide](#file-by-file-guide)
11. [Extending the Parser](#extending-the-parser)

---

## Overview

`slaplog` is a command-line tool that parses OpenLDAP `slapd` access logs and
produces structured reports in text (with ANSI color), HTML, or JSON format.

It is designed to handle large log volumes (multi-GB, thousands of files) by
processing files in parallel using one thread per file. Each thread builds its
own `Aggregator` instance, which are then merged after all files are processed,
avoiding any mutex contention during parsing.

Key features:

- Parses three common slapd log header formats (RFC 3339, OL26 bracket-style,
  syslog).
- Recognises all standard LDAP operations: BIND, SRCH, ADD, DEL, MOD, MODRDN,
  CMP, EXT, ABANDON, UNBIND, and RESULTS.
- Tracks connection state (ACCEPT, CLOSED, TLS), replication CSN events,
  session tracking control, and extended operations.
- Detects server start/stop events from log lines.
- Collects detailed per-operation metrics: execution time (etime), queue time
  (qtime), error codes, search base, filter, attributes, and who performed the
  operation.
- Session tracking correlation: maps NAT'd ACCEPT IPs to real client IPs via
  the OpenLDAP session tracking request control `[IP=... NAME=... USERNAME=...]`.
- Top-N slowest operations and busiest connections.
- Indexing diagnostics, question-mark filter analysis, global control warnings.
- Section filtering (`-s`) to show only the parts of the report you need.
- Compact mode for top-5 summaries.
- Unknown-line collection for diagnosing log lines the parser does not yet
  handle.

## Supported Log Formats

### RFC 3339 (fractional seconds)

```
2026-05-27T14:49:01.393037259Z myserver.example.com slapd[597222]: conn=700635 fd=45687 ACCEPT from IP=10.226.49.169:46174 (IP=0.0.0.0:11636)
```

### OL26 (bracket-style)

```
[2025-03-12T10:00:00Z] conn=12345 op=1 BIND dn="cn=admin,dc=example,dc=com" method=128
```

### Syslog

```
Mar 12 10:00:00 host slapd[1234]: conn=12345 op=1 SRCH base="dc=example,dc=com" scope=2 deref=0 filter="(uid=test)"
```

If a line does not match any header format, it is marked as `UNKNOWN_LINE` and
collected for diagnostic output.

## Build & Install

### Requirements

- C++17 compiler — GCC 8+ (GCC 11+ recommended)
- POSIX threads
- Development libraries: `zlib`, `bzip2`, `lzma` (for compressed log files)
- `nlohmann/json` header (system package — see below)

Install dependencies for your distro:

| Distro | Command |
|--------|---------|
| Fedora / RHEL 9+ | `sudo dnf install gcc-c++ zlib-devel bzip2-devel xz-devel json-devel` |
| RHEL 8 (EPEL)    | `sudo dnf install gcc-toolset-12-gcc-c++ zlib-devel bzip2-devel xz-devel json-devel` |
| Debian / Ubuntu  | `sudo apt install g++ zlib1g-dev libbz2-dev liblzma-dev nlohmann-json3-dev` |
| Arch Linux       | `sudo pacman -S gcc zlib bzip2 xz nlohmann-json` |

### Build

```bash
cd slaplog
make
```

The Makefile auto-increments a build number on each compilation.

### Clean

```bash
make clean
```

## Usage

```bash
slaplog [options] <logfile|directory> [file|dir ...]
```

### Basic Examples

Parse a single log file and print a color report:

```bash
slaplog /var/log/slapd/access.log
```

Parse all log files in a directory recursively:

```bash
slaplog -r /var/log/slapd/
```

Generate an HTML report:

```bash
slaplog -o html /var/log/slapd/access.log > report.html
```

Show only the statistics and session tracking sections:

```bash
slaplog -s stats,sessions /var/log/slapd/access.log
```

Analyze only recent logs without a progress bar (batch / cron friendly):

```bash
# Only files modified in the last 7 days, no progress bar
slaplog -q -m 7 -r /var/log/slapd/

# Only the 5 most recently modified files
slaplog -q -n 5 -r /var/log/slapd/
```

The `-n/--max-files` and `-m/--mtime` filters apply to files discovered when
scanning directories; they are based on each file's last-modification time.
When both are combined, the `--mtime` window is applied first, then the
`--max-files` limit keeps the newest survivors.

Write unknown lines to a file (and still produce the report):

```bash
slaplog --unknown-lines unknown.txt /var/log/slapd/access.log
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-o, --output FORMAT` | Output format: `text` (plain), `textcolor` (ANSI, default), `html`, `json` |
| `-c, --compact` | Show top 5 instead of top 20 for ranked sections |
| `-r, --recursive` | Recurse into directories when collecting log files |
| `-q, --quiet` | Suppress the progress bar on stderr (useful for batch / cron runs) |
| `-n, --max-files N` | Analyze only the `N` most recently modified files in a directory scan |
| `-m, --mtime DAYS` | Analyze only files modified within the last `DAYS` days (like `find -mtime`) |
| `-s, --section LIST` | Comma-separated list of sections to display (see below) |
| `--unknown-lines FILE` | Write unrecognised lines to FILE, then generate the full report |
| `--unknown-lines-only FILE` | Like `--unknown-lines` but skip the report |
| `--debug` | Print debug information (file count, parsing details) |
| `-h, --help` | Show help message |
| `-V, --version` | Show version and build info |

### Section Names (`-s`)

All sections are included by default (`-s all`). Use `-s section1,section2,...`
to select specific sections:

| Section | Content |
|---------|---------|
| `stats` | Processing time, line counts, connection stats, time range |
| `ops` | Per-operation type counts (BIND, SRCH, RESULT, etc.) |
| `errors` | Error code distribution with LDAP error names |
| `errors_per_app` | Errors broken down by application identity |
| `bases` | Top search bases by count and cumulative etime |
| `filters` | Top search filters by count, etime, nentries=1/0, wildcards |
| `filters_per_app` | Filters broken down by application identity |
| `attrs` | Most frequently requested attributes |
| `apps` | Top applications by operation count and etime |
| `extops` | Extended Operation OIDs and Global Control warnings |
| `qmark` | Question-mark filter `(?attr=...)` analysis |
| `csn` | CSN internal replication events (get/queue/graduate) |
| `server` | Server start, stop, and shutdown events |
| `index` | Indexing diagnostics (not-indexed attributes) |
| `sessions` | Session Tracking correlation table |
| `topops` | Top 100 slowest operations (by etime) |
| `topconns` | Top 100 busiest connections (by cumulative etime) |

## Report Sections Detail

### Statistics

Shows processing performance, total/unknown lines, connection counts, peak
active connections, time range, total etime/qtime, and read/write balance.

### Operation Counts

Counts per operation type: BIND, BIND ANONYMOUS, EXT, ADD, DEL, MOD, MODRDN,
CMP, SRCH, SRCH ATTR, RESULT, SEARCH RESULT, ABANDON, UNBIND, TLS, SASL,
GLOBAL_CONTROL, SYNCPROV, CSN_GET/QUEUE/GRADUATE, NOT_INDEXED, STARTTLS.

### Error Counts

Distribution of LDAP result error codes with human-readable names.

### Search Analysis

- **Bases**: Top search base DNs by frequency and cumulative execution time.
- **Filters**: Top filters by frequency and cumulative etime, plus analysis of
  filters returning exactly 1 or 0 entries.
- **Wildcard filters**: Filters containing `*` (substring searches).
- **Filters per app**: Which applications use which filters.
- **Attributes**: Most frequently requested attributes in search results.

### Application Profiling

Each connection is identified by its BIND DN, authcid/authzid, or session
tracking username/name. The report shows which applications are most active
and which consume the most server time.

### Extended Operations

OIDs and names of all extended operations used (StartTLS, PasswordModify,
WhoAmI, Cancel, etc.), plus unrecognised global control OIDs.

### Session Tracking Correlations

When OpenLDAP's session tracking request control is enabled, slapd logs
`[IP=... NAME=... USERNAME=...]` blocks on operation lines. The session
tracking table correlates:

- **ACCEPT IP**: The source IP from the TCP accept (may be NAT'd).
- **Real IP**: The actual client IP from the session tracking control.
- **Name**: Client identifier (hostname, pod name, etc.).
- **Username**: Application username or DN.
- **BIND dn**: The DN used to authenticate on this connection.

Correlation entries are keyed by `(restart_epoch, conn)` so that connections
are correctly isolated across slapd restarts (where the connection ID counter
resets).

### Top Operations & Connections

The 100 slowest individual operations and the 100 most expensive connections
by cumulative execution time. Each shows the connection, operation, who,
search base/filter, and error code.

## Output Formats

### Text (`-o text`)

Plain monochrome output suitable for terminal pipes, file logging, or
environments without ANSI support.

### Textcolor (`-o textcolor`, default)

Same layout as text but with ANSI escape sequences for:
- Section headers in cyan bold
- Metric labels in green
- Etime values color-coded: green (<0.1s), cyan (<0.5s), yellow (<1s),
  red (<5s), bright red (≥5s)
- Error codes color-coded: green for success/referral, red for failures
- Alternating application colors in filters-per-app table
- Count gradient: green → yellow → red → bright red

### HTML (`-o html`)

Standalone HTML page with embedded CSS featuring:
- Blue gradient header
- Flexbox meta information bar
- Rounded tables with hover highlighting and alternating row colors
- Server events with green (start) / red (stop) left border indicators
- Color-coded etime values
- Responsive layout (`@media` query for mobile)

### JSON (`-o json`)

Complete machine-readable output via `nlohmann/json` with all aggregated data
structures (operation counts, error distribution, top operations, session
correlations, etc.).

## Session Tracking

OpenLDAP supports the Session Tracking Request Control as defined in
draft-ietf-ldup-session-tracking. When enabled on the client side, slapd logs
the tracking information on each operation line:

```
conn=705807 op=1 [IP=10.67.10.49 NAME=vm3 USERNAME=uid=MyApplication,...] BIND dn="..." method=128
```

### How slaplog handles it

1. **Parsing**: After extracting `conn` and `op` via `RE_CONN_OP`, the parser
   checks if the remaining text starts with `[`. If so, it tries to match the
   session tracking block with two regexes:
   - Full: `[IP=... NAME=... USERNAME=...]`
   - Partial: `[IP=... NAME=...]` (no USERNAME)

2. **Storage**: The extracted fields (`session_ip`, `session_name`,
   `session_username`) are stored in the `Event` struct and forwarded to
   `ConnState` during aggregation.

3. **Correlation**: When session tracking data is encountered, a
   `SessionCorrelation` entry is created/updated. The key is
   `(restart_count, conn)` to handle slapd restarts where the connection ID
   counter resets.

4. **BIND DN enrichment**: When a BIND response is processed on the same
   connection, the correlation entry is updated with the DN used for
   authentication. The DN is extracted from the event data itself (not from
   `conn_state`) to avoid stale values across restart epochs.

### Restart handling

On `SLAPD_STARTING` events, an internal `restart_count` is incremented. All
subsequent session correlations use `(new_restart_count, conn)` as their key.
This prevents a connection ID from a previous server instance from colliding
with an ID from a new instance.

## Architecture

```
main.cpp
  ├── parse CLI arguments
  ├── collect_input_files() — discover log files
  ├── create per-thread Aggregator instances
  ├── spawn worker threads (one per file)
  │     └── process_file() → parse_line() → update_aggregator()
  ├── progress bar thread (stderr)
  ├── merge_aggregators() — combine thread results
  ├── write unknown lines if --unknown-lines
  └── print_report() — text / HTML / JSON
```

### Two-stage parsing

Each log line goes through two distinct stages:

**Stage 1: `parse_line()`** → `Event`

- Strips the timestamp header (RFC 3339 / OL26 / syslog).
- Extracts `conn=`, `op=`, `fd=` identifiers.
- Strips `[IP=... NAME=... USERNAME=...]` session tracking blocks.
- Dispatches to the correct regex group based on the first character of the
  remaining text (`R` for RESULT, `B` for BIND, `S` for SRCH/SEARCH/SASL,
  etc.).
- Fills in the appropriate `Event` fields (kind, err, etime, dn, base,
  filter, session_ip, etc.).
- Returns `Event` — a value type that is cheap to copy between stages.

**Stage 2: `update_aggregator()`** → `Aggregator`

- Checks `ev.kind` and updates the corresponding counters.
- Maintains per-connection state (`ConnState`) and per-operation state
  (`OpState`).
- Tracks active connections, peak concurrent connections.
- Accumulates etime totals, averages, and top-N lists.
- Records errors, search bases, filters, attributes.
- Creates/updates session correlation entries.

### Parallelism

- No shared state between threads — each file gets its own `Aggregator`.
- Merging is a single-threaded post-processing step that unions all maps and
  keeps top-N entries.
- The progress bar runs on a dedicated thread and refreshes every 100 ms.

## File-by-File Guide

### `main.cpp`

Entry point. Defines CLI argument parsing, file collection (`wanted_log_file`,
`collect_input_files`), parallel processing orchestration, and report
dispatch. The `print_progress()` function renders a text progress bar on
stderr.

### `log_parser.hpp`

All data structures:

- **`Event`**: The output of `parse_line()`. Contains the parsed kind, raw
  text, optional LDAP fields, and session tracking fields.
- **`OpState`**: Mutable state for one LDAP operation within a connection.
  Tracks type, base, filter, who, etime, etc.
- **`ConnState`**: Per-connection mutable state. Contains a map of ops,
  accumulated etime, binddn, authcid, src, session tracking fields.
- **`TopOpRow`** / **`TopConnRow`**: Rows for the top-N leaderboards.
- **`Stats`**: Simple scalar counters (lines, connections, unknowns).
- **`Aggregator`**: The main aggregation structure containing all maps,
  counters, and state. Includes `SessionCorrelation` and `server_events`.
  Also holds `restart_count` for correct session tracking across slapd
  restarts.

### `log_parser.cpp`

All parsing and aggregation logic:

- **Helpers**: `dequote`, `to_int`, `trim`, `normalize_filter`,
  `normalize_attrs`, `ts_sort_key`, `update_time_bounds`.
- **`parse_line()`**: ~450 lines of regex dispatch. Starts with header
  parsing, then connection/operation ID extraction, session tracking strip,
  and prefix-character-based dispatch to ~30 regex patterns.
- **`update_aggregator()`**: ~500 lines of counter and state updates. Routes
  on `ev.kind` to the correct handler (BIND, SRCH, RESULT, etc.).
- **`merge_aggregators()`**: Unions two `Aggregator` instances, keeping the
  top 100 for operations and connections.
- **File I/O**: `process_plain_file`, `process_gzip_file`, `process_bzip2_file`,
  `process_xz_file` — each reads lines and calls `parse_line` + `update_aggregator`.

### `regex_patterns.hpp`

All compiled `std::regex` objects in the `slaplog_rx` namespace. Organised
into groups: headers, connection identifiers, connection events, BIND
patterns, operations, results, sub-patterns, replication CSN, session
tracking, and miscellaneous.

### `report.hpp` / `report.cpp`

Report generation:

- **`print_text_report()`**: ANSI-colored terminal output with section
  filtering via `has_section()`. Uses `print_table()` for formatted tables
  with automatic column-width calculation.
- **`print_html_report()`**: Standalone HTML with embedded CSS. Produces
  responsive, styled tables with colour gradients for etime values.
- **`print_json_report()`**: Machine-readable JSON output with all
  aggregated data, including session correlations.

### `utils.hpp`

Small utility functions: `ends_with` for filename suffix checks,
`parse_timestamp` for ISO 8601 parsing, `format_time` for display
formatting, and a regex cache for frequently-used patterns.

## Extending the Parser

### Adding a new log line pattern

1. Add the regex to `regex_patterns.hpp` in the appropriate group.
2. In `parse_line()` (`log_parser.cpp`), add a dispatch branch:
   - For operation lines: add an `if (fc == 'X' && rest.compare(...))` block.
   - For connection events: add to the existing `c` dispatch.
   - For miscellaneous patterns: add to the catch-all section at the end.
3. Set `ev.kind` to a unique string for the new pattern.
4. In `update_aggregator()`, add an `if (ev.kind == "NEW_KIND")` handler.
5. Add any new counters to the `Aggregator` struct in `log_parser.hpp`.
6. Handle merge in `merge_aggregators()`.

### Adding a report section

1. Add the section data to `Aggregator` in `log_parser.hpp`.
2. Populate the data in `update_aggregator()`.
3. Add a `has_section("new_section")` block in `print_text_report()`.
4. Add the corresponding HTML table in `print_html_report()`.
5. Add the corresponding JSON key in `print_json_report()`.
6. Add the section name to the `-s` help text in `main.cpp`.

### Thread safety

- `parse_line()` is a pure function (no mutable globals).
- `update_aggregator()` modifies its `Aggregator&` argument only — no shared
  state.
- `merge_aggregators()` is called single-threaded after all workers join.
- If adding new mutable global state, protect it with `std::mutex` or refactor
  into the `Aggregator` struct.
