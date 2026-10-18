# slaplog — OpenLDAP Access Log Analyzer

**SPDX-License-Identifier:** AGPL-3.0-or-later  
**License:** GNU Affero General Public License v3.0 (https://www.gnu.org/licenses/agpl-3.0.txt)  
**Version:** 4.0.1  
**Author:** Manuel FLURY  
**Copyright:** © 2026 Manuel FLURY. All rights reserved.

See the [CHANGELOG](../CHANGELOG.md) for the release history.

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
produces structured reports in text (with ANSI color), HTML, JSON, or replay
format (for jMeter/LoadRunner).

It is designed to handle large log volumes (multi-GB, thousands of files) by
processing files in parallel using one thread per file. Each thread builds its
own `Aggregator` instance, which are then merged after all files are processed,
avoiding any mutex contention during parsing.

Key features:

- **Multi-format support**: Parses all OpenLDAP log formats (debug, syslog-utc,
  syslog-localtime, rfc3339-utc, ol26, rfc3339, syslog) with automatic per-line
  detection, supporting mixed formats in a single file.
- **Replay output format**: Pipe-delimited single-line operations for
  jMeter/LoadRunner replay with configurable separators.
- **Configurable date output**: Reports can output timestamps in rfc3339, iso8601,
  syslog, epoch, or preserve original format.
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
- **Cluster aggregation**: the logs of several servers (same period, or periods
  that overlap) are analysed into a single global picture, with the load split
  back per server.  A connection is keyed by *(server, conn)*, so two servers
  that both number their connections from 1 are never merged into one.
- **Bind usage**: how clients authenticated — method (simple / SASL /
  anonymous), the transport the bind ran over (ldaps / ldap + StartTLS / plain
  ldap), the SASL mechanism, and whether the session-tracking control was used.
- Top-N slowest operations and busiest connections.
- Indexing diagnostics, question-mark filter analysis, global control warnings.
- Section filtering (`-s`) to show only the parts of the report you need.
- Compact mode for top-5 summaries.
- Unknown-line collection for diagnosing log lines the parser does not yet
  handle.

## Supported Log Formats

slaplog supports all OpenLDAP log formats with automatic per-line detection:

| Format | Example | Description |
|--------|---------|-------------|
| `auto` | (default) | Tries all formats per line, supports mixed formats in a single file |
| `debug` | `411d2b6a.1f4b2c3a 0x7f9c1e33a700` | Hex timestamp + thread ID |
| `syslog-utc` | `Aug  5 14:23:01` | Syslog format in UTC |
| `syslog-localtime` | `Aug  5 14:23:01` | Syslog format in local time |
| `rfc3339-utc` | `2026-08-05T14:23:01.123456Z` | RFC3339 UTC with fractional seconds |
| `ol26` | `[2026-08-05T14:23:01.123Z]` | Bracket-style timestamp |
| `rfc3339` | `2026-08-05T14:23:01Z` | Generic RFC3339 |
| `syslog` | `Aug  5 14:23:01` | Generic syslog |

Use `--log-format` to specify a fixed format for faster parsing when you know all lines share the same format.

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

### WebAssembly build (browser)

slaplog can also be compiled to WebAssembly, so a log file can be analysed
**entirely inside a browser tab** — the file never leaves the machine. Several
files can be dropped at once, and a **whole folder can be added**: it is walked
recursively, which is how a cluster's logs are gathered in one gesture
(`logs/*/access.log`). Selections add up, and a file is identified by its path
*inside* the selection rather than by its name — a folder holding one
identically named `access.log` per server directory would otherwise lose all but
the first.  Each file in the list carries its own **remove** button, so a file
picked by mistake comes back out of the selection without starting over.
The files are analysed sequentially and aggregated into a single report, with a
progress indicator.

**Live build:** <https://slaplog.pages.dev/>

```bash
make wasm                                   # -> wasm/web/slaplog.js + slaplog.wasm
python3 -m http.server -d wasm/web 8000     # then open http://localhost:8000/
```

This requires the [Emscripten SDK](https://emscripten.org/) (`em++` on the
`PATH`). zlib and bzip2 come from Emscripten's own ports; liblzma is cross-built
once by `wasm/build_liblzma.sh`. The target is fully separate from the native
build, which is left untouched. See `wasm/README.md` for the architecture and
for the ordering details that differ from earlier releases.

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
| `-o, --output FORMAT` | Output format: `text` (plain), `textcolor` (ANSI, default), `html`, `json`, `replay` |
| `-c, --compact` | Show top 5 instead of top 20 for ranked sections |
| `-r, --recursive` | Recurse into directories when collecting log files |
| `-q, --quiet` | Suppress the progress bar on stderr (useful for batch / cron runs) |
| `-n, --max-files N` | Analyze only the `N` most recently modified files in a directory scan |
| `-m, --mtime DAYS` | Analyze only files modified within the last `DAYS` days (like `find -mtime`) |
| `-j, --jobs N` | Worker thread count (default: CPU cores - 1) |
| `-s, --section LIST` | Comma-separated list of sections to display (see below) |
| `--log-format FORMAT` | Input log format: `auto` (default), `debug`, `syslog-utc`, `syslog-localtime`, `rfc3339-utc`, `ol26`, `rfc3339`, `syslog` |
| `--output-date-format FMT` | Output date format in reports: `rfc3339` (default), `iso8601`, `syslog`, `epoch`, `preserve` |
| `--replay-separator SEP` | Delimiter for replay output (default: `\|`). Use `tab` for tabulation, `comma` for CSV |
| `--replay-limit N` | Max operations written to the replay temp file (default: `1000000`, `0` = unlimited). Acts as a safety cap; a warning is printed when ops are dropped. |
| `--unknown-lines FILE` | Write unrecognised lines to FILE, then generate the full report |
| `--unknown-lines-only FILE` | Like `--unknown-lines` but skip the report |
| `--no-graph` | Omit the charts from the `html` report (they are drawn by default) |
| `-d, --debug` | Print debug information (file count, parsing details, per-file traces) |
| `-D, --documentation` | Print full documentation to stdout |
| `-h, --help` | Show help message |
| `-V, --version` | Show version and build info |

### Section Names (`-s`)

All sections are included by default (`-s all`). Use `-s section1,section2,...`
to select specific sections:

| Section | Content |
|---------|---------|
| `stats` | Processing time, line counts, connection stats, time range |
| `load` | Per-server load: operations, cumulative etime, connections (cluster aggregation) |
| `ops` | Per-operation type counts (BIND, SRCH, RESULT, etc.) |
| `bind` | Bind usage: authentication method, transport (ldap/ldaps/StartTLS), SASL mechanism |
| `errors` | Error code distribution with LDAP error names |
| `errors_per_app` | Errors broken down by application identity |
| `paged` | Searches using the pagedResultsControl (by shape, or the control line at loglevel `trace`) |
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
active connections, time range, total etime/qtime, and read/write balance.  The
**server(s)** the log lines name are listed too — read from the syslog/rfc3339
header prefix, so a log taken with the *debug* format (which names no host)
carries none and the row is simply absent.  The HTML report lays these metrics
out **two per row**, because the section holds little data and a single column
would make it far taller than it needs to be.

### Load by Server

The one section that only means something when the logs of **several servers**
are analysed together — a cluster, a load-balanced pair, a set of rotated files
collected from each node.  It is drawn only when the log names more than one
server; the JSON always carries the per-server totals, since that output is
data rather than a rendered report.

Each file is parsed independently and its counters summed, so a run over the
whole set yields one global picture; this section splits that picture back
across the servers the log lines name:

| Column | Meaning |
|--------|---------|
| Server | The hostname in the syslog/rfc3339 header of the lines |
| Operations | Completed operations (result lines) attributed to that server |
| Share | That server's part of the total operation count |
| Total etime | Cumulative execution time of its operations |
| Connections | Connections opened on it (`ACCEPT`) |
| Results | Result lines it produced |

A connection's identity is **(server, conn)**, not the connection number alone:
every server in a cluster numbers its connections from 1, so `conn=1` on two
servers is two different connections.  Keying on the number alone — as a
single-server analysis can — would merge them into one and corrupt the
per-connection figures (top connections, session correlation, paged runs).  When
the log names more than one server, the *Top Connections* table therefore gains
a **server** column so a connection number can be attributed to the right node;
a single-server log, where the number is already unambiguous, keeps its
narrower table.  The *replay* format keeps its fixed schema, in which `conn` is
per-server: a replay run over a cluster should be split by server.

The *debug* log format names no host, so it contributes nothing here and the
section is absent — that format describes one server, and there is nothing to
split.

Each server's own coverage is also part of this picture: the parser keeps the
earliest and the latest timestamped line seen from each host, the report prints
them as the **coverage lanes** under the two time-series charts, and the JSON
carries them as `time_by_server` next to `load_by_server`.

### Operation Counts

Counts per operation type: BIND, BIND ANONYMOUS, EXT, ADD, DEL, MOD, MODRDN,
CMP, SRCH, SRCH ATTR, RESULT, SEARCH RESULT, ABANDON, UNBIND, TLS, SASL,
GLOBAL_CONTROL, SYNCPROV, CSN_GET/QUEUE/GRADUATE, NOT_INDEXED, STARTTLS.

### Bind Usage

How clients authenticated, from the `BIND` request lines.  Three cuts of the
same set of binds:

**Authentication method** — the method slapd decoded and logged:

| `method=` | Meaning |
|-----------|---------|
| `128` (0x80) | The simple method.  A simple bind with an **empty DN** is counted as *anonymous*, not *simple* |
| `163` (0xa3) | SASL |
| `0` | The anonymous-demotion line (`BIND anonymous mech=implicit …`) |

**Transport** — read from the connection's state at the moment of the bind, so
it is the transport that bind actually ran over:

| Value | How it is recognised |
|-------|----------------------|
| `ldaps` | A `TLS established` line and **no** STARTTLS on the connection (implicit TLS) |
| `ldap + StartTLS` | A `TLS established` line **after** a `STARTTLS` operation on the connection |
| `ldap` | No `TLS established` at all |

A bind that runs *before* the STARTTLS operation is counted as `ldap`, which is
what it was: the credentials crossed in the clear, whatever happened later.

**SASL mechanism** — the mechanism slapd names when a bind succeeds
(`EXTERNAL`, `PLAIN`, …).  `SIMPLE` and `implicit` are not listed: the first is
the simple method already counted above, the second the anonymous demotion.

The section also reports how many bind requests carried the **session-tracking
control**, and draws a donut of the method mix whose footnote gives the share of
binds that ran over TLS.

### LDAP Result Codes

Every LDAP result code with its human-readable name and count.  A code does not
say *error or not*: it points at who is at fault — or, for one class, says the
log cannot tell — and only the server-side class says anything about the
directory's health.  Rows, table cells and charts are coloured by class:

| Colour | Class | What it means | Codes |
|--------|-------|---------------|-------|
| green | informational | the operation did what was asked, or the protocol is progressing | `0`, `5`, `6`, `10`, `14` |
| amber | client-side | the request, the identity or the data were at fault; slapd answered correctly | `2`, `7`, `16`–`21`, `32`, `34`, `48`, `49`, `64`–`69` |
| violet | by configuration | the server refused or limited **by configuration** — a numeric limit it was told to enforce, which the client is told about and can page or split around | `3`, `4`, `11` |
| amber over violet, hatched | by configuration, or client-side | the same "no", but the log cannot say which side should have known better: a request the client had no right to make and one it legitimately expected to work are refused with the very same code | `8`, `13`, `50`, `53` |
| red | server-side | slapd itself: internal error, overload, unavailable backend, broken alias | `1`, `12`, `33`, `36`, `51`, `52`, `54`, `71`, `80` |

The five lists cover the whole mnemonic table, so no code is left unclassified;
a code outside it is reported server-side (and named `unknown`) rather than
guessed into a harmless class.  The informational codes are recalled in a note
above the table, and left out of the two charts that show *failures*.

The *by configuration, or client-side* class is drawn **hatched** — amber
diagonal stripes over the violet base — because the result code alone does not
say who should have done otherwise.
`53 unwillingToPerform` is the clearest case: OpenLDAP returns it when it refuses
by policy (a referral it will not follow, TLS that is required, a password-policy
outcome), and the same code answers a client that had no business asking and a
client whose legitimate request stumbles on the configuration.  `50
insufficientAccessRights` is the same question asked of an ACL: a genuine
"no" to an overreaching client, or an ACL that is too tight.  The class says
*look at the request*, not *someone is guilty* — and unlike the numeric limits
(`3`, `4`, `11`), nothing in the result tells the client it could have avoided
the refusal.

### Paged Searches

Searches that carried the **pagedResultsControl** (`1.2.840.113556.1.4.319`),
with the count broken down by the identity that issued them.  Two independent
ways are used, and either may find one:

1. **By shape** — a paged search repeats the same request on one connection, and
   every page returns the same number of entries until the last, which is
   smaller: that is the end of the result set.  On the reference log this is the
   only way, because the log was taken at `loglevel stats`.
2. **By the control line** — at `loglevel trace`, slapd logs every control a
   request carries:

```
=> get_ctrls: oid="1.2.840.113556.1.4.319" (critical)
```

That line carries no `conn=`, so the control is attributed to the connection of
the next line that names one — normally the `SRCH` that asked for it.

The shape is a match, not a proof.  Two cases it gets wrong, in opposite
directions: an application that repeats one search and then stops has exactly
this shape, so a counted run is an *upper bound* on the real number of paged
searches; and a result set whose size is an exact multiple of the page size ends
on a full page, leaving every count equal, so a real paged walk of that shape is
*not* counted.  A run is closed when the parameters change, a non-search
operation completes, or the connection ends.

On the 1 GiB reference log the count is **zero**, and that is the honest answer
rather than a failure of the method: its busiest searching connection interleaves
a `SRCH` with a `DEL` (a uid lookup before a delete), so every run is one search
long, and the rest query a different uid each time.  No connection there repeats
one identical request, which is what a paged walk does.

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
`[IP=... NAME=... USERNAME=...]` blocks on operation lines. The table is
**grouped by client** and sorted by session count, because the tracking name
usually carries a per-session identifier that would otherwise make every row
unique:

- **Sessions**: Number of sessions seen for this client.
- **NAT IPs**: Number of distinct NAT addresses it connected from.
- **Real IP**: The actual client IP from the session tracking control.
- **Name**: Client identifier (hostname, pod name, …), with a trailing session
  id such as `…=sessionId-1792207915730` stripped so that sessions group.
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
- Error codes color-coded by class: green for information, amber for
  client-side, magenta for what the configuration refused, red for slapd's own
  failures — and a colour key printed above the table.  The dual class shares
  the magenta: ANSI has no hatch, and the text report names no class, so it is
  the HTML side that draws the "either cause" reading
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
- **A floating section index**, fixed in the top-right corner: it lists every
  section the report actually drew (charts are not sections) and scrolls to it
  on click.  It opens with the report, so the reader sees where he can go, then
  tucks itself away into a three-line window on the section being read — the one
  before, the one read, the one after — which it keeps up to date as the report
  is scrolled.  It opens again as the pointer comes near, and a click on the
  heading pins it open, so it is also usable without a pointer (touch,
  keyboard); the change of height is animated, and the box is clipped rather
  than rebuilt, so its width never moves.  The links are built from the page
  itself, so the index can never offer a section that is not there.
- **Ten inline SVG charts**, each placed under the section it summarises —
  drawn by default, disable with `--no-graph`.  None of them carries a
  *"How to read it"* note.  A note under a drawing that needs no explaining (a
  share ring, a connection curve, a pie) is noise, and a note that talks past the
  thing the reader is stuck on is worse than none.  Where a word really is needed,
  it belongs in the chart's subtitle — which is where every one of them now says
  what it shows:
  - *Simultaneous Connections*: how many connections were open across the
    analysed time range, with a marker on every server start/stop event, a
    shaded band over each downtime period, and an orange marker for a restart
    that had no shutdown before it (a likely crash).  Under the time axis sits
    one **lane per server**: the faint track is the window the chart plots and
    the coloured span is the window that server's own log actually covers, so a
    curve that steps up and then falls off a cliff is read as the end of a file
    instead of the end of a heavy operation.  A single server gets no lane — its
    window *is* the chart's — and the key under the chart names each server with
    the window it covers;
  - *Errors Over Time*: **failing** results only — informational codes (success,
    both Compare answers, a referral) are not plotted, so the curve is not
    inflated by operations that did what they were asked.  The curve is
    **stacked by result code**: the silhouette is the total, exactly where a
    single curve would be, and the colour underneath says which code built it —
    amber for what the client asked, violet for what the configuration refuses,
    red for what slapd failed to do, shaded by rank so two codes of one class
    stay distinguishable.  A refusal the log cannot attribute to either side
    (see the result-code classes) is a diagonal amber/violet **hatch** instead of
    a flat colour, and its legend swatch carries the same hatch.  A peak in one
    colour is one problem; a rise spread over several is a general one.  The
    legend under the chart names each band and its share, and hovering a slice
    lists the codes it is made of.  It carries the same per-server coverage
    lanes as *Simultaneous Connections*, since a fall at the edge of one
    server's file is exactly what this curve invites misreading as a recovery;
  - *Response Time Distribution*: how many operations fall into each etime
    bucket, each bar labelled with its exact count and share — the latency tail
    at a glance.  A cumulative share curve with its own 0-100 % axis used to run
    down the right-hand side; it was removed because the bars already carried
    every figure it derived from, and because on that axis each row past the
    second reads 100 %: the reader had to work out what the number referred to,
    for nothing.  The bars now have the width it and its label column took;
  - *Response Time Density*: the **shape** of that same distribution, on a
    logarithmic x axis whose window follows the data.  The eleven buckets above
    cannot show a shape that fits in one of them, and on a real 1 GiB access log
    99.9992 % of the operations finish under 1 ms; here the bins are equal in
    ratio (×1.58 per step) so the profile is readable — and this is also the
    only axis on which a latency distribution could ever look like a bell, which
    is what a log-normal latency is;
  - *Resource Consumers by Bind Account*: share of the cumulative operation
    time (etime) per bind DN, with each account's operation count and average
    time per operation;
  - *Operation Types*: share of SRCH / BIND / MOD / … ;
  - *Load by Server*: share of the operations each server of the analysed set
    handled, with each server's operation count in the legend — the only chart
    that only means something when several servers' logs are analysed together;
  - *Bind Usage*: share of each authentication method (simple / SASL /
    anonymous), with a footnote giving how many of the binds ran over TLS
    (ldaps or ldap + StartTLS) rather than in the clear;
  - *Result Code Breakdown*: every result code, successes included, as bars
    coloured by class, with the same codes drawn as **a pie** on the right — same
    order, same colours, sized by area.  One huge slice and a tail of slivers is
    what a result-code distribution looks like: on a concentrated log the first code
    alone is 63 % of everything and the top six are 99.99 %, so the chart says how
    few codes carry how much at a glance — no axis, no curve, no caption.  That
    right-hand side has been drawn four ways: a cumulative *curve* with its figures
    repeated in a text column beside it (the same number rendered twice, and the
    reader had to interpolate between 24 px rows to answer a question that is asked
    row by row), then a flat bar per row (which answered once the row was found),
    then those bars stacked so the sum could be seen being built (which needed a
    note to be read at all), and now the pie — which needs none.  Every code keeps
    **one colour** all through the report: the colour of its bar, of its slice here,
    and of its band in the stacked chart above.  A code of the dual class is the
    one exception, and it is deliberate: it is painted with the amber/violet
    **hatch** everywhere — bar, slice and band — so it reads as "either cause" at
    every place it appears, while its label and tooltip keep the violet base
    colour.  The left bars are on a log scale —
    counts span five orders of magnitude, and a linear scale would leave every code
    but the first invisible — so each bar carries its exact count and share, and
    **the scale itself is labelled under the bars** in decades: one step is ten
    times the one before.  Without that label the chart showed a percentage grid and
    nothing at all to measure a bar against;
  - *Failing Result Codes*: share of each failing result code, coloured by
    class — the dual class as the same amber/violet hatch as everywhere else.
    The informational results are not drawn as slices but counted and
    named in a note under the legend — on a 1 GiB production access log the
    Compare answers alone were 169 894 results, 32 % of the slices, which made
    the failure count read 48 % higher than it is.
  All are interactive — a tooltip follows the mouse and shows the exact value
  under the cursor.
- The OpenLDAP version, when the startup banner is present in the log.

### JSON (`-o json`)

Complete machine-readable output via `nlohmann/json` with all aggregated data
structures (operation counts, error distribution, top operations, session
correlations, etc.).

### Replay (`-o replay`)

Pipe-delimited single-line format for jMeter/LoadRunner replay. Multi-line
operations (SRCH + SRCH_ATTR) are merged into a single line with results
included:

```
timestamp|conn|op|type|base|filter|attrs|scope|deref|binddn|authcid|authzid|err|etime|qtime|nentries|text
```

Every LDAP operation produces exactly one line, including those with no
RESULT line in the access log:

| Type | Notes |
|------|-------|
| `BIND` | `binddn` carries the DN; `err` is the expected result code. |
| `SRCH` | `base`, `filter`, `attrs`, `scope`, `deref`; `nentries` is the expected entry count. |
| `CMP` / `COMPARE` | `base` carries the entry DN. |
| `ADD`, `DEL`, `MOD`, `MODRDN` | write operations: `base` carries the target DN. |
| `EXT` | extended operation. |
| `ABANDON` | fire-and-forget cancellation; `filter` carries the numeric message id of the operation to abandon. |
| `UNBIND` | graceful disconnect. |

`ABANDON` and `UNBIND` have no RESULT line in the slapd access log, so their
replay rows carry no `err`/`etime`/`nentries`. They are still emitted (from
their own log line) so the replayer sees every operation.

The companion replayer (`jMeter_OpenLDAP_replay`) replays only `BIND`, `SRCH`,
`CMP`, `UNBIND` and `ABANDON`; the write operations (`ADD`, `DEL`, `MOD`,
`MODRDN`, `EXT`) are written here for traceability but skipped by the
replayer.

Use `--replay-separator` to change the delimiter:
```bash
slaplog -o replay --replay-separator tab access.log   # tab-separated
slaplog -o replay --replay-separator comma access.log # CSV format
```

Use `--replay-limit` to cap the number of operations written to the temp file:
```bash
slaplog -o replay --replay-limit 500000 access.log   # max 500K ops
slaplog -o replay --replay-limit 0 access.log         # unlimited
```

Replay data is written to a temporary file during processing, keeping memory
usage bounded regardless of log file size. Use `--replay-limit` as a safety
cap for extremely large log sets or limited disk space on `/tmp`.

This format is useful for replaying LDAP operations against a test server or
analyzing operation timing with external tools.

A complete jMeter run, with the options combined:
```bash
slaplog -o replay --replay-separator comma --output-date-format epoch \
  --replay-limit 500000 --log-format auto -q /var/log/slapd/access.log > jmeter_replay.csv
```

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

- Detects the header format (RFC 3339 / OL26 / syslog / debug) via
  `try_parse_header()` — automatic per-line detection in `auto` mode — and
  converts the timestamp to RFC 3339 UTC via `convert_to_rfc3339_utc()`.
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
  Tracks type, base, filter, attrs, scope, deref, who, etime, qtime,
  nentries, err, text, timestamp, etc.
- **`ConnState`**: Per-connection mutable state. Contains a map of ops,
  accumulated etime, binddn, authcid, src, session tracking fields.
- **`TopOpRow`** / **`TopConnRow`**: Rows for the top-N leaderboards.
  `TopOpRow` includes all fields needed for replay output.
- **`Stats`**: Simple scalar counters (lines, connections, unknowns).
- **`Aggregator`**: The main aggregation structure containing all maps,
  counters, and state. Includes `SessionCorrelation` and `server_events`.
  Also holds `restart_count` for correct session tracking across slapd
  restarts.
- **`LogFormat`** enum and helpers: `parse_log_format()`,
  `convert_to_rfc3339_utc()`, `try_parse_header()` with auto-detection support.

### `log_parser.cpp`

All parsing and aggregation logic:

- **Helpers**: `dequote`, `to_int`, `trim`, `normalize_filter`,
  `normalize_attrs`, `ts_sort_key`, `update_time_bounds`.
- **Format conversion**: `convert_to_rfc3339_utc()` with helpers
  `parse_debug_timestamp()`, `parse_syslog_timestamp()`, `format_rfc3339_utc()`.
  Converts any supported format to RFC3339 UTC.
- **`try_parse_header()`**: Multi-format header detection. In `AUTO` mode,
  tries all formats per line and reports the detected format via output
  parameter.
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
- **`print_replay_report()`**: Pipe-delimited single-line output for
  jMeter/LoadRunner replay. Configurable delimiter via `--replay-separator`.
  Data written to a temp file during processing (bounded memory).

### `version.hpp`

Single source of truth for `SLAPLOG_VERSION` and `BUILD_NUMBER`.

### `embedded.hpp`

Holds the licence text and **this document**, printed by `-l` and `-D`.  It is
a **generated** file: `LICENSE` and `doc/slaplog.md` are the sources and
`make embedded` rewrites it — `make` does it automatically as soon as either
source changes, and `make check-doc` fails when it is stale.  Never edit it by
hand: the two copies used to be maintained that way and drifted apart.

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
