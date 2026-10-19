
# slaplog — OpenLDAP Log Analysis Tool

**SPDX-License-Identifier:** AGPL-3.0-or-later  
**License:** GNU Affero General Public License v3.0 (https://www.gnu.org/licenses/agpl-3.0.txt)  
**Version:** 4.0.5  
**Author:** Manuel FLURY  
**Copyright:** © 2026 Manuel FLURY. All rights reserved.

See the [CHANGELOG](CHANGELOG.md) for the release history.  
  
    This file is part of slaplog - an OpenLDAP Log Analysis Tool.  
 
    Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later).  
    See the LICENSE file distributed with this work for full license text.  
      
    THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
    FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL  
    THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN  
    AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN  
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


Parse, analyze, and produce structured reports from OpenLDAP slapd access logs.

## Quick start

```bash
make
./slaplog /var/log/slapd/access.log
./slaplog -o html -r /var/log/slapd/ > report.html
./slaplog -s stats,sessions -c /var/log/slapd/access.log
./slaplog -q -m 7 -r /var/log/slapd/          # last 7 days, no progress bar
./slaplog -q -n 5 -r /var/log/slapd/          # 5 most recent files
```

## Features

- **5 output formats**: text/ANSI color, HTML (standalone with CSS), tabbed HTML, JSON, replay (for jMeter/LoadRunner)
- **Parallel processing**: bounded worker pool (`-j`, capped at the file count), each worker merging its file under one mutex
- **Compressed logs**: `.gz`, `.bz2`, `.xz` transparently handled
- **Session tracking**: correlates NAT'd IPs to real clients via `[IP=... NAME=... USERNAME=...]`
- **Section filtering**: `-s all` (default) or select specific sections
- **Top-N analysis**: 100 slowest ops, busiest connections, most-used filters
- **HTML charts**: eight inline SVG graphs — simultaneous connections over time
  (with downtime bands and server start/stop/abrupt-restart markers), errors
  over time (failing results only, stacked by result code), response-time
  distribution and its density profile on a log scale, resource consumers by
  bind account, operation types, every result code (successes included, on a log
  scale, with the same codes drawn as a pie on the right) and the failing ones by
  class — all with mouse-following tooltips, each placed under the section it
  summarises, no note anywhere (a chart that needs a word says it in its subtitle),
  and result codes coloured
  by who is at fault (information / client-side / refused by configuration /
  refused by configuration *or* client-side, drawn as an amber-over-violet hatch
  / slapd itself); disable them with `--no-graph`
- **OpenLDAP version**: reported when the startup banner is present in the log
  (Statistics table, html meta bar, JSON)
- **Server events**: start/stop/shutdown detection
- **Restart-aware**: handles slapd connection-ID counter resets
- **Multi-format support**: parses debug, syslog-utc, syslog-localtime, rfc3339-utc formats with auto-detection

## Usage

```
Usage: ./slaplog [options] <logfile|directory> [file|dir ...]

Options:
  -o, --output FORMAT        text | textcolor | html | json | replay
  -c, --compact              Top 5 instead of top 20
  -r, --recursive            Recurse into directories
  -q, --quiet                Suppress the progress bar (batch mode)
  -n, --max-files N          Analyze only the N most recently modified files
  -m, --mtime DAYS           Analyze only files modified in the last DAYS days
  -j, --jobs N               Worker threads (default: CPU cores - 1)
  -s, --section LIST         Comma-sep section list: all,stats,ops,errors,
                             bases,filters,attrs,apps,extops,csn,server,
                             index,sessions,topops,topconns,...
  --log-format FORMAT        Input log format: auto, debug, syslog-utc,
                             syslog-localtime, rfc3339-utc, ol26, rfc3339,
                             syslog (default: auto)
  --output-date-format FMT   Output date format in reports: rfc3339, iso8601,
                             syslog, epoch, preserve (default: rfc3339)
  --replay-separator SEP     Delimiter for replay output (default: "|")
                             Use "tab" for tabulation, "comma" for CSV
  --replay-limit N           Max ops stored for replay (default: 1000000, 0=unlimited)
  --unknown-lines FILE       Write unparseable lines to FILE
  --unknown-lines-only FILE  Like above but skip report
  -D, --documentation        Print full documentation
  -l, --licence              Print AGPLv3 license
  -d, --debug                Verbose diagnostics
  -h, --help                 Show help
  -V, --version              Show version
```

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

## Replay Output Format

The `replay` output format generates pipe-delimited single-line operations for jMeter/LoadRunner replay:

```
timestamp|conn|op|type|base|filter|attrs|scope|deref|binddn|authcid|authzid|err|etime|qtime|nentries|text
```

Every LDAP operation produces exactly one line, including `ABANDON` and
`UNBIND` which have no RESULT line in the access log (their rows carry no
`err`/`etime`/`nentries`). `ABANDON` stores the numeric message id of the
operation to cancel in the `filter` column.

Write operations (`ADD`, `DEL`, `MOD`, `MODRDN`) are emitted with the target
DN in the `base` column for traceability, but the companion replayer
(`jMeter_OpenLDAP_replay`) only replays `BIND`, `SRCH`, `CMP`, `UNBIND` and
`ABANDON` and skips the writes.

Example:
```bash
./slaplog -o replay /var/log/slapd/access.log | tee replay.csv
```

Use `--replay-separator` to change the delimiter:
```bash
./slaplog -o replay --replay-separator tab /var/log/slapd/access.log   # tab-separated
./slaplog -o replay --replay-separator comma /var/log/slapd/access.log # CSV format
```

This format is useful for replaying LDAP operations against a test server or analyzing operation timing with external tools.

## Build requirements

- **C++17 compiler** — GCC 8+ (GCC 11+ recommended). Code compiled on
  GCC 8 needs the runtime from GCC 9+ (`GLIBCXX_3.4.26`; RHEL 8.5 ships it).
- **POSIX threads**
- **zlib, bzip2, lzma** development libraries
- **nlohmann/json** header (not bundled — install via your package manager)

Install the dependencies for your distro:

| Distro | Command |
|--------|---------|
| Fedora / RHEL 9+ | `sudo dnf install gcc-c++ zlib-devel bzip2-devel xz-devel json-devel` |
| RHEL 8 (EPEL) | `sudo dnf install gcc-toolset-12-gcc-c++ zlib-devel bzip2-devel xz-devel json-devel` |
| Debian / Ubuntu | `sudo apt install g++ zlib1g-dev libbz2-dev liblzma-dev nlohmann-json3-dev` |
| Arch Linux | `sudo pacman -S gcc zlib bzip2 xz nlohmann-json` |

Then build:

```bash
make clean && make
```

## Tests

```bash
make test        # dependency-free guards (shell + the binary): parse rate, TZ
make test-ui     # the jsdom/WebAssembly harnesses (npm install --prefix tests)
```

## WebAssembly build (browser)

slaplog can also be compiled to WebAssembly and run **entirely inside a browser
tab** — drop one or more log files and read the report, without anything
leaving the machine. Several files are analysed sequentially and aggregated
into a single report, with a progress indicator. This is an additional, fully
separate build target; the native build is unchanged.

**Live build:** <https://slaplog.pages.dev/>

```bash
make wasm                                   # -> wasm/web/slaplog.js + slaplog.wasm
python3 -m http.server -d wasm/web 8000     # then open http://localhost:8000/
```

It needs the Emscripten SDK (`em++`); zlib and bzip2 come from Emscripten's
ports and liblzma is cross-built automatically. See
[`wasm/README.md`](wasm/README.md) for the architecture and the details.

## License

AGPLv3-or-later — see `LICENSE` or `./slaplog -l`.

Full documentation: `./slaplog -D` or `doc/slaplog.md`.
