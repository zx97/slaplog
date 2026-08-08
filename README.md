
# slaplog — OpenLDAP Log Analysis Tool

**SPDX-License-Identifier:** AGPL-3.0-or-later  
**License:** GNU Affero General Public License v3.0 (https://www.gnu.org/licenses/agpl-3.0.txt)  
**Version:** 3.6.0  
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

- **4 output formats**: text/ANSI color, HTML (standalone with CSS), JSON, replay (for jMeter/LoadRunner)
- **Parallel processing**: one thread per file, no mutex contention
- **Compressed logs**: `.gz`, `.bz2`, `.xz` transparently handled
- **Session tracking**: correlates NAT'd IPs to real clients via `[IP=... NAME=... USERNAME=...]`
- **Section filtering**: `-s all` (default) or select specific sections
- **Top-N analysis**: 100 slowest ops, busiest connections, most-used filters
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

## License

AGPLv3-or-later — see `LICENSE` or `./slaplog -l`.

Full documentation: `./slaplog -D` or `doc/slaplog.md`.
