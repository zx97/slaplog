# slaplog — OpenLDAP Log Analysis Tool

+ ----------------------------------------------------------------------------------------------- +
| **SPDX-License-Identifier:** AGPL-3.0-or-later                                                  |
| **License:** GNU Affero General Public License v3.0 (https://www.gnu.org/licenses/agpl-3.0.txt) |
| **Version:** 3.0.0                                                                              |
| **Author:** Manuel FLURY                                                                        |
| **Copyright:** © 2026 Manuel FLURY. All rights reserved.                                        |
|                                                                                                 |
| This file is part of slaplog - an OpenLDAP Log Analysis Tool.                                   |
|                                                                                                 |
| Licensed under the GNU General Public License v3.0 (GPL-3.0-or-later).                          |
| See the LICENSE file distributed with this work for full license text.                          |
|                                                                                                 |
| THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR                     |
| IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,                        |
| FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL                        |
| THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN                     |
| AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN                            |
| CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                      |
+ ----------------------------------------------------------------------------------------------- +

Parse, analyze, and produce structured reports from OpenLDAP slapd access logs.

## Quick start

```bash
make
./slaplog /var/log/slapd/access.log
./slaplog -o html -r /var/log/slapd/ > report.html
./slaplog -s stats,sessions -c /var/log/slapd/access.log
```

## Features

- **3 output formats**: text/ANSI color, HTML (standalone with CSS), JSON
- **Parallel processing**: one thread per file, no mutex contention
- **Compressed logs**: `.gz`, `.bz2`, `.xz` transparently handled
- **Session tracking**: correlates NAT'd IPs to real clients via `[IP=... NAME=... USERNAME=...]`
- **Section filtering**: `-s all` (default) or select specific sections
- **Top-N analysis**: 100 slowest ops, busiest connections, most-used filters
- **Server events**: start/stop/shutdown detection
- **Restart-aware**: handles slapd connection-ID counter resets

## Usage

```
Usage: ./slaplog [options] <logfile|directory> [file|dir ...]

Options:
  -o, --output FORMAT        text | textcolor | html | json
  -c, --compact              Top 5 instead of top 20
  -r, --recursive            Recurse into directories
  -s, --section LIST         Comma-sep section list: all,stats,ops,errors,
                             bases,filters,attrs,apps,extops,csn,server,
                             index,sessions,topops,topconns,...
  --unknown-lines FILE       Write unparseable lines to FILE
  --unknown-lines-only FILE  Like above but skip report
  -d, --documentation        Print full documentation
  -l, --licence              Print AGPLv3 license
  --debug                    Verbose diagnostics
  -h, --help                 Show help
  -V, --version              Show version
```

## Build requirements

- C++17 compiler (GCC)
- POSIX threads
- `zlib`, `bzip2`, `lzma` development libraries
- `nlohmann/json` (bundled or system)

```bash
make clean && make
```

## License

AGPLv3-or-later — see `LICENSE` or `./slaplog -l`.

Full documentation: `./slaplog -d` or `doc/slaplog.md`.
