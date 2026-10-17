# Changelog

All notable changes to **slaplog** are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

The project is distributed under the **GNU Affero General Public License
v3.0 (AGPL-3.0)** — see the [LICENSE](LICENSE) file for the full text.

## [3.7.0] - 2026-10-17

### Added

- **WebAssembly build** (`make wasm`): slaplog can now be compiled to
  WebAssembly and driven from a browser page, analysing one or more
  dragged-and-dropped log files entirely on the client (sequential processing,
  aggregated into a single report, with a progress indicator). The native build
  is untouched: the WASM target compiles a separate entry point
  (`wasm/wasm_main.cpp`) and reuses `log_parser.cpp` / `report.cpp` as-is.
  Plain, gzip, bzip2 and xz inputs are all supported. liblzma is cross-built
  once by `wasm/build_liblzma.sh`; zlib and bzip2 come from Emscripten's ports.
  A live build is available at <https://slaplog.pages.dev/>.

### Fixed

- **Ordering of rows with equal timings.** The replay report and the top-N
  tables were sorted with comparators that only looked at the timing
  (`etime` / `total_etime`) or at `timestamp`/`conn`/`op`, leaving rows that
  compared equal in an order defined by the sort *implementation*. Because
  `std::sort` and `std::partial_sort` are not stable, libstdc++ (GCC) and
  libc++ (clang/Emscripten) ordered those rows differently, so the same log
  could render in a different order — and a different set of rows could
  survive the top-100 cut. All ordering paths now use a total comparator, so
  the result is identical on any standard library.
- **Timestamp resolution.** Timestamps previously used
  `std::chrono::system_clock::time_point`, whose resolution is nanoseconds on
  libstdc++ but microseconds on libc++, so `debug`-format sub-microsecond
  fractions were truncated in the WASM build. They are now held in
  `SystemTimePoint` (nanosecond resolution) everywhere.

  Note: where many operations genuinely share the same timing, the previous
  order was not defined by the code but chosen by the sort *implementation*;
  it is stable for a given standard library but is not portable and cannot be
  reproduced by an explicit comparator. The rows and metrics are unchanged, but
  their order (and, at the top-100 boundary, the selected subset) may differ
  from earlier releases. On real production logs, whose slowest operations have
  distinct timings, the output is byte-for-byte identical: verified against
  release binaries on eight slapd 2.6 logs ranging from 36 MB to 438 MB (up to
  2.9 M lines), in text, JSON, HTML and replay form.

## [3.6.2] - 2026-08-17

### Fixed

- `-o replay` now emits a line for **every** operation, including those that
  have no RESULT line in the slapd access log:
  - `ABANDON` and `UNBIND` are written immediately from their own log line.
    `ABANDON` stores the numeric message id of the operation to cancel in the
    `filter` column (the value read by the `jMeter_OpenLDAP_replay` replayer).
  - Operations still in-flight when a connection closes (e.g. an abandoned
    search) are flushed to the replay output at the end of processing.
- Fixed an off-by-one in the `MODRDN` dispatch that made `MODRDN` lines parse
  as unknown and lose their type.
- Write operations (`ADD`, `DEL`, `MOD`, `MODRDN`) now carry their target DN
  in the `base` column instead of dropping it. `CMP`/`COMPARE` carry the entry
  DN in `base`.

## [3.6.1] - 2026-08-17

### Fixed

- Track `version.hpp` in the repository so a fresh clone builds out of the box.

## [3.6.0] - 2026-08-08

### Added

- Replay output written to a temporary file during processing, bounding memory
  usage regardless of log size.
- `--replay-limit N` option to cap the number of operations written to the
  replay file (default `1000000`, `0` = unlimited).

## [3.1.0] - 2026-06-01

### Added

- Streaming of unknown lines directly to a file instead of buffering them in
  memory.

## [3.0.1] - 2026-05-28

### Fixed

- Session-tracking correlation deduplication and assorted fixes.

## [3.0.0] - 2026-05-28

### Added

- Initial release: OpenLDAP slapd access-log analyzer with text/HTML/JSON
  reports, parallel processing, compressed-log support, and session tracking.

[3.7.0]: https://github.com/zx97/slaplog/releases/tag/v3.7.0
[3.6.2]: https://github.com/zx97/slaplog/releases/tag/v3.6.2
[3.6.1]: https://github.com/zx97/slaplog/releases/tag/v3.6.1
[3.6.0]: https://github.com/zx97/slaplog/releases/tag/v3.6.0
[3.1.0]: https://github.com/zx97/slaplog/releases/tag/v3.1.0
[3.0.1]: https://github.com/zx97/slaplog/releases/tag/v3.0.1
[3.0.0]: https://github.com/zx97/slaplog/releases/tag/v3.0.0
