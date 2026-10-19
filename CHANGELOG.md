# Changelog

All notable changes to **slaplog** are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

The project is distributed under the **AGPL-3.0** license — see [LICENSE](LICENSE).

## [Unreleased]

### Added

- `--save-state FILE` / `--resume FILE`: fold successive analyses into one report (xz-compressed, versioned); also in the WASM page (*Resume a previous analysis*, *Download state*).
- Repeated `-o`: `-o html=report.html -o json=report.json` writes several reports in one run.

## [4.0.5] - 2026-10-19

### Added

- PCRE2 regex engine (JIT in the native build), SIMD line splitting, memory-mapped I/O, parallel decompression.
- Per-server coverage lanes on both time-series charts.
- Spans no server's log covers are shaded on both time charts, keyed *no log*, with a tooltip.
- `--title` option (native CLI and WASM `slaplog_set_title()`).
- `--no-version`: the report footer names neither the engine nor its version.
- `-o tabhtml`: the HTML report grouped into five tabs mapped on the log's objects (Overview, Server, Process, Connections, Operations), all always shown — presentation only, every section stays in the DOM for printing and deep links.
- Clickable table headers: sort any report table by a column (arrow, `aria-sort`, keyboard); the *show more* fold follows the sorted order.
- Error `text=` field shown in *LDAP Result Codes* and *Errors per Application* (text, HTML, JSON).
- JSON key `error_counts_by_app`.
- Progress bar based on measured compression ratios.
- Folder picking and per-file removal in the WASM page.
- `tests/` tree, `make test`, `make test-ui`.
- Short options accept an attached value (`-j4`, `-ohtml`, `-sstats`).

### Changed

- WASM xz decompression uses liblzma instead of spawning `xz`.
- The section index opens with the report, then tucks into a three-line window on the section being read.
- The WASM file list scrolls instead of truncating; a file is keyed by its path inside the selection.

### Fixed

- Progress bar with compressed logs: the total was the on-disk size, so it hit 100 % almost immediately (CLI) or stalled (WASM); the estimate now applies measured expansion ratios (xz 17.7x, bzip2 20.6x, gzip 13.3x).
- Peak active connections: a multi-server run reported the busiest server, not the peak of the sum; it is recomputed from the merged timeline, which is now collected even with `--no-graph`.
- `-o json --title` failed outright; JSON and replay ignore `--title` by design.
- WASM title truncated at the first space or hyphen; quoted-string and JS quoting fixed.
- `-s server` and `-s wildcards` selected nothing.
- Syslog timestamps: independent of `TZ`, ~4x faster.
- Non-reentrant `gmtime`/`localtime` replaced by their `_r` forms (wrong chart windows under threads).
- Error texts per application, not global per result code.

## [3.9.0] - 2026-10-18

### Added

- Section index; server names; paged searches; cluster load per server; bind usage; three charts.

### Fixed

- Result-code colours, WASM memory/OOM handling, chart hover order, bar axis.

## [3.8.0] - 2026-10-17

### Added

- Two SVG charts; `--no-graph`.

## [3.7.0] - 2026-10-17

### Added

- WebAssembly build and page.

### Fixed

- Nanosecond timestamps; deterministic ordering.

## [3.6.2] - 2026-08-17

### Fixed

- Replay emits every operation; MODRDN dispatch; write DN in `base`.

## [3.6.1] - 2026-08-17

### Fixed

- `version.hpp` tracked.

## [3.6.0] - 2026-08-08

### Added

- Replay temp file; `--replay-limit`.

## [3.1.0] - 2026-06-01

### Added

- Streaming of unknown lines.

## [3.0.1] - 2026-05-28

### Fixed

- Session-tracking correlation deduplication.

## [3.0.0] - 2026-05-28

### Added

- Initial release.

[3.9.0]: https://github.com/zx97/slaplog/releases/tag/v3.9.0
[3.8.0]: https://github.com/zx97/slaplog/releases/tag/v3.8.0
[3.7.0]: https://github.com/zx97/slaplog/releases/tag/v3.7.0
[3.6.2]: https://github.com/zx97/slaplog/releases/tag/v3.6.2
[3.6.1]: https://github.com/zx97/slaplog/releases/tag/v3.6.1
[3.6.0]: https://github.com/zx97/slaplog/releases/tag/v3.6.0
[3.1.0]: https://github.com/zx97/slaplog/releases/tag/v3.1.0
[3.0.1]: https://github.com/zx97/slaplog/releases/tag/v3.0.1
[3.0.0]: https://github.com/zx97/slaplog/releases/tag/v3.0.0
