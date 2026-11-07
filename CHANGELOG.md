# Changelog

All notable changes to **slaplog** are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

The project is distributed under the **AGPL-3.0** license — see [LICENSE](LICENSE).

## [Unreleased]

### Added

- **`--log-format default`**: `default` is accepted as an alias of `debug`.
  It is a valid `olcLogFileFormat` value and slapd writes it exactly like
  `debug` (`logging.c` only takes the syslog/rfc3339 branch when
  `logfile_format > LFMT_DEBUG`), but the option used to fall back to
  auto-detection without saying so.

### Changed

- **Parsing is ~2.3× faster** on a single thread (1 M-line fixture: 8.28 s →
  3.47 s, ~120 k → ~290 k lines/s).  Three costs found with a profile were
  removed, with byte-identical reports (`-o json`, `-o replay`, `-o text`,
  `-o html`) on every fixture:
  - the top-100 operation table re-sorted all 101 rows after *every*
    completed operation; it is now a bounded sorted insert that rejects the
    common case in one comparison — this alone was more than half the parse
    time;
  - two PCRE2 searches per line were run to look for an OpenLDAP version
    banner even in logs that carry none; a byte-level pre-check now skips
    them (`"slapd"` followed by whitespace and a digit);
  - `parse_line()` takes a `std::string_view`, so the mapped line is no
    longer materialised into a `std::string` before being copied into
    `Event::raw`.

### Fixed

- **The top-operations and top-connections tables are now ranked for small
  logs.** The list was only sorted once it exceeded 100 rows, so a log with
  fewer operations printed them in insertion order — the "Top operations"
  table of a short sample was not sorted by `etime` at all.  Both lists are
  now kept in order at every size.
- **`ol26` and generic `rfc3339` timestamps were read as local time.**  Both
  formats went through `get_time()` + `mktime()`, so a UTC string was decoded
  with the analysing host's UTC offset: every timestamp was shifted, the
  fractional seconds were dropped, and an explicit `+02:00` designator was
  ignored.  They now use an arithmetic RFC3339 parser (`days_from_civil`) that
  honours `Z` / `±HH:MM` / `±HHMM`, defaults to UTC when the designator is
  missing, and keeps the nanosecond fraction.  The instant no longer depends
  on `TZ` (pinned by the new `tests/native/timestamps.sh`).
- **`-o replay` timestamps carried the same shift.**  The replay path
  re-parses an already-normalised UTC timestamp with
  `parse_any_timestamp()`, which used the same `mktime()` chain; replay rows
  now carry the exact UTC instant of the operation, fraction included.

## [5.0.1] - 2026-11-07

### Added

- **Wrong-file guard**: each input is sampled after decompression (up to 200
  lines or 512 KiB), and the sample is checked with the parser's own header
  detection.  A file with no recognisable `slapd` line — an LDIF export read by
  mistake, a config file, a binary — is skipped with
  `not an OpenLDAP log file` on stderr instead of filling the report with
  unknown lines.  The run still succeeds when another file was analysed, and
  exits 1 when nothing was.  The WebAssembly session applies the same rule and
  reports the skipped files.

## [5.0.0] - 2026-11-06

### Added

- **Behaviour patterns** (on by default): `--no-patterns` turns the collection
  off, `--pattern-seq-len N` sets the maximum length (default 4) of a repeated
  operation sequence.  Per bind account, search filters are generalised by
  masking their literal values — `employeeNumber=0*`…`904*` fold into one
  `employeenumber=#*` family, and runs of identical clauses into `(|(uid=$)+)` —
  and repeated operation sequences are counted as contiguous n-grams.  A new
  `patterns` section reports the filter families and sequences in text, HTML and
  JSON, with two donuts (*Cost per Operation Type*, *Filter Families by Cost*).
- **Cost per operation**: each bind account and each operation type ranked by
  its cumulative and average `etime` and its share of the total, in the
  `patterns` section (`cost_by_account` / `cost_by_type` in JSON).
- **Resource-hog verdict**: an account whose unindexed (substring/negated)
  filter family spends more than 20 % of the cumulative `etime` is named, with
  its family and share (`resource_hogs` in JSON).
- **Top consumer per hour**: the #1 account by `etime` in each hour, as a table
  (`top_consumer_per_hour` in JSON) and two charts — bars whose height is the
  busiest account's etime, coloured by account so a takeover reads as a run of
  one colour, plus a stacked area showing how each hour's total load was split
  between accounts. A durable takeover (an account that was rarely #1 before and
  leads most of the next 24 h) is marked by a vertical onset line on both charts,
  with a tooltip spelling it out.
- Displayed templates and sequences are truncated to 100 characters; the JSON
  keeps the full string.

### Changed

- `-c`/`--compact` now trims the report to what matters (text and HTML): every
  ranked table keeps its top 10 rows, then only rows above 1 % of that table's
  total — instead of the old "top 5 instead of top 20".
- The *Statistics* section is regrouped into run / scope / traffic / latency,
  drops the redundant FD-open and replication-log rows, renames "FD close
  events" to "Connections closed", groups the time range and the connection
  open/close into single rows, and adds the average `etime` per operation plus
  the top consumer (costliest account by etime, with its average and share).
- The analysis state is now schema 6 (schemas 1 through 5 still read): the
  filter families, operation sequences, per-type etime, detected log format and
  per-hour etime are stored.
- The HTML meta bar is reduced to a single discreet line — Generated / OpenLDAP
  / Servers / detected log format — with the processing and timing figures kept
  in the Statistics table.

### Fixed

- The CLI progress bar now recognises rotated logs whose compression extension
  is followed by a date suffix (`slapd.log.02.bz2_2026-10-30`), so the estimated
  total reflects the decompressed size instead of the on-disk size.
- When every file is done, the CLI progress bar reaches 100 % with the real
  total on both sides, instead of stalling below 100 % on a pessimistic
  estimate.
- The *Top Long Operations* table now truncates each filter to 100 characters
  (text and HTML) and HTML-escapes it, so a single generated filter (thousands
  of clauses) no longer bloats the report.

## [4.1.2] - 2026-10-20

### Changed

- The filter dimensions (filters, their nentries=1/0 and wildcard views, and the filter-by-application table) intern their keys in one shared pool and store the entries in open-addressing tables instead of `std::map<std::string,…>`.  Same reports, byte for byte; a two-day export's browser heap drops 350 → 266 MB (native RSS 374 → 247 MB) and a 1 GiB log's state now fits the 128 MB initial heap.
- Smaller aggregate: the filter/attributes map that no report read is gone, the connection timeline is packed (9 bytes per event) and varint-encoded in the state (schema 2; schema 1 still reads), and unparsed lines are only kept when `--unknown-lines` asks for them.  Measured: the 1 GiB reference log's state 2.1 → 1.6 MB and its resume heap 221 → 128 MB; a two-day export's state 11.5 → 7.6 MB.

### Fixed

- The browser pre-flight was pessimistic by a factor of three: it assumed the whole selection was held in memory, while files are parsed one at a time (the peak is the accumulated analysis plus the largest file). A 3.67 GiB selection in ~1 GiB files is now accepted instead of warning at 2.75 GiB, and the result line reports the peak memory actually used.
- *Errors per Application* listed informational result codes (success, compareFalse/True, referral, saslBindInProgress), one row per application.  Only failures are listed now; a resumed state is normalised on load, and `error_counts` still accounts for every result.

## [4.1.1] - 2026-10-20

### Fixed

- WASM page: replaying a state file with no log crashed (`files[0]` undefined).  The report is now titled after the state, and its downloads are named after it.

## [4.1.0] - 2026-10-20

### Added

- `--save-state FILE` / `--resume FILE`: fold successive analyses into one report (xz-compressed, versioned, clear `SLAPSTAT` header); `--resume` is repeatable and merges state files; a resume refuses a log naming a server the states do not hold. Also in the WASM page (*Resume a previous analysis*, *Download state* or the *Also save the state* box; a dropped state file is routed by its header).
- Repeated `-o`: `-o html=report.html -o json=report.json` writes several reports in one run.

### Fixed

- Exact ties made the report depend on merge order: two runs of one command could disagree on the top-100 rows and the slowest operation/connection.

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

[5.0.1]: https://github.com/zx97/slaplog/releases/tag/v5.0.1
[5.0.0]: https://github.com/zx97/slaplog/releases/tag/v5.0.0
[4.1.2]: https://github.com/zx97/slaplog/releases/tag/v4.1.2
[4.1.1]: https://github.com/zx97/slaplog/releases/tag/v4.1.1
[4.1.0]: https://github.com/zx97/slaplog/releases/tag/v4.1.0
[4.0.5]: https://github.com/zx97/slaplog/releases/tag/v4.0.5
[3.9.0]: https://github.com/zx97/slaplog/releases/tag/v3.9.0
[3.8.0]: https://github.com/zx97/slaplog/releases/tag/v3.8.0
[3.7.0]: https://github.com/zx97/slaplog/releases/tag/v3.7.0
[3.6.2]: https://github.com/zx97/slaplog/releases/tag/v3.6.2
[3.6.1]: https://github.com/zx97/slaplog/releases/tag/v3.6.1
[3.6.0]: https://github.com/zx97/slaplog/releases/tag/v3.6.0
[3.1.0]: https://github.com/zx97/slaplog/releases/tag/v3.1.0
[3.0.1]: https://github.com/zx97/slaplog/releases/tag/v3.0.1
[3.0.0]: https://github.com/zx97/slaplog/releases/tag/v3.0.0
