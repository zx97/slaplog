# Changelog

All notable changes to **slaplog** are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

The project is distributed under the **GNU Affero General Public License
v3.0 (AGPL-3.0)** — see the [LICENSE](LICENSE) file for the full text.

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

[3.6.2]: https://github.com/zx97/slaplog/releases/tag/v3.6.2
[3.6.1]: https://github.com/zx97/slaplog/releases/tag/v3.6.1
[3.6.0]: https://github.com/zx97/slaplog/releases/tag/v3.6.0
[3.1.0]: https://github.com/zx97/slaplog/releases/tag/v3.1.0
[3.0.1]: https://github.com/zx97/slaplog/releases/tag/v3.0.1
[3.0.0]: https://github.com/zx97/slaplog/releases/tag/v3.0.0
