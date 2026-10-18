# Changelog

All notable changes to **slaplog** are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/), and this project
adheres to [Semantic Versioning](https://semver.org/).

The project is distributed under the **GNU Affero General Public License
v3.0 (AGPL-3.0)** — see the [LICENSE](LICENSE) file for the full text.

## [Unreleased]

### Added

- **A floating section index in the HTML report**, fixed in the top-right
  corner.  It lists every section the report actually drew (charts are not
  sections) and scrolls to one on click; its heading collapses the list.  The
  links are built from the page's own `<h2 id>` elements, so the index can never
  offer a section that is not there and never drifts from a renamed heading.
- **The server(s) the analysed logs come from.**  The hostname is read from the
  syslog/rfc3339 header prefix of every parsed line, deduplicated, and shown in
  the meta bar and the *Statistics* table.  The *debug* log format carries no
  hostname, so for it nothing is shown rather than a name being invented — and a
  log taken from several servers lists them all.
- **Paged searches (RFC 2696).**  Searches that carried the
  `pagedResultsControl` (`1.2.840.113556.1.4.319`), counted and broken down by
  the identity that issued them, in a new *Paged Searches* section (HTML, text
  and JSON, and `-s paged`).  slapd logs the control only at `loglevel trace`,
  as `=> get_ctrls: oid="1.2.840.113556.1.4.319" (critical)`; that line carries
  no `conn=`, so the control is attributed to the connection of the next line
  that names one — normally the `SRCH` that asked for it.  At the usual `stats`
  level there is no such line, the count stays zero and the section is absent:
  it is not that no client paged, it is that the log cannot say.
- **An eighth chart, *Response Time Density***: the same etime distribution as
  *Response Time Distribution*, but with logarithmically spaced bins (×1.58 per
  step) and an x window that follows the data.  The eleven fixed buckets cannot
  show the shape of a distribution that fits inside one of them — on the 1 GiB
  reference log 99.9992 % of the operations finish under 1 ms, which is one bar
  and one sliver.  On a log axis the shape appears where the traffic actually
  is: on that same log the profile is bimodal (one hump at the log's own
  resolution, a second at ~20 µs), which the coarse chart could not show.  It is
  also the only axis on which a log-normal latency — the usual model — looks
  like a bell, so a reader looking for one either finds it or learns the data
  has no such shape.
### Removed

- **Every *How to read it* note, and the mechanism that drew them.**  Earlier in
  this same release every chart carried one; reading the report showed why that is
  the wrong rule.  Notes landed under charts that need no explaining (a share ring,
  a connection curve), and the one chart that genuinely stopped a reader dead — the
  right-hand side of the result-code breakdown — had a note that talked past it.
  The last one went away with the bars it described, replaced by a pie that needs no
  caption: a note under a drawing nobody is stuck on is noise, and a note that
  misses the point is worse than none.  A chart that needs a word now says it in
  its subtitle, where the reader is already looking.

### Fixed

- **The *Result Code Breakdown* chart had no scale for its bars.**  A bar's
  length is a logarithm, so the only axis the drawing carried was 0 % … 100 % —
  the cumulative scale of the curve that then ran down the other side — and a
  reader had two curves' worth of percentages and nothing to measure a bar
  against.  The bar axis is now labelled under the bars, in decades (each step
  ×10, or quarters of the busiest code when the range is too small for a log),
  with a gridline per step.

### Changed

- **The HTML *Statistics* table is laid out two metrics per row.**  The section
  carries little data, and a single column made it far taller than it needed to
  be; it now reads as two label/value pairs side by side.  The metrics are
  unchanged.
- **A fifth result-code class, for the refusals the log cannot attribute.**  The
  classification split result codes by who is at fault: green informational, amber
  client-side, violet by configuration, red slapd itself.  Reading a real log showed
  one gap in it.  A handful of codes answer *the same* when a client asks for what
  it has no right to see and when a client's legitimate request meets a
  configuration it should not have met: `8 strongerAuthRequired`, `13
  confidentialityRequired`, `50 insufficientAccessRights`, `53 unwillingToPerform`
  (the numeric limits `3`, `4`, `11` do not have this property — the client is told
  the limit and can page or split around it).  Filing those under *by
  configuration* quietly blamed the configuration for every refused ACL, and filing
  them under *client-side* would have blamed the client every time an ACL was too
  tight.  They now form a class of their own, drawn as a diagonal amber/violet
  **hatch** — violet, the class it is closest to, as the base; amber, the other
  candidate, on the stripes — wherever a class colour was used: the table rows (a
  pale hatch behind the code and its name, which keep their violet text), the
  colour key, the stacked error bands, the breakdown bars and pie slices, and the
  failing-codes donut and its legend.  Names, tooltips and the text report read
  "by configuration, or client-side"; the text/ANSI report keeps the violet, since
  it cannot hatch.

- **The right-hand side of the *Result Code Breakdown* is a pie, not a stack of
  bars.**  That side has now been drawn four ways, and the pie is the one that needs
  no words.  It began as the cumulative share drawn as a curve, with the same
  figures printed again in a text column beside it — one number rendered twice,
  neither of them readable row by row: past the sixth code every figure reads 100 %
  because six codes cover 99.99 % of everything, and the reader has to interpolate
  between 24 px rows to answer a question that is asked row by row.  It became one
  flat bar per row, which answered once the row was found but still hid *how* the
  sum was built; then those bars stacked, so the sum could be watched being built,
  which took a note to be read at all.  The pie of the same codes — same order, same
  colours, sized by area — says it with nothing: one huge slice, then crumbs, which
  is what a result-code distribution is.  Every code still keeps one colour, the one
  it shows on its bar, so a slice is found on the left without a legend.

- **The right-hand side of the *Response Time Distribution* chart is gone.**  It
  carried a cumulative share curve with its own 0-100 % axis and a column
  repeating its figures.  The bars beside it already carried every figure it
  derived from, and on that axis each row past the second reads 100 % — the
  buckets are ordered, so the sum saturates immediately and the reader has to
  work out what the number refers to, for nothing.  The bars now have the width
  the curve and its label column took, and their shares are printed with the same
  four significant digits as the rest of the report: a bucket holding eleven
  operations out of a million used to read "11  (0.0%)", which looks like a bug
  next to the exact count printed with it.

- **The *Errors Over Time* curve is now stacked by result code.**  The
  silhouette is unchanged — it is still the total of failing results, exactly
  where a single curve was — but the colour underneath says which code built
  each part of it: amber for what the client asked, violet for what the
  configuration refuses, red for what slapd failed to do, shaded by rank so two
  codes of one class stay distinguishable, with a grey band folding the smaller
  codes.  A peak in one colour is one problem, a rise spread over several is a
  general one.  The legend under the chart names each band and its share, and
  the tooltip lists the codes a slice is made of.  This required keeping the
  result code with each error timestamp (`error_times_by_code`); the memory
  bound (`MAX_ERROR_TIMES`) is unchanged.

- **Four more charts in the html report**, alongside *Simultaneous Connections*
  and *Resource Consumers by Bind Account*:
  - *Errors Over Time* — **failing** results only, on the same time window as
    the connection chart;
  - *Response Time Distribution* — how many operations fall into each etime
    bucket, which makes a latency tail visible at a glance;
  - *Operation Types* — the share of SRCH / BIND / MOD / … ;
  - *Result Code Breakdown* — every result code, successes included, as bars
    coloured by class, with the same codes drawn as a pie on the right, sitting
    directly
    under the table it belongs to.  The bars are on a log scale, because counts
    span five orders of magnitude and a linear scale would leave every code but
    the first invisible, so each bar carries its exact count and share;
  - *Failing Result Codes* — the share of each failing result code; the
    informational results are counted and named in a note under the legend
    instead of being drawn as slices.
- **A colour key for the result codes**, printed above the table and built from
  the same colours as the table cells, the bars and the slices — the five class
  colours, the hatched one drawn as the same amber/violet diagonal it shows in
  the charts — so the page cannot be read without knowing what amber and violet
  mean.
- **Downtime bands and restart markers** on the connection chart: a shaded band
  materialises every period the server was down, and a start that is *not*
  preceded by a shutdown is drawn in orange as a probable abrupt termination
  (crash, OOM, kill -9).  A band is only drawn where the log shows no traffic,
  so a stop whose restart lives in another rotated file no longer shades an
  active half of the chart.
- **OpenLDAP version**: read from the startup banner
  (`@(#) $OpenLDAP: slapd X.Y.Z …` or `slapd X.Y.Z (…)`) when the log carries
  one, and reported in the Statistics table, the html meta bar and the JSON
  output.  Recognising the line also stops it being counted as unknown.  Many
  installations never log that banner — slapd writes it to stderr before
  switching to syslog — and nothing is displayed when it is absent.

- **Long tables are collapsed in the html report**: only the first 25 rows are
  shown and the tail is revealed by a *show N more row(s)* button.  This is done
  generically in the page, so every section benefits without its emitter having
  to know about it.

- **The WebAssembly page shows the engine version** in its footer, read from the
  module (`slaplog_version()`) so it can never drift from `version.hpp`, and
  **each selected file can be removed individually** with the trash button beside
  its name — duplicates are ignored, so picking the same file twice no longer
  analyses it twice.

### Changed

- **`embedded.hpp` is a generated file now.**  It carries `LICENSE` and
  `doc/slaplog.md` as raw string literals for `-l` / `-D`, and those two copies
  had been maintained by hand since the beginning: they had drifted 131 lines
  apart, each side holding content the other lacked, so `-D` and the file it
  advertises were telling different stories.  `doc/slaplog.md` is the single
  source (as is `LICENSE` for the licence text), `tools/gen_embedded.py` splices
  them into `tools/embedded.hpp.in`, and `make` regenerates the header as soon
  as either source changes — `make check-doc` fails when it is stale.  The
  content recovered from the embedded copy while merging: the `version.hpp` and
  `print_replay_report()` entries, the `LogFormat` / `try_parse_header()` /
  `convert_to_rfc3339_utc()` helpers and a complete combined jMeter example.

- **Session tracking correlations are grouped by client.**  The tracking name
  usually carries a per-session identifier, so the section listed one row per
  session — 10 000+ essentially unique rows on a busy log.  It is now grouped by
  client and sorted by session count, and shows the number of distinct NAT
  addresses as well as the name with its session id stripped.  On a real log the
  section went from 10 459 rows to 231, and the whole html report from 2.1 MB to
  363 kB.
- **Result codes now say who is at fault, not just "error or not".**  Each code
  is classified into one of four classes, and the class drives every colour on
  the page — the text report, the html cells, the colour key and all the charts:

  | colour | class | codes |
  |---|---|---|
  | green | informational — the operation did what was asked, or the protocol is progressing | `0`, `5`, `6`, `10`, `14` |
  | amber | client-side — the request, the identity or the data were at fault, slapd answered correctly | `2`, `7`, `16`–`21`, `32`, `34`, `48`, `49`, `64`–`69` |
  | violet | by configuration — a limit the server was told to enforce, a requirement it was told to impose | `3`, `4`, `8`, `11`, `13`, `50`, `53` |
  | red | server-side — slapd itself: internal error, overload, unavailable backend, broken alias | `1`, `12`, `33`, `36`, `51`, `52`, `54`, `71`, `80` |

  Only the red class says anything about the directory's health, which is the
  whole point: three situations that shared one undifferentiated red now read
  apart, and the two limits an administrator configures on purpose stop looking
  like breakage.  `53 unwillingToPerform` is in the violet class rather than
  among the failures: OpenLDAP returns it when it refuses *by policy* (a referral
  it will not follow, a TLS requirement, a password-policy outcome), which is a
  decision.  The classification lives in `log_parser.cpp` — the parser filters on
  it and the reports colour by it, so the two can no longer drift — and the four
  classes cover the whole mnemonic table exactly; a code outside it is reported
  server-side (`unknown`) rather than guessed into a harmless class.
- **The result-code charts no longer count informational results as failures.**
  The donut (*Failing Result Codes*) draws the failing codes only and states
  under its legend how many results were left out and which codes they were, and
  *Errors Over Time* plots failing results only, with its subtitle saying so.  On
  a 1 GiB production access log this is not a rounding detail: of 1 430 765
  results, 1 077 005 are informational and only 353 760 are failures, and the
  Compare answers alone (169 894) were 32 % of the donut's slices — the failure
  count read 48 % higher than it is, and the temporal curve showed a level of
  traffic that had nothing to do with errors.
- **Charts are capped at 1100 px and centred** instead of stretching to the full
  width of a wide window.
- **Each chart is emitted under the section whose data it draws** — connections
  under *Statistics*, operation types under *Operation Counts*, both result-code
  charts under *LDAP Result Codes*, bind-account consumers under *Top
  Applications*, and the latency distribution under *Top Long Operations* —
  instead of all of them being grouped in one block.
- The *Resource Consumers by Bind Account* legend and tooltip now also show the
  operation count and the average time per operation, so an account that tops
  the chart through volume (many short operations) can be told apart from one
  that tops it through weight (a few very long ones).

### Fixed

- **Result-code chart colours survive being rendered.**  They were emitted as
  the SVG presentation attribute `fill`, which a stylesheet rule on the
  element's class silently overrides: `.sl-bar{fill:#3498db}` repainted every
  class-coloured bar blue while `fill="#27ae60"` sat right there in the markup.
  Colours are inline `style` now — one explanation of the trap is written once,
  next to the helper — and a test asserts the presence of the style *and* the
  absence of the attribute.  A rasterised PNG is what caught it: every assertion
  on the HTML passed, because the markup really did carry the right colours.
- WebAssembly page robustness on large inputs: the in-memory copy of a
  compressed file is now freed once it has been parsed (it used to stay in the
  module's filesystem for the whole session), and an out-of-memory abort is
  reported with an actionable message — including the reload the dead module
  requires — instead of a raw `RuntimeError`.
- **The WebAssembly size pre-flight is now calibrated on measurements** instead
  of guesswork: on a 1 GiB production log the module's heap peaks at 1.12× the
  input with the charts and 1.02× without, so the safe ceiling is about 2.75 GiB
  (3.0 GiB without charts) rather than the 512 MiB the previous heuristic used —
  which flagged a perfectly viable 1.09 GiB selection and predicted an abort that
  would not happen.  The warning no longer claims a run *will* abort, states the
  safe size it computed, and gives each lever its real weight (the charts are
  worth about 10 %, not "most of the memory").
- Chart hover areas for the lifecycle markers were emitted *before* the 240
  per-bucket strips and were therefore never reached by the mouse; they are now
  emitted last.  Marker dots are staggered as well, so the several events of one
  restart — seconds apart, hence a few pixels — stay visible instead of being
  overdrawn by the last one.

## [3.8.0] - 2026-10-17

### Added

- **Charts in the HTML report**: two inline SVG graphs, drawn by default and
  disabled with the new `--no-graph` option (the WASM page has a matching
  "No charts" checkbox, unchecked by default):
  - *Simultaneous Connections* over the analysed time range, with a marker on
    every server start/stop event;
  - *Resource Consumers by Bind Account*, showing each bind DN's share of the
    cumulative operation time (falling back to the operation count when the
    log carries no timings).

  Both are interactive: a tooltip follows the mouse and reads the value from
  the element under the cursor. The data they need is collected only when it
  will be used, so the text, JSON and replay outputs are unchanged.

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

[3.8.0]: https://github.com/zx97/slaplog/releases/tag/v3.8.0
[3.7.0]: https://github.com/zx97/slaplog/releases/tag/v3.7.0
[3.6.2]: https://github.com/zx97/slaplog/releases/tag/v3.6.2
[3.6.1]: https://github.com/zx97/slaplog/releases/tag/v3.6.1
[3.6.0]: https://github.com/zx97/slaplog/releases/tag/v3.6.0
[3.1.0]: https://github.com/zx97/slaplog/releases/tag/v3.1.0
[3.0.1]: https://github.com/zx97/slaplog/releases/tag/v3.0.1
[3.0.0]: https://github.com/zx97/slaplog/releases/tag/v3.0.0
