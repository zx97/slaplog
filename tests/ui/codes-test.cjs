#!/usr/bin/env node
const SL = require("../lib/env.cjs");
// codes-test.cjs — how LDAP result codes are presented (text + HTML).
//
// The reference log is tests/fixtures/slaplog-sample/access.log plus four lines
// added below, so it holds exactly one code of every class:
//
//   0 success (22), 5 compareFalse (1)      -> informational, "not a failure"
//   32 noSuchObject (1), 49 invalidCredentials (1)   -> client-side
//   4 sizeLimitExceeded (1)                 -> by configuration (pure)
//   8 strongerAuthRequired (1), 50 insufficientAccessRights (1),
//   53 unwillingToPerform (1)               -> by configuration, or client-side
//                                              (the hatched class)
//   52 unavailable (1)                      -> slapd itself
//
// 30 results, 23 of them informational, 7 real failures (1 pure-policy, 3 dual).
// Every expectation below follows from those numbers, not from what the report
// happens to print.
//
// The last group of checks is a regression test for a bug only a render caught:
// colours were emitted as the SVG presentation attribute `fill`, which a
// stylesheet rule on the element's class silently overrides — every bar of the
// result-code chart rendered blue while its markup said #27ae60.  Colours must
// now be inline `style`, which wins, and the check fails on the old form.
const fs = require("fs");
const { execFileSync } = require("child_process");

const SLA = "" + SL.ROOT + "/slaplog";
const LOG = SL.SCRATCH + "/codes.log";
const SAMPLE = "" + SL.FIXTURES + "/slaplog-sample/access.log";

let failures = 0, checks = 0;
function check(name, ok, detail) {
  checks++;
  if (!ok) { failures++; console.log("  FAIL  " + name + (detail ? "\n        " + detail : "")); }
  else console.log("  ok    " + name);
}
const run = (args) => execFileSync(SLA, args, { encoding: "utf8", maxBuffer: 1 << 28 });

// ---------------------------------------------------------------- fixtures
const extra = [
  "6a734745.00000099 0x7f9c1e33a700 conn=1900 op=0 SEARCH RESULT tag=101 err=52 qtime=0 etime=9 nentries=0 text=Server is unavailable",
  "6a734745.0000009a 0x7f9c1e33a700 conn=1900 op=1 SEARCH RESULT tag=101 err=4 qtime=0 etime=2 nentries=0 text=Size limit exceeded",
  "6a734745.0000009b 0x7f9c1e33a700 conn=1900 op=2 SEARCH RESULT tag=101 err=50 qtime=0 etime=1 nentries=0 text=Insufficient access",
  "6a734745.0000009c 0x7f9c1e33a700 conn=1900 op=3 RESULT tag=97 err=8 qtime=0 etime=1 text=strongerAuthRequired",
].join("\n") + "\n";
const base = fs.readFileSync(SAMPLE, "utf8");
if (!fs.existsSync(LOG) || fs.readFileSync(LOG, "utf8") !== base + extra)
  fs.writeFileSync(LOG, base + extra);

console.log("result code presentation");

// ------------------------------------------------------------------- JSON
// The data keeps every code: only the *presentation* filters information out,
// so a consumer of the JSON report still sees the whole picture.
const json = JSON.parse(run(["-o", "json", "-q", LOG]));
const counts = {};
for (const [code, v] of Object.entries(json.error_counts)) counts[code] = v.count;
const want = { "0": 22, "4": 1, "5": 1, "8": 1, "32": 1, "49": 1, "50": 1, "52": 1, "53": 1 };
check("JSON error_counts still holds every code, informational included",
      JSON.stringify(counts) === JSON.stringify(want), JSON.stringify(counts));

// -------------------------------------------------------------------- text
const text = run(["-o", "text", "-q", LOG]);
check("text: informational codes are recalled in a note",
      text.includes("Not errors (informational): 0 success, 5 compareFalse"));
check("text: the table lists every code",
      ["0", "4", "5", "8", "32", "49", "50", "52", "53"].every(
        (c) => new RegExp("\\| " + c + " +\\|").test(text)));

// -------------------------------------------------------------------- HTML
// Headings carry an id (the floating index links to it), so the match
// tolerates attributes on the <h2>.
const h2re = (title) =>
  new RegExp("<h2[^>]*>" + title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "</h2>");
const html = run(["-o", "html", "-q", LOG]);
const section = (title, next) => {
  const i = html.search(h2re(title));
  if (i < 0) return "";
  const j = next ? html.search(h2re(next)) : html.length;
  return html.slice(i, j < 0 ? html.length : j);
};

const table = section("LDAP Result Codes", "Result Code Breakdown");
const breakdown = section("Result Code Breakdown", "Failing Result Codes");
const donut = section("Failing Result Codes", "Errors Over Time");
const overtime = section("Errors Over Time", null);

check("HTML: the four result-code sections are present, in order",
      ["LDAP Result Codes", "Result Code Breakdown", "Failing Result Codes",
       "Errors Over Time"].every((t) => h2re(t).test(html)) &&
      html.search(h2re("LDAP Result Codes")) <
      html.search(h2re("Result Code Breakdown")) &&
      html.search(h2re("Result Code Breakdown")) <
      html.search(h2re("Failing Result Codes")));

// The donut is the "what failed" reading: information must not be in it, and
// the count of what was left out must be written under the legend.
const donutLabels = [...donut.matchAll(/class="sl-legend-name"[^>]*>([^<]*)</g)]
  .map((m) => m[1]);
check("donut: holds the seven failing codes only, no success/compareFalse",
      donutLabels.length === 7 &&
      donutLabels.every((l) => !/^0 |^5 /.test(l)) &&
      ["32 noSuchObject", "49 invalidCredentials", "4 sizeLimitExceeded",
       "53 unwillingToPerform", "52 unavailable", "8 strongerAuthRequired",
       "50 insufficientAccessRights"].every((l) => donutLabels.includes(l)),
      donutLabels.join(" | "));
check("donut: the footnote states how many results were left out, and which",
      donut.includes("23 further result(s) are not failures and are left out here: " +
                     "0 success, 5 compareFalse."));

// The breakdown is the companion of the table: every code, successes included.
// Each row is read as (label fill, label), the label fill being the class colour
// the text carries — the dual class keeps violet for its text, so the hatch has to
// show up on the bar itself, asserted just below.
const bars = [...breakdown.matchAll(
  /class="sl-legend-name"[^>]*style="fill:(#[0-9a-f]{6})"[^>]*>([^<]*)</g)]
  .map((m) => [m[1], m[2]]);
check("breakdown: every code of the log, most frequent first",
      JSON.stringify(bars) === JSON.stringify([
        ["#27ae60", "0 success"], ["#e67e22", "32 noSuchObject"],
        ["#8e44ad", "4 sizeLimitExceeded"], ["#e67e22", "49 invalidCredentials"],
        ["#27ae60", "5 compareFalse"], ["#8e44ad", "50 insufficientAccessRights"],
        ["#cc0000", "52 unavailable"], ["#8e44ad", "53 unwillingToPerform"],
        ["#8e44ad", "8 strongerAuthRequired"]]), JSON.stringify(bars));

// The bar of a dual-class code is painted with the hatch pattern; a pure Policy
// code keeps the flat violet.  The two read differently even though their labels
// share the violet — which is the point of the hatch.
const barRows = [...breakdown.matchAll(
  /class="sl-legend-name"[^>]*>([^<]*)<\/text>\s*<rect class="sl-bar"[^>]*style="fill:([^;"]*);/g)]
  .map((m) => [m[1], m[2]]);
check("breakdown: the dual class bars use the hatch, pure policy stays flat",
      JSON.stringify(barRows.filter(([l]) => /^(50|53|8) /.test(l)))
        === JSON.stringify([["50 insufficientAccessRights", "url(#sl-hatch-breakdown)"],
                           ["53 unwillingToPerform", "url(#sl-hatch-breakdown)"],
                           ["8 strongerAuthRequired", "url(#sl-hatch-breakdown)"]]) &&
      barRows.find(([l]) => l.startsWith("4 sizeLimitExceeded"))[1] === "#8e44ad",
      JSON.stringify(barRows.filter(([l]) => /^(4|50|53|8) /.test(l))));

// The hatch pattern must be defined inside the very svg that uses it — a paint
// reference is resolved per drawing — once, before the first fill that names it.
check("breakdown: the hatch defs are in the same svg as its users, before them",
      breakdown.indexOf('id="sl-hatch-breakdown"') >= 0 &&
      breakdown.indexOf('id="sl-hatch-breakdown"') <
        breakdown.indexOf("url(#sl-hatch-breakdown)") &&
      (breakdown.match(/id="sl-hatch-breakdown"/g) || []).length === 1,
      String((breakdown.match(/id="sl-hatch-breakdown"/g) || []).length));

// The number of significant digits is fixed, so a share is printed the same way
// at every scale: 73.33 %, 3.333 %, and never a rounded "0.00 %" for a code seen
// three times in 1.4 M results.
check("breakdown: count and share are given for each bar",
      breakdown.includes("22  73.33%") && breakdown.includes("1  3.333%"));

// That last claim needs a log big enough for the small branch, hence this
// synthetic one: 12 000 successes against two limits, i.e. 0.008333 %.
const BIG = SL.SCRATCH + "/codes-big.log";
const res = (err) => "6a734745.00000004 0x7f9c1e33a700 conn=1000 op=0 RESULT tag=97 err=" +
                     err + " qtime=0 etime=1 text=\n";
fs.writeFileSync(BIG, res(0).repeat(12000) +
  "6a734745.00000004 0x7f9c1e33a700 conn=1000 op=0 SEARCH RESULT tag=101 err=4 qtime=0 etime=1 nentries=0 text=\n" +
  "6a734745.00000004 0x7f9c1e33a700 conn=1000 op=0 SEARCH RESULT tag=101 err=11 qtime=0 etime=1 nentries=0 text=\n");
const bigHtml = run(["-o", "html", "-q", BIG]);
check("breakdown: a share far below 1 % keeps significant digits",
      bigHtml.includes("12000  99.98%") && bigHtml.includes("0.008332%"));
// Both codes of that log are pure *by configuration* (`4`, `11`), so no chart
// there may emit a hatch pattern — the defs are drawn only when they are used.
check("breakdown: no dual-class code means no hatch anywhere",
      !bigHtml.includes("sl-hatch") && !bigHtml.includes("url(#"), bigHtml.slice(0, 0));

// The regression: a class selector beats a presentation attribute, so a colour
// must be an inline style.  Both forms are asserted, so this fails if one ever
// comes back as an attribute.
check("breakdown: bars and labels colour via inline style, not fill=",
      breakdown.includes('class="sl-bar"') && breakdown.includes('style="fill:#') &&
      !/class="sl-(bar|legend-name)"[^>]*\sfill="/.test(breakdown));
check("donut: slices and legend swatches colour via inline style too",
      donut.includes('class="sl-slice" style="fill:#') &&
      !/class="sl-slice"[^>]*\sfill="/.test(donut));

// Errors over time counts failures only — the whole point of the change.
check("errors over time: counts the 7 real failures, and says information is out",
      /class="sl-chart-sub">7 failing result\(s\)/.test(overtime) &&
      overtime.includes("are not plotted"));

// The table and its colour key.
const cellStyles = Object.fromEntries(
  [...table.matchAll(/<td style="color:(#[0-9a-f]{6})(;[^"]*)?">(\d+)<\/td>/g)]
    .map((m) => [m[3], { color: m[1], rest: m[2] || "" }]));
check("table: each code is coloured by its class",
      cellStyles["0"] && cellStyles["0"].color === "#27ae60" &&
      cellStyles["5"].color === "#27ae60" &&
      cellStyles["32"].color === "#e67e22" && cellStyles["49"].color === "#e67e22" &&
      cellStyles["52"].color === "#cc0000", JSON.stringify(cellStyles));
// The dual class keeps violet text and gains a pale hatch behind the row; the
// pure Policy code keeps the flat violet with no background at all.
check("table: the dual class keeps violet text and gains a pale hatch",
      ["8", "50", "53"].every((c) => cellStyles[c] &&
                                  cellStyles[c].color === "#8e44ad" &&
                                  cellStyles[c].rest.includes("background:repeating-linear-gradient(45deg")) &&
      cellStyles["4"].color === "#8e44ad" && cellStyles["4"].rest === "",
      JSON.stringify(["4", "8", "50", "53"].map((c) => [c, cellStyles[c]])));
check("table: the colour key names the five classes",
      ["informational", "client-side", "refused by configuration", "slapd itself"]
        .every((k) => table.includes(k)) &&
      table.includes("refused by configuration &mdash; or a client-side mistake"));
check("table: the colour key draws the dual class as the hatch",
      /background:repeating-linear-gradient\(45deg,#8e44ad 0 3px,#e67e22 3px 6px\);margin-right:5px"><\/span>refused by configuration &mdash;/.test(table));

// Repeated codes of the same class in a *donut* and a *bar* chart must agree.
check("donut: legends name the class each slice belongs to",
      donut.includes("client-side") && donut.includes("by configuration") &&
      donut.includes("by configuration, or client-side") &&
      donut.includes("server-side"));
// The dual slice is hatched in the drawing and in its legend swatch, and the
// pattern is defined in the donut's own svg.
check("donut: the dual slice and its swatch carry the hatch",
      donut.indexOf('id="sl-hatch-donut"') >= 0 &&
      donut.indexOf('id="sl-hatch-donut"') < donut.indexOf("url(#sl-hatch-donut)") &&
      donut.includes('width="12" height="12" rx="2" style="fill:url(#sl-hatch-donut)"'));
// The stacked chart's legend is HTML, where an SVG pattern means nothing: its
// swatch draws the same two colours as a CSS gradient.
check("errors over time: the dual band's legend swatch draws the CSS hatch",
      overtime.includes("background:repeating-linear-gradient(45deg,#8e44ad 0 3px,#e67e22 3px 6px)") &&
      overtime.includes('id="sl-hatch-stack"') &&
      overtime.indexOf('id="sl-hatch-stack"') < overtime.indexOf("url(#sl-hatch-stack)"));

// ------------------------------------------------------- --no-graph switch
// The two count-fed charts exist whatever the flag, so the flag is now tested
// explicitly: no chart may survive --no-graph.
const nograph = run(["-o", "html", "-q", "--no-graph", LOG]);
check("--no-graph suppresses every chart, the new one included",
      !nograph.includes("<h2>Result Code Breakdown</h2>") &&
      !nograph.includes("<h2>Failing Result Codes</h2>") &&
      !nograph.includes("<h2>Errors Over Time</h2>") &&
      !nograph.includes('class="sl-chart"') &&
      !nograph.includes(".sl-chart{"));

console.log("\n" + failures + " failure(s) / " + checks + " checks");
process.exit(failures ? 1 : 0);
