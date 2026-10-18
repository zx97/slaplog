#!/usr/bin/env node
const SL = require("../lib/env.cjs");
// charts8-test.cjs — the eighth chart (*Response Time Density*), the stacked
// *Errors Over Time*, the result-code pie, and the absence of notes.
//
// Three fixtures are generated here, so every expectation below follows from the
// fixture rather than from whatever the program happens to print:
//
//   dens.log  — 620 operations whose etimes fall in exactly four logarithmic
//               bins (300 at 0 ms, 200 at 0.02 ms = 20 us, 100 at 0.2 ms =
//               200 us, 20 at 3 ms), so the density profile is known in advance.
//   stack.log — 100 seconds of failing results: 3/s of 49 invalidCredentials
//               (300), 1/s of 32 noSuchObject (100), one burst of 20
//               unwillingToPerform, plus 3 compareFalse answers which are
//               informational and must not reach the stacked chart.
//   sat.log   — a concentrated log: 10 000 of one code, then eleven codes seen
//               once each.  That is the shape a production access log has, and it
//               is where the pie has to stay honest (eleven slivers drawn, none
//               folded into an "other" slice, each still named on hover).
//
// The point of the density chart is that a distribution living inside one
// coarse bucket still has a readable shape; the point of the stack is that the
// silhouette is the total while the colour names the code; the point of the pie is
// that the concentration of result codes needs no axis and no caption.
const fs = require("fs");
const { execFileSync } = require("child_process");

const SLA = "" + SL.ROOT + "/slaplog";
const DENS = SL.SCRATCH + "/dens8.log";
const STACK = SL.SCRATCH + "/stack8.log";
const SAT = SL.SCRATCH + "/sat8.log";

let failures = 0, checks = 0;
function check(name, ok, detail) {
  checks++;
  if (!ok) { failures++; console.log("  FAIL  " + name + (detail ? "\n        " + detail : "")); }
  else console.log("  ok    " + name);
}
const run = (args) => execFileSync(SLA, args, { encoding: "utf8", maxBuffer: 1 << 28 });
const US = "\u00b5s";

// ---------------------------------------------------------------- fixtures
function buildDensity() {
  const out = [];
  let sec = 0, usec = 1, op = 0, conn = 2000;
  const t = () => ("6a734745" + (sec.toString(16).padStart(2, "0"))).slice(-8) +
                   "." + (usec++).toString(16).padStart(8, "0");
  const emit = (etime) => {
    op++;
    if (op % 40 === 0) conn++;
    out.push(`${t()} 0x7f9c1e33a700 conn=${conn} op=${op} SRCH base="dc=example,dc=com" scope=2 deref=0 filter="(uid=x)"`);
    out.push(`${t()} 0x7f9c1e33a700 conn=${conn} op=${op} SEARCH RESULT tag=101 err=0 qtime=0 etime=${etime} nentries=1 text=`);
    if (out.length > 400) { sec++; usec = 1; }
  };
  for (let i = 0; i < 300; i++) emit(0);        // bin 0: 0 or under 1 us
  for (let i = 0; i < 200; i++) emit(0.02);     // 20 us  -> [15.8, 25.1) us
  for (let i = 0; i < 100; i++) emit(0.2);      // 200 us -> [158, 251) us
  for (let i = 0; i < 20; i++)  emit(3);        // 3 ms   -> [2.51, 3.98) ms
  return "6a734745.00000001 0x7f9c1e33a700 slapd starting\n" + out.join("\n") + "\n";
}

function buildStack() {
  const out = [];
  let bound = 0, op = 0, conn = 3000;
  const t = (sec, usec) => (0x6a734745 + sec).toString(16).padStart(8, "0") + "." +
                           usec.toString(16).padStart(8, "0");
  const emit = (sec, err, text) => {
    bound++; op++;
    if (op % 30 === 0) conn++;
    out.push(`${t(sec, 1000 + (bound % 900))} 0x7f9c1e33a700 conn=${conn} op=${op} SRCH base="dc=example,dc=com" scope=2 deref=0 filter="(uid=x)"`);
    out.push(`${t(sec, 1100 + (bound % 900))} 0x7f9c1e33a700 conn=${conn} op=${op} SEARCH RESULT tag=101 err=${err} qtime=0 etime=1 nentries=0 text=${text}`);
  };
  out.push(`${t(0, 1)} 0x7f9c1e33a700 slapd starting`);
  for (let c = 0; c < 4; c++)                                   // so the
    out.push(`${t(c, 500)} 0x7f9c1e33a700 conn=${3000 + c} fd=${12 + c} ACCEPT from IP=192.0.2.${10 + c}:3456${c} (IP=0.0.0.0:389)`);
  for (let s = 0; s < 100; s++) {
    for (let k = 0; k < 3; k++) emit(s, 49, "Invalid credentials");       // 300
    emit(s, 32, "No such object");                                        // 100
    if (s === 50) for (let k = 0; k < 20; k++) emit(s, 53, "Unwilling to perform"); // 20
    if (s % 25 === 0) emit(s, 5, "");                                     // 3 compareFalse
  }
  return out.join("\n") + "\n";
}

// A concentrated log, the shape a production access log actually has: one code
// takes 99.88 % of every result and eleven codes weigh one result each.  The pie
// then draws one slice and eleven slivers — and it has to draw all twelve: a
// "top N, rest folded" rule would hide eleven codes behind one word.
function buildSaturated() {
  const out = [];
  let line = 0, op = 0, conn = 4000;
  const t = () => (0x6a734745 + (line++ >> 6)).toString(16).padStart(8, "0") + "." +
                  (1000 + (line % 900)).toString(16).padStart(8, "0");
  const emit = (err, text) => {
    op++;
    if (op % 30 === 0) conn++;
    out.push(`${t()} 0x7f9c1e33a700 conn=${conn} op=${op} SRCH base="dc=example,dc=com" scope=2 deref=0 filter="(uid=x)"`);
    out.push(`${t()} 0x7f9c1e33a700 conn=${conn} op=${op} SEARCH RESULT tag=101 err=${err} qtime=0 etime=1 nentries=0 text=${text}`);
  };
  out.push(`${t()} 0x7f9c1e33a700 slapd starting`);
  for (let i = 0; i < 10000; i++) emit(49, "Invalid credentials");   // 99.88 %
  // Eleven codes seen once each, spread over the four classes.
  for (const [err, text] of [[32, "No such object"], [5, ""], [6, ""],
                             [53, "Unwilling to perform"], [52, "Unavailable"],
                             [66, "Not allowed on non-leaf"], [4, "Size limit exceeded"],
                             [16, "No such attribute"], [11, "Administrative limit exceeded"],
                             [1, "Operations error"], [50, "Insufficient access"]])
    emit(err, text);
  return out.join("\n") + "\n";
}

if (!fs.existsSync(DENS) || fs.readFileSync(DENS, "utf8").length < 1000)
  fs.writeFileSync(DENS, buildDensity());
if (!fs.existsSync(STACK) || fs.readFileSync(STACK, "utf8").length < 1000)
  fs.writeFileSync(STACK, buildStack());
if (!fs.existsSync(SAT) || fs.readFileSync(SAT, "utf8").length < 1000)
  fs.writeFileSync(SAT, buildSaturated());

// The section of the page between one <h2> and the next.  Headings now carry
// an id (the floating index links to it), so the match tolerates attributes.
function sectionOf(html, title) {
  const esc = title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const i = html.search(new RegExp("<h2[^>]*>" + esc + "</h2>"));
  if (i < 0) return "";
  const j = html.indexOf("<h2", i + 4);
  return html.slice(i, j < 0 ? html.length : j);
}

console.log("eighth chart + stacked errors");

// ------------------------------------------------- Response Time Density
{
  const html = run(["-o", "html", "-q", DENS]);
  const s = sectionOf(html, "Response Time Density");
  check("density: the chart is drawn", s.length > 0 && s.includes("sl-density-line"));
  check("density: subtitle counts every operation with a time",
        s.includes("620 operation(s)"), (s.match(/sl-chart-sub">(.*?)</) || [])[1]);
  check("density: subtitle states the bin ratio",
        s.includes("1.58&times; wider in time"), (s.match(/sl-chart-sub">(.*?)</) || [])[1]);

  const tips = [...s.matchAll(/data-y="([^"]*)"/g)].map((m) => m[1]);
  check("density: four populated bins, drawn as four points",
        s.split("sl-density-dot").length - 1 === 4,
        "dots=" + (s.split("sl-density-dot").length - 1));
  check("density: every bin the plot shows is hoverable, none outside it",
        tips.length === 19 && tips.filter((t) => t.startsWith("0 operation(s)")).length === 15,
        "tips=" + tips.length + " empty=" + tips.filter((t) => t.startsWith("0 ")).length);
  check("density: the 0 bin is named as such, not left a mystery tower",
        tips.some((t) => t.startsWith("300 operation(s) at 0 or under 1 " + US + " (48.39%)")), tips[0]);
  check("density: the 20 us bin reports its range and count",
        tips.some((t) => t === "200 operation(s) between 15.8 " + US + " and 25.1 " + US + " (32.26%)"));
  check("density: the 200 us bin reports its range and count",
        tips.some((t) => t === "100 operation(s) between 158 " + US + " and 251 " + US + " (16.13%)"));
  check("density: the 3 ms bin reports its range and count",
        tips.some((t) => t === "20 operation(s) between 2.51 ms and 3.98 ms (3.226%)"), tips[3]);

  const ticks = [...s.matchAll(/class="sl-tick"[^>]*text-anchor="middle">([^<]*)</g)].map((m) => m[1]);
  check("density: decade ticks cover the window the data set",
        JSON.stringify(ticks) === JSON.stringify(["1 " + US, "10 " + US, "100 " + US, "1 ms"]),
        JSON.stringify(ticks));

  const geom = [...s.matchAll(/sl-density-dot" cx="([\d.]+)" cy="([\d.]+)"/g)]
      .map((m) => [parseFloat(m[1]), parseFloat(m[2])]);
  check("density: every point stays inside the plot box",
        geom.every(([x, y]) => x >= 84 && x <= 962 && y >= 34 && y <= 254.5), JSON.stringify(geom));
  check("density: the tallest bin is the 0 one, drawn at the top of the box",
        geom.length === 4 && geom[0][1] === Math.min(...geom.map((g) => g[1])), JSON.stringify(geom));
  check("density: hovering slices tile the plot edge to edge, none past it",
        (() => {
          const r = [...s.matchAll(/class="sl-hit" x="([\d.]+)"[^>]*width="([\d.]+)"/g)]
              .map((m) => [parseFloat(m[1]), parseFloat(m[2])]);
          return r.length === 19 && Math.abs(r[0][0] - 84) < 0.2 &&
                 r.every(([x, w], i) => i === 0 || Math.abs(x - (r[i - 1][0] + r[i - 1][1])) < 0.15) &&
                 r.every(([x, w]) => x >= 84 && x + w <= 962.01) &&
                 Math.abs(r[r.length - 1][0] + r[r.length - 1][1] - 962) < 0.2;
        })());
}

// -------------------------------- the right-hand side of the latency chart
{
  // The chart carried a cumulative curve with its own 0-100 % axis and a column
  // repeating its figures.  The bars beside it already said everything it said
  // (every row past the second read 100 %), so the curve went — and the bars took
  // the width it and its column occupied, instead of leaving a void.
  const html = run(["-o", "html", "-q", DENS]);
  const s = sectionOf(html, "Response Time Distribution");

  check("latency: the subtitle stops promising a cumulative curve",
        !/cumulative/i.test(s), (s.match(/sl-chart-sub">(.*?)</) || [])[1]);
  check("latency: the curve, its dots and the 0-100 % axis are gone",
        !s.includes("sl-curve") && !s.includes("sl-curve-dot") &&
        !/>25%</.test(s) && !/>50%</.test(s) && !/>75%</.test(s) && !/>100%</.test(s));
  check("latency: the only right-aligned texts left are the bucket names",
        (() => {
          const ends = [...s.matchAll(/text-anchor="end">([^<]*)</g)].map((m) => m[1]);
          return ends.length > 0 &&
                 ends.every((t) => /^((&lt;=|&gt;)=? )?\d[\d.]*(-\d[\d.]*)? (ms|s)$/.test(t));
        })(), JSON.stringify([...s.matchAll(/text-anchor="end">([^<]*)</g)].map((m) => m[1])));

  const bars = [...s.matchAll(/class="sl-bar" x="([\d.]+)" y="[\d.]+" width="([\d.]+)"/g)]
      .map((m) => [parseFloat(m[1]), parseFloat(m[2])]);
  const vals = [...s.matchAll(/class="sl-legend-val"[^>]*>([\d.]+)\s+\(([\d.]+)%\)/g)]
      .map((m) => [+m[1], parseFloat(m[2])]);
  const total = vals.reduce((a, v) => a + v[0], 0);

  check("latency: one bar per bucket, each with its count and share",
        bars.length === vals.length && bars.length > 1 &&
        vals.every(([n, pct]) => Math.abs((n / total) * 100 - pct) < 0.05),
        JSON.stringify(vals));
  check("latency: the bars are on one linear scale, none clipped by the viewBox",
        (() => {
          // Widths are rounded to a tenth, so the ratio is compared with slack.
          const r = bars.map(([x, w], i) => w / vals[i][0]);
          return bars.every(([x, w]) => x === 130 && x + w <= 1000) &&
                 r.every((v) => Math.abs(v - r[0]) < 0.01);
        })(), JSON.stringify(bars));
  check("latency: the widest bar uses the width the curve and its column had",
        Math.abs(Math.max(...bars.map(([x, w]) => x + w)) - 780) < 0.2,
        String(Math.max(...bars.map(([x, w]) => x + w))));
  check("latency: hovering reports the bucket, its count and its share",
        [...s.matchAll(/data-y="([^"]*)"/g)].map((m) => m[1])
          .every((t) => /^\d[\d ]* ops \([\d.]+%\)$/.test(t)),
        [...s.matchAll(/data-y="([^"]*)"/g)].map((m) => m[1])[0]);
}

// ------------------------------------------------- stacked Errors Over Time
{
  const html = run(["-o", "html", "-q", STACK]);
  const s = sectionOf(html, "Errors Over Time");
  check("stack: one band per failing code, plus the total outline",
        (s.split('class="sl-stack"').length - 1) === 3 &&
        (s.split('class="sl-stack-total"').length - 1) === 1,
        "bands=" + (s.split('class="sl-stack"').length - 1));
  check("stack: subtitle counts the failing results only",
        s.includes("420 failing result(s)"), (s.match(/sl-chart-sub">(.*?)</) || [])[1]);

  const keys = [...s.matchAll(/<span class="sl-stack-key" title="([^"]*)"[^>]*>([\s\S]*?)<\/span>/g)]
      .map((m) => [m[1], m[2].replace(/<[^>]+>/g, "")]);
  check("stack: the legend names each band with its count and share",
        JSON.stringify(keys.map((k) => k[1])) === JSON.stringify([
          "49 invalidCredentials \u2014 300 (71.43%)",
          "32 noSuchObject \u2014 100 (23.81%)",
          "53 unwillingToPerform \u2014 20 (4.762%)",
        ]), JSON.stringify(keys.map((k) => k[1])));
  check("stack: the legend says which class each band belongs to",
        keys[0][0] === "result class: client-side" &&
        keys[1][0] === "result class: client-side" &&
        keys[2][0] === "result class: by configuration, or client-side",
        JSON.stringify(keys.map((k) => k[0])));

  // The dual class paints its band with the hatch (an SVG pattern) and its
  // legend swatch with the same two colours as a CSS gradient.
  const styles = [...s.matchAll(/class="sl-stack" style="fill:([^;"]+);fill-opacity:([\d.]+)"/g)]
      .map((m) => m[1] + "@" + m[2]);
  check("stack: class colours, shaded so two codes of one class differ",
        JSON.stringify(styles) === JSON.stringify(["#e67e22@0.95", "#e67e22@0.70", "url(#sl-hatch-stack)@0.95"]),
        JSON.stringify(styles));
  check("stack: the dual band's legend swatch draws the CSS hatch",
        s.includes("background:repeating-linear-gradient(45deg,#8e44ad 0 3px,#e67e22 3px 6px)") &&
        s.indexOf('id="sl-hatch-stack"') < s.indexOf("url(#sl-hatch-stack)"));

  const tips = [...s.matchAll(/data-y="([^"]*)"/g)].map((m) => m[1]);
  check("stack: a slice tooltip names the codes it is made of",
        tips.some((t) => t.includes("4 error(s) \u2014 3 \u00b7 49 invalidCredentials, 1 \u00b7 32 noSuchObject")),
        tips[0]);
  check("stack: the burst slice names the configuration refusal",
        tips.some((t) => t.includes("53 unwillingToPerform")), tips.filter((t) => t.includes("53"))[0]);
  check("stack: the compareFalse answers are nowhere in the chart",
        !s.includes("compareFalse") && !s.includes(">5 "), "");
  check("stack: bands are painted before the total outline, so the edge stays crisp",
        s.indexOf('class="sl-stack"') < s.indexOf('class="sl-stack-total"'));
}

// --------------------------------------------------- notes under the charts
{
  // There are none, and the mechanism to draw one is gone.  A note under a drawing
  // that needs no explaining (a share ring, a connection curve) is noise, a note
  // that talks past the thing the reader is stuck on is worse than none — and the
  // last one, under the result-code breakdown's cumulative bars, went away with
  // the bars: a pie of the same codes says the same thing without a caption.
  const html = run(["-o", "html", "-q", STACK]);
  const notes = html.split('<div class="sl-chart-help">').length - 1;
  check("notes: the report carries no how-to-read note at all", notes === 0, "notes=" + notes);
  check("notes: not even the stylesheet is still shipped for one",
        !html.includes(".sl-chart-help{"));

  const none = run(["-o", "html", "-q", "--no-graph", STACK]);
  check("help: --no-graph suppresses the density chart, the bands and the pie",
        !none.includes("Response Time Density") && !none.includes("sl-stack") &&
        !none.includes("sl-density") && !none.includes("sl-slice"));

  check("connections: the marker key is a legend in the subtitle, not a note",
        sectionOf(html, "Simultaneous Connections")
          .includes("markers: green start, red stop, orange restart without a clean shutdown"));
}

// ------------------------------------------- the result-code bar scale
{
  // The bars are on a log scale and the chart carried no scale of its own: the
  // reader had "0 % … 100 %" from the cumulative axis that then sat beside them and
  // nothing at all to measure a bar against.  The bar axis is labelled now, in
  // decades.
  const html = run(["-o", "html", "-q", STACK]);
  const s = sectionOf(html, "Result Code Breakdown");
  const labels = [...s.matchAll(/<text class="sl-tick" x="([\d.]+)"[^>]*>([^<]*)<\/text>/g)]
      .map((m) => [parseFloat(m[1]), m[2]]);
  const bars = labels.filter(([, v]) => !v.endsWith("%"));
  const axisY = [...s.matchAll(/<text class="sl-tick" x="[\d.]+" y="([\d.]+)"[^>]*>\d+k?<\/text>/g)]
      .map((m) => parseFloat(m[1]));
  check("bars: the scale is labelled, and the labels are counts (not more percentages)",
        JSON.stringify(bars.map((b) => b[1])) === JSON.stringify(["1", "10", "100"]),
        JSON.stringify(bars));
  check("bars: the labels sit under the bars, after the last row",
        axisY.length === 3 && new Set(axisY).size === 1 && axisY[0] > 30 + 3 * 24, JSON.stringify(axisY));
  // The position of a label must be where a bar of that count ends — the axis is
  // the bars' own scale.  The top of the scale is the busiest code, which is
  // almost never a round decade, so an even spread across the bar area puts
  // "100k" under a bar of 907k.  Derive the expected x from the counts the
  // chart itself prints.
  check("bars: each label sits where a bar of that count would end",
        (() => {
          const counts = [...s.matchAll(/<text class="sl-legend-val"[^>]*>(\d+)\s/g)]
              .map((m) => +m[1]).filter((v) => v > 0);
          const lmax = Math.log10(Math.max(...counts));
          const want = bars.map(([, v]) => {
            const k = v.endsWith("k") ? Math.log10(parseFloat(v) * 1e3) : Math.log10(parseFloat(v));
            return +(215 + (k / lmax) * 345).toFixed(1);
          });
          return bars.every((b, i) => Math.abs(b[0] - want[i]) < 0.5);
        })(), JSON.stringify([bars.map((b) => b[0]),
          (() => { const c = [...s.matchAll(/<text class="sl-legend-val"[^>]*>(\d+)\s/g)].map((m) => +m[1]);
                   const l = Math.log10(Math.max(...c));
                   return bars.map(([, v]) => +(215 + (Math.log10(parseFloat(v) * (v.endsWith("k") ? 1e3 : 1)) / l) * 345).toFixed(1)); })()]));
  check("bars: the subtitle says the axis is labelled rather than leaving it to be guessed",
        s.includes("axis labelled under the bars"), (s.match(/sl-chart-sub">(.*?)</) || [])[1]);
}

// --------------------------------------------------- the result-code pie
{
  // The right-hand side of this chart has been drawn three ways: a cumulative
  // curve with its own 0-100 % axis and a column repeating its figures, then a flat
  // bar per row, then those bars stacked.  Each one needed a sentence to be read,
  // and the last one needed a note.  A pie of the same codes — same order, same
  // colours — says the same thing (one huge slice, then crumbs) and needs neither.
  const html = run(["-o", "html", "-q", STACK]);
  const s = sectionOf(html, "Result Code Breakdown");

  const counts = [...s.matchAll(/<text class="sl-legend-val"[^>]*>(\d+)\s/g)].map((m) => +m[1]);
  const total = counts.reduce((a, b) => a + b, 0);
  const names = [...s.matchAll(/<text class="sl-legend-name" x="[\d.]+" y="[\d.]+" style="fill:#[0-9a-f]+">([^<]*)<\/text>/g)]
      .map((m) => m[1]);
  const bars = [...s.matchAll(
      /<rect class="sl-bar" x="[\d.]+" y="[\d.]+" width="[\d.]+" height="14" rx="2" style="fill:(#[0-9a-f]+|url\([^)]+\));fill-opacity:([\d.]+)"/g)]
      .map((m) => ({ fill: m[1], op: m[2] }));

  // Every wedge, with the circle it lives in and the sweep it covers: the paths are
  // "M cx,cy L x1,y1 A r,r 0 f 1 x2,y2 Z", so both angles come straight out of the
  // geometry the browser will draw.
  const slices = [...s.matchAll(
      /class="sl-slice" style="([^"]*)" d="M ([\d.]+),([\d.]+) L ([\d.]+),([\d.]+) A ([\d.]+),[\d.]+ 0 \d 1 ([\d.]+),([\d.]+) Z" data-x="([^"]*)"/g)]
      .map((m) => {
        const n = (k) => Number(m[k]);
        const a1 = Math.atan2(n(5) - n(3), n(4) - n(2));
        const a2 = Math.atan2(n(8) - n(3), n(7) - n(2));
        return { style: m[1], cx: n(2), cy: n(3), a1, a2, name: m[9],
                 span: (a2 - a1 + 4 * Math.PI) % (2 * Math.PI) };
      });

  check("pie: one slice per code, and the slices follow the rows",
        slices.length === counts.length && names.length === counts.length &&
        slices.every((sl, i) => sl.name === names[i]),
        `${slices.length} slice(s) / ${counts.length} row(s)`);
  check("pie: a code's slice is painted exactly like its bar",
        slices.every((sl, i) => sl.style === `fill:${bars[i].fill};fill-opacity:${bars[i].op}`),
        JSON.stringify(slices.map((sl) => sl.style)));
  check("pie: the slices are proportional to the counts, not to the log bars",
        slices.every((sl, i) => Math.abs(sl.span / (2 * Math.PI) - counts[i] / total) < 0.002),
        JSON.stringify(slices.map((sl) => +(sl.span * 180 / Math.PI).toFixed(2))));
  check("pie: twelve o'clock to twelve o'clock, one turn, in row order",
        (() => {
          if (Math.abs(slices[0].a1 + Math.PI / 2) > 0.01) return false;
          let acc = -Math.PI / 2;
          for (const sl of slices) {
            let a1 = sl.a1;
            while (a1 < acc - 0.01) a1 += 2 * Math.PI;   // unwrap: the pie turns one way
            if (Math.abs(a1 - acc) > 0.01) return false;
            acc = a1 + sl.span;
          }
          return Math.abs(acc - (3 * Math.PI / 2)) < 0.01;
        })());
  check("pie: the same circle holds every slice, and it stays in the viewBox",
        (() => {
          const w = Number((s.match(/viewBox="0 0 ([\d.]+)/) || [])[1]);
          return slices.every((sl) => sl.cx > 700 && sl.cy > 0) &&
                 slices[0].cx + 115 <= w && slices[0].cx - 115 > 700;
        })(), JSON.stringify([slices[0].cx, slices[0].cy]));
  check("pie: every slice names its code and its exact figure on hover",
        slices.length === counts.length &&
        [...s.matchAll(/class="sl-slice"[^>]*data-x="([^"]*)" data-y="([^"]*)"/g)]
          .every((m, i) => m[1] === names[i] && m[2].startsWith(counts[i] + "  (")),
        ([...s.matchAll(/class="sl-slice"[^>]*data-y="([^"]*)"/g)][0] || [])[1]);
  check("pie: the curve, its dots and the stacked coverage bars are all gone",
        !s.includes("sl-code-curve") && !s.includes("sl-code-curve-dot") &&
        !s.includes("sl-coverage-bar") && !/>25%</.test(s) && !/text-anchor="end"/.test(s));
}

// ------------------------------------------- the pie on a concentrated log
{
  // One code covers 99.88 % of everything and eleven weigh one result each.  That
  // is where a "top N + other" fold would quietly hide eleven codes, and where the
  // slices are too thin to see — so the figure has to survive on hover.
  const html = run(["-o", "html", "-q", SAT]);
  const s = sectionOf(html, "Result Code Breakdown");

  const counts = [...s.matchAll(/<text class="sl-legend-val"[^>]*>(\d+)\s/g)].map((m) => +m[1]);
  const names = [...s.matchAll(/<text class="sl-legend-name" x="[\d.]+" y="[\d.]+" style="fill:#[0-9a-f]+">([^<]*)<\/text>/g)]
      .map((m) => m[1]);
  const tips = [...s.matchAll(/class="sl-slice"[^>]*data-x="([^"]*)" data-y="([^"]*)"/g)]
      .map((m) => [m[1], m[2]]);

  check("pie/saturated: twelve codes, twelve slices, none folded into an 'other'",
        counts.length === 12 && tips.length === 12 && !s.includes("other"),
        `${counts.length} code(s) / ${tips.length} slice(s)`);
  check("pie/saturated: the eleven one-result codes are drawn, not dropped as invisible",
        counts.filter((c) => c === 1).length === 11 &&
        tips.filter(([, what]) => /^1  \(0\.\d+%\)/.test(what)).length === 11,
        JSON.stringify(tips.slice(1, 3)));
  check("pie/saturated: every slice still names its exact figure on hover",
        tips.every(([name, what], i) => {
          const m = /^([\d ]+)  \(([\d.]+)%\)/.exec(what);
          return name === names[i] && m !== null &&
                 +m[1].replace(/[^\d]/g, "") === counts[i] && parseFloat(m[2]) > 0;
        }),
        JSON.stringify(tips.slice(0, 2)));
}

console.log(`\n  ${failures} failure(s) / ${checks} checks\n`);
process.exit(failures ? 1 : 0);
