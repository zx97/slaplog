const SL = require("../lib/env.cjs");
// Per-server time-coverage band: the lane strip under the x axis of the two
// time-series charts.  Checks the geometry against the timestamps the fixture
// actually contains, that a single server draws no strip at all, that the
// lanes never reach the time labels, and that the WASM session path produces
// the same band as the native binary.
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const NATIVE = "" + SL.ROOT + "/slaplog";
const WEB = "" + SL.ROOT + "/wasm/web";
const D = SL.SCRATCH + "/covfix";
const MEM = "/work";

let results = [];
const ok = (n, c) => { results.push((c ? "PASS  " : "FAIL  ") + n); return c; };

// ---------------------------------------------------------------- fixture ---
// Two servers whose windows overlap but do not coincide: A covers the first
// half of the window, B the last four fifths of it.
function line(ts, host, body) {
  return `2026-10-16T${ts}.000000000Z ${host} slapd[1]: ${body}\n`;
}
function makeServer(host, from, count, stepSec, withError) {
  let s = "";
  const base = from;
  for (let i = 0; i < count; i++) {
    const t = base + i * stepSec;
    const hh = String(Math.floor(t / 3600)).padStart(2, "0");
    const mm = String(Math.floor((t % 3600) / 60)).padStart(2, "0");
    const ss = String(t % 60).padStart(2, "0");
    s += line(`${hh}:${mm}:${ss}`, host, `conn=${i + 1} fd=${i + 10} ACCEPT from IP=10.0.0.${i + 1}:1000 (IP=0.0.0.0:389)`);
    s += line(`${hh}:${mm}:${ss}`, host, `conn=${i + 1} op=0 SRCH base="dc=example,dc=com" scope=2 deref=0 filter="(objectClass=*)"`);
    s += line(`${hh}:${mm}:${ss}`, host, `conn=${i + 1} op=0 RESULT tag=101 err=${withError && i === 1 ? 49 : 0} qtime=0 etime=1 text=`);
  }
  return s;
}
fs.mkdirSync(D, { recursive: true });
// hostA: 10:00:00 → 10:10:00 (600 s), hostB: 10:04:00 → 10:20:00 (960 s)
fs.writeFileSync(`${D}/s1.log`, makeServer("hostA", 10 * 3600, 11, 60, true));
fs.writeFileSync(`${D}/s2.log`, makeServer("hostB", 10 * 3600 + 240, 17, 60, true));

const S1 = `${D}/s1.log`, S2 = `${D}/s2.log`;

// ------------------------------------------------------------------ runner ---
const run = (args) => execFileSync(NATIVE, ["-o", "html", "-q", "-j", "1", ...args],
  { maxBuffer: 1 << 30 }).toString();

function svgOf(html, label) {
  const at = html.indexOf(`aria-label="${label}"`);
  if (at < 0) return "";
  const close = html.indexOf("</svg>", at);
  const open = html.lastIndexOf("<svg", at);
  return html.slice(open, close);
}
const all = (s, re) => [...s.matchAll(re)].map((m) => m[0]);
const viewBox = (svg) => (/viewBox="0 0 ([\d.]+) ([\d.]+)"/.exec(svg) || []).slice(1).map(Number);

const two = run([S1, S2]);
const one = run([S1]);

// ------------------------------------------------------- geometry expected ---
// L = 68, plot width 918, window 10:00:00 → 10:20:00 (1200 s).
const xof = (sec) => 68 + (sec / 1200) * 918;
const near = (a, b, tol = 1.5) => Math.abs(a - b) <= tol;

const CONN = "Simultaneous connections over time";
const ERR = "Errors over time, stacked by result code";
const connTwo = svgOf(two, CONN), errTwo = svgOf(two, ERR);
const connOne = svgOf(one, CONN), errOne = svgOf(one, ERR);

// 1. two servers draw two lanes on BOTH charts
for (const [name, svg] of [["connections", connTwo], ["errors", errTwo]]) {
  const tracks = all(svg, /class="sl-cov-track"/g).length;
  const spans = all(svg, /class="sl-cov-span"/g).length;
  const hits = all(svg, /data-x="host[AB]"/g).length;
  ok(`${name}: two servers draw two lanes (tracks=${tracks}, spans=${spans}, hits=${hits})`,
     tracks === 2 && spans === 2 && hits === 2);
  ok(`${name}: every lane carries a hit area naming its server`,
     /data-x="hostA"/.test(svg) && /data-x="hostB"/.test(svg));
}

// 2. the strip grows the canvas and stops short of the time labels
{
  const [w, h] = viewBox(connTwo);
  ok(`connections: canvas grows by the strip height (300 -> ${h})`, w === 1000 && h === 300 + 21);
  const ticks = all(connTwo, /<text class="sl-tick" x="[\d.]+" y="([\d.]+)" text-anchor="middle"/g)
    .map((s) => Number(/y="([\d.]+)"/.exec(s)[1]));
  const labelY = Math.max(...ticks);
  const lanes = all(connTwo, /<rect class="sl-cov-track" x="([\d.]+)" y="([\d.]+)" width="([\d.]+)" height="([\d.]+)"/g)
    .map((s) => s.match(/[\d.]+/g).map(Number));
  const bottom = Math.max(...lanes.map(([, y, , hh]) => y + hh));
  ok(`connections: the lanes stay above the time labels (lane bottom ${bottom} < label top ${labelY - 11})`,
     bottom < labelY - 11);
  const side = all(connTwo, /<rect class="sl-cov-(?:track|span)" x="([\d.]+)"[^>]*width="([\d.]+)"/g)
    .map((s) => s.match(/[\d.]+/g).map(Number));
  ok("connections: no lane leaves the plot area",
     side.every(([x, wd]) => x >= 68 - 0.01 && x + wd <= 68 + 918 + 0.01));
}

// 3. the painted span is where the timestamps say it is
{
  const spans = all(connTwo, /<rect class="sl-cov-span" x="([\d.]+)" y="([\d.]+)" width="([\d.]+)"/g)
    .map((s) => s.match(/[\d.]+/g).map(Number));
  ok(`connections: hostA's span runs 10:00 -> 10:10 (x=${spans[0][0]}..${spans[0][0] + spans[0][2]})`,
     spans.length === 2 && near(spans[0][0], xof(0)) && near(spans[0][0] + spans[0][2], xof(600)));
  ok(`connections: hostB's span runs 10:04 -> 10:20 (x=${spans[1][0]}..${spans[1][0] + spans[1][2]})`,
     spans.length === 2 && near(spans[1][0], xof(240)) && near(spans[1][0] + spans[1][2], xof(1200)));
  ok("connections: the earlier log is the upper lane",
     spans.length === 2 && spans[0][1] < spans[1][1]);
}

// 4. both charts carry the same lanes: same windows, one window per chart
{
  const lanes = (svg) => all(svg, /<rect class="sl-cov-track"[\s\S]*?data-x="(\w+)" data-y="([^"]*)"/g);
  ok("errors: same two lanes as the connections chart",
     lanes(errTwo).length === 2 &&
     lanes(errTwo).map((s) => /data-x="(\w+)"/.exec(s)[1]).join() ===
     lanes(connTwo).map((s) => /data-x="(\w+)"/.exec(s)[1]).join());
  const errWin = /data-y="log covers ([^"]*) to ([^"]*)"/.exec(lanes(errTwo)[0] || "");
  const connWin = /data-y="log covers ([^"]*) to ([^"]*)"/.exec(lanes(connTwo)[0] || "");
  ok("the two charts agree on every window",
     !!errWin && !!connWin && errWin[1] === connWin[1] && errWin[2] === connWin[2]);
}

// 5. the key names the servers and their windows
{
  const from = two.indexOf("Simultaneous Connections");
  const start = two.indexOf('class="sl-stack-legend"', from);
  const key = two.slice(start, two.indexOf("</div>", start));
  ok("key: a chart-window entry and one entry per server",
     /chart window/.test(key) && (key.match(/host[AB] — /g) || []).length === 2);
  ok("key: each entry carries the window it covers (minute resolution, like the axis)",
     /hostA — 2026-10-16 10:00 . 2026-10-16 10:10/.test(key) &&
     /hostB — 2026-10-16 10:04 . 2026-10-16 10:20/.test(key));
}

// 6. one server: no strip at all, and the canvas stays exactly as it was
{
  ok("single server: no lane is drawn",
     !/sl-cov-track/.test(connOne) && !/sl-cov-track/.test(errOne) &&
     !/sl-cov-key-track/.test(connOne));
  ok("single server: the chart geometry is untouched (300 / 260)",
     viewBox(connOne)[1] === 300 && viewBox(errOne)[1] === 260);
}

// 7. the JSON carries the same windows
{
  const j = JSON.parse(execFileSync(NATIVE,
    ["-o", "json", "-q", "-j", "1", S1, S2], { maxBuffer: 1 << 30 }).toString());
  const t = j.time_by_server || {};
  ok("json: time_by_server lists both hosts with their windows",
     t.hostA && t.hostA.first_timestamp === "2026-10-16T10:00:00.000000000Z" &&
     t.hostA.last_timestamp === "2026-10-16T10:10:00.000000000Z" &&
     t.hostB && t.hostB.first_timestamp === "2026-10-16T10:04:00.000000000Z" &&
     t.hostB.last_timestamp === "2026-10-16T10:20:00.000000000Z");
  const j1 = JSON.parse(execFileSync(NATIVE, ["-o", "json", "-q", "-j", "1", S1],
    { maxBuffer: 1 << 30 }).toString());
  ok("json: a single server still carries its window",
     j1.time_by_server && j1.time_by_server.hostA &&
     j1.time_by_server.hostA.last_timestamp === "2026-10-16T10:10:00.000000000Z");
}

// 8. spans no server's log covers are banded; a window the servers together
//    cover gets no band at all.
{
  ok("no 'no log' band when the servers cover the whole window",
     !/sl-nolog-band/.test(connTwo) && !/sl-nolog-band/.test(errTwo) &&
     !/>no log</.test(two));

  // Two servers twenty weeks apart: the reported range is the union, and
  // everything between them is a period no log covers.
  const G = `${SL.SCRATCH}/covgap`;
  fs.mkdirSync(G, { recursive: true });
  const mkAt = (host, date, hh) => {
    let s = "";
    for (let i = 0; i < 20; i++) {
      const ts = `${date}T${String(hh).padStart(2, "0")}:${String(i).padStart(2, "0")}:00.000000000Z`;
      s += `${ts} ${host} slapd[1]: conn=${i + 1} fd=${i + 10} ACCEPT from IP=10.0.0.1:1000 (IP=0.0.0.0:389)\n`;
      s += `${ts} ${host} slapd[1]: conn=${i + 1} op=0 SEARCH RESULT tag=101 err=49 qtime=0 etime=1 nentries=0 text=x\n`;
    }
    return s;
  };
  fs.writeFileSync(`${G}/g1.log`, mkAt("hostC", "2026-08-07", 5));
  fs.writeFileSync(`${G}/g2.log`, mkAt("hostD", "2026-10-18", 20));
  const gapHtml = run([`${G}/g1.log`, `${G}/g2.log`]);

  // window = [first line, last line]; the gap = [end of hostC, start of hostD]
  const tt0 = Date.parse("2026-08-07T05:00:00Z") / 1000;
  const tt1 = Date.parse("2026-10-18T20:19:00Z") / 1000;
  const gx = (iso) => 68 + ((Date.parse(iso) / 1000 - tt0) / (tt1 - tt0)) * 918;

  for (const [name, label] of [["connections", CONN], ["errors", ERR]]) {
    const svg = svgOf(gapHtml, label);
    const bands = [...svg.matchAll(/<rect class="sl-nolog-band" x="([\d.]+)"[^>]*width="([\d.]+)"/g)]
      .map((m) => [Number(m[1]), Number(m[2])]);
    ok(`${name}: one 'no log' band over the empty span`, bands.length === 1,
       `bands=${bands.length}`);
    if (bands.length === 1) {
      ok(`${name}: the band runs from hostC's end to hostD's start`,
         near(bands[0][0], gx("2026-08-07T05:19:00Z")) &&
         near(bands[0][0] + bands[0][1], gx("2026-10-18T20:00:00Z")));
    }
    ok(`${name}: the band carries a hover tooltip`,
       /class="sl-hit"[^>]*data-x="missing data"/.test(svg));
  }
  ok("the key names the band ('no log')", />no log</.test(gapHtml));
  ok("the subtitle says what the shading is",
     /shaded: no server's log covers it/.test(gapHtml));
}

// 9. the WASM session path draws the same band as the native binary
(async () => {
  const createSlaplog = require(path.join(WEB, "slaplog.js"));
  let out = [];
  const m = await createSlaplog({ print: (l) => out.push(l), printErr: (l) => out.push(l),
                                  locateFile: (p) => path.join(WEB, p) });
  try { m.FS.mkdir(MEM); } catch (e) { /* exists */ }
  // The build uses -ffp-contract=off (see the Makefile), so libstdc++ and
  // libc++ round identically and the two reports must match byte for byte —
  // no numeric tolerance is needed or wanted here.
  const norm = (s) => s.replace(/\n+$/, "").split("\n")
    .filter((l) => !/Processing time|Processing speed|Generated on|lines\/s/.test(l)).join("\n");
  m.ccall("slaplog_begin", "number", ["string"], ["-o html -q"]);
  for (const [i, hp] of [S1, S2].entries()) {
    const b = new Uint8Array(fs.readFileSync(hp));
    m.FS.writeFile(`${MEM}/s${i}.log`, b);
    m.ccall("slaplog_add_file", "number", ["string"], [`${MEM}/s${i}.log`]);
  }
  m.ccall("slaplog_end", "number", [], []);
  ok("wasm session == native, band included", norm(out.join("\n")) === norm(two));

  console.log("\n" + results.join("\n") + "\n\n" +
    results.filter((r) => r.startsWith("FAIL")).length + " failure(s) / " +
    results.length + " checks\n");
  process.exitCode = results.some((r) => r.startsWith("FAIL")) ? 1 : 0;
})().catch((e) => { console.error("harness error:", e); process.exit(2); });
