// collapse-test.cjs — long tables are collapsed client-side behind a button.
//
// The report ships a script that hides the rows past the first 25 of any table
// and inserts a "show N more row(s)" button beside it; nothing is hidden in the
// served HTML, so the behaviour is only observable with the page's own script
// running — which is what jsdom does here.  The expectations are derived from
// the report that was just generated (every table over the limit has a button,
// no shorter one does) instead of a fixed count, so the test is fixture-driven.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const SL = require("../lib/env.cjs");
const path = require("path");
const { execFileSync } = require("child_process");
const { JSDOM } = SL.loadJsdom();

const LIMIT = 25;   // must match the script embedded in report.cpp

const html = execFileSync(SL.BIN, [
  "-q", "-o", "html",
  path.join(SL.FIXTURES, "logsmall", "a.log"),
  path.join(SL.FIXTURES, "logsmall", "b.log"),
], { maxBuffer: 1 << 30 }).toString();

const dom = new JSDOM(html, { runScripts: "dangerously", pretendToBeVisual: true });
const doc = dom.window.document;

const res = [];
const ok = (n, c) => res.push((c ? "PASS  " : "FAIL  ") + n);
const dataRows = (t) => [...t.querySelectorAll("tr")].filter((r) => r.querySelector("td"));
const isBtn = (t) => t.nextElementSibling && t.nextElementSibling.className === "sl-more";

setTimeout(() => {
  const tables = [...doc.querySelectorAll("table")];
  const long = tables.filter((t) => dataRows(t).length > LIMIT);
  const short = tables.filter((t) => dataRows(t).length <= LIMIT);

  ok(`the fixture yields at least one long table (${long.length})`, long.length >= 1);
  ok("every long table gets a button", long.every(isBtn));
  ok("no short table gets a button", short.every((t) => !isBtn(t)));

  const t = long[0], b = t.nextElementSibling;
  const rows = dataRows(t);
  const rest = rows.slice(LIMIT);

  ok(`initial state: the tail is folded (${rest.filter((r) => r.style.display === "none").length}/${rest.length})`,
     rest.length > 0 && rest.every((r) => r.style.display === "none"));
  ok(`label offers the tail ("${b.textContent}")`, /^show \d+ more row/.test(b.textContent));

  b.onclick();
  ok("click 1: every row visible", rows.every((r) => r.style.display !== "none"));
  ok(`label after click 1 ("${b.textContent}")`, /^hide \d+ row/.test(b.textContent));

  b.onclick();
  ok("click 2: the tail is folded again", rest.every((r) => r.style.display === "none"));
  ok(`label restored ("${b.textContent}")`, /^show \d+ more row/.test(b.textContent));

  console.log("\n" + res.join("\n") + "\n\n" +
    res.filter((r) => r.startsWith("FAIL")).length + " failure(s) / " + res.length + " checks\n");
  process.exitCode = res.some((r) => r.startsWith("FAIL")) ? 1 : 0;
}, 200);
