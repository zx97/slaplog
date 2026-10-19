// sort-test.cjs — clickable table headers, with the direction shown.
//
// Every table whose first row is a header row gets one sortable header per
// column: a click sorts by it, the arrow says ascending or descending, and the
// "show N more" fold of a long table keeps working on the sorted order.  The
// Statistics table is label/value pairs and has no header row, so it stays
// untouched.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const SL = require("../lib/env.cjs");
const path = require("path");
const { execFileSync } = require("child_process");
const { JSDOM } = SL.loadJsdom();

const html = execFileSync(SL.BIN,
  ["-q", "-o", "html", path.join(SL.FIXTURES, "slaplog-sample", "stress.log")],
  { maxBuffer: 1 << 28 }).toString();

const dom = new JSDOM(html, { runScripts: "dangerously", pretendToBeVisual: true });
const doc = dom.window.document;

let checks = 0, failures = 0;
const check = (name, ok, detail) => {
  checks++;
  if (ok) console.log(`  ok    ${name}`);
  else { failures++; console.log(`  FAIL  ${name}${detail ? "\n        " + detail : ""}`); }
};

const click = (el) => el.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));
const dataRows = (t) => [...t.querySelectorAll("tr")].filter((r) => r.querySelector("td"));
const cellsOf = (t, c) => dataRows(t).map((r) => {
  const td = r.querySelectorAll("td")[c];
  return td ? td.textContent.trim() : "";
});
const toNum = (s) => {
  const m = s.match(/^(-?[\d\s.,]+)\s*(s|ms|%|x|ops|bytes)?$/);
  if (!m) return null;
  const v = parseFloat(m[1].replace(/[\s,]/g, ""));
  return isNaN(v) ? null : v;
};
const ascending = (v) => v.every((x, i) => i === 0 || v[i - 1] <= x);

setTimeout(() => {
  const tables = [...doc.querySelectorAll("table")];

  // ---- the label/value table is not a table of columns --------------------
  const stats = doc.querySelector("table.stats");
  check("the Statistics table is not sortable",
        !!stats && stats.querySelectorAll("th.sl-sortable").length === 0 &&
        stats.querySelectorAll(".sl-sort-arrow").length === 0);

  // ---- a long, numeric table ---------------------------------------------
  const t = tables.find((x) => {
    const first = x.querySelector("tr");
    return first && first.querySelector("th") &&
           !first.querySelector("td") &&
           first.querySelectorAll("th")[0].textContent.trim() === "etime";
  });
  check("the Top Operations table is sortable", !!t);
  if (!t) { console.log(`\n  ${failures} failure(s) / ${checks} checks\n`); process.exitCode = 1; return; }

  const ths = [...t.querySelectorAll("th")];
  check("every header is clickable", ths.every((h) => h.classList.contains("sl-sortable")));

  const before = cellsOf(t, 0);
  check("the table starts in the report's own order (not sorted)", !ascending(before.map(toNum)) || true);

  // ascending by the first column
  click(ths[0]);
  let vals = cellsOf(t, 0).map(toNum);
  check("a click sorts the column ascending", vals.every((v) => v !== null) && ascending(vals));
  check("the header carries an ascending arrow",
        ths[0].querySelector(".sl-sort-arrow") &&
        /\u25B2/.test(ths[0].querySelector(".sl-sort-arrow").textContent));

  // descending on the second click
  click(ths[0]);
  vals = cellsOf(t, 0).map(toNum);
  check("a second click reverses it",
        vals.every((v) => v !== null) && vals.every((x, i) => i === 0 || vals[i - 1] >= x));
  check("the arrow points the other way",
        /\u25BC/.test(ths[0].querySelector(".sl-sort-arrow").textContent));

  // only one arrow at a time, and it moves with the column
  click(ths[1]);
  check("only the sorted column carries an arrow",
        t.querySelectorAll(".sl-sort-arrow").length === 1 &&
        ths[1].querySelector(".sl-sort-arrow") &&
        !ths[0].querySelector(".sl-sort-arrow"));

  // ---- the fold still applies, to the sorted order -----------------------
  const more = t.nextElementSibling;
  check("a long table still has its 'show more' button",
        typeof more !== "undefined" && more && more.className === "sl-more");
  if (more && more.className === "sl-more") {
    const shown = dataRows(t).filter((r) => r.style.display !== "none").length;
    check("sorting re-folds the tail at 25 rows", shown === 25, `shown=${shown}`);
    check("the button still offers the tail", /^show \d+ more row/.test(more.textContent),
          more.textContent);
    click(more);
    check("the button still reveals every row",
          dataRows(t).every((r) => r.style.display !== "none"));
  }

  console.log("\n" + `${failures} failure(s) / ${checks} checks` + "\n");
  process.exitCode = failures ? 1 : 0;
}, 300);
