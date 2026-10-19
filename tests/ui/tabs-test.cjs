// tabs-test.cjs — the -o tabhtml report: section groups in tabs, nothing lost.
//
// Tabs are a presentation change only: every section stays in the DOM, so
// printing shows the whole report and a deep link can select the tab holding
// its section.  The default (-o html) is untouched.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const SL = require("../lib/env.cjs");
const path = require("path");
const { execFileSync } = require("child_process");
const { JSDOM } = SL.loadJsdom();

const LOG = path.join(SL.FIXTURES, "slaplog-sample", "stress.log");
const run = (fmt) => execFileSync(SL.BIN, ["-q", "-o", fmt, LOG],
  { maxBuffer: 1 << 28 }).toString();

let checks = 0, failures = 0;
const check = (name, ok, detail) => {
  checks++;
  if (ok) console.log(`  ok    ${name}`);
  else { failures++; console.log(`  FAIL  ${name}${detail ? "\n        " + detail : ""}`); }
};

const open = (html, url) => new JSDOM(html, {
  runScripts: "dangerously", pretendToBeVisual: true,
  ...(url ? { url } : {}),
});
const settle = (dom) => new Promise((r) => setTimeout(r, 250));
const visiblePanel = (doc) =>
  [...doc.querySelectorAll(".sl-tabpanel")].find((p) => !p.hidden) || null;
const selectedButton = (doc) =>
  [...doc.querySelectorAll(".sl-tabs button")].find((b) => b.classList.contains("on")) || null;
const click = (el, dom) => el.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true }));

(async () => {
  const plain = run("html");
  const tabbed = run("tabhtml");

  // ---- the default is unchanged -----------------------------------------
  check("-o html is not tabbed", !/class="sl-tabbed"/.test(plain));
  check("-o tabhtml marks the body", /<body class="sl-tabbed">/.test(tabbed));
  check("the alias -o tab-html works", (() => {
    try { return /class="sl-tabbed"/.test(run("tab-html")); } catch (e) { return false; }
  })());

  // ---- the tab bar ------------------------------------------------------
  const d1 = open(tabbed);
  await settle(d1);
  const doc = d1.window.document;
  const buttons = [...doc.querySelectorAll(".sl-tabs button")];
  check("a tab bar was built with 6 groups", buttons.length === 6,
        buttons.map((b) => b.textContent).join(" | "));
  check("exactly one panel is visible",
        doc.querySelectorAll(".sl-tabpanel").length > 1 &&
        doc.querySelectorAll(".sl-tabpanel:not([hidden])").length === 1);
  check("the first tab is the overview (Statistics)",
        !!visiblePanel(doc) && !!visiblePanel(doc).querySelector("#sec-statistics"));
  check("the selected tab is marked for assistive tech",
        !!selectedButton(doc) && selectedButton(doc).getAttribute("aria-selected") === "true");

  // ---- switching --------------------------------------------------------
  const errors = buttons.find((b) => b.textContent === "Errors");
  check("an 'Errors' tab exists", !!errors);
  if (errors) {
    click(errors, d1);
    check("clicking it shows the result-code section",
          !!visiblePanel(doc) && !!visiblePanel(doc).querySelector("#sec-result-codes"));
    check("and hides the overview", !visiblePanel(doc).querySelector("#sec-statistics"));
    check("the bar follows the selection", selectedButton(doc) === errors);
  }

  // ---- nothing is lost: every section is still in the DOM ---------------
  const countH2 = (h) => (h.match(/<h2 id=/g) || []).length;
  check("the tabbed report holds every section", countH2(tabbed) === countH2(plain),
        `tabhtml=${countH2(tabbed)} html=${countH2(plain)}`);
  check("printing reveals every panel",
        /@media print \{ body\.sl-tabbed \.sl-tabs \{ display:none !important; \}/.test(tabbed) &&
        /body\.sl-tabbed \.sl-tabpanel \{ display:block !important; \}/.test(tabbed));

  // ---- a deep link selects the tab that holds its section ----------------
  const d2 = open(tabbed, "https://example.test/report.html#sec-top-ops");
  await settle(d2);
  const doc2 = d2.window.document;
  check("a deep link opens the tab holding its section",
        !!visiblePanel(doc2) && !!visiblePanel(doc2).querySelector("#sec-top-ops"),
        selectedButton(doc2) ? selectedButton(doc2).textContent : "(none)");

  console.log("\n" + `${failures} failure(s) / ${checks} checks` + "\n");
  process.exitCode = failures ? 1 : 0;
})();
