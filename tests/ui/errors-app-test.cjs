// errors-app-test.cjs — error counts and error texts per application.
//
// The "Errors per Application" table used to print the *global* per-code message
// histogram on every row, so two clients refused with the same code showed the
// same texts; the JSON had no per-application breakdown at all.  The messages
// are now keyed (application, code, text), and the JSON carries
// `error_counts_by_app`.
//
// Nothing here needs jsdom or the WebAssembly build: it drives the native
// binary and reads its text, HTML and JSON output.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const SL = require("../lib/env.cjs");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

// Two files, so the merge of the nested map is exercised too: APP_A's errors are
// split across both, with a different message in each.
const FILE1 = [
  "6a734745.00000001 0x7f9c1e33a700 slapd starting",
  "6a734745.00000002 0x7f9c1e33a700 conn=1 fd=12 ACCEPT from IP=192.0.2.10:1111 (IP=0.0.0.0:389)",
  '6a734745.00000003 0x7f9c1e33a700 conn=1 op=0 BIND dn="uid=APP_A,ou=TrustedApps,dc=x" method=128',
  "6a734745.00000004 0x7f9c1e33a700 conn=1 op=0 RESULT tag=97 err=0 qtime=0.000010 etime=0.000200 text=",
  "6a734745.00000005 0x7f9c1e33a700 conn=1 op=1 SEARCH RESULT tag=101 err=53 qtime=0 etime=1 nentries=0 text=Rule #1",
  "6a734745.00000006 0x7f9c1e33a700 conn=1 op=2 SEARCH RESULT tag=101 err=53 qtime=0 etime=1 nentries=0 text=Rule #1",
  "6a734745.00000007 0x7f9c1e33a700 conn=2 fd=13 ACCEPT from IP=192.0.2.11:2222 (IP=0.0.0.0:389)",
  '6a734745.00000008 0x7f9c1e33a700 conn=2 op=0 BIND dn="uid=APP_B,ou=TrustedApps,dc=x" method=128',
  "6a734745.00000009 0x7f9c1e33a700 conn=2 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text=",
  "6a734745.0000000a 0x7f9c1e33a700 conn=2 op=1 SEARCH RESULT tag=101 err=53 qtime=0 etime=1 nentries=0 text=Rule #9",
  "6a734745.0000000b 0x7f9c1e33a700 conn=2 op=2 SEARCH RESULT tag=101 err=53 qtime=0 etime=1 nentries=0 text=Rule #9",
].join("\n") + "\n";

const FILE2 = [
  "6a734745.00000001 0x7f9c1e33a700 slapd starting",
  "6a734745.00000002 0x7f9c1e33a700 conn=1 fd=12 ACCEPT from IP=192.0.2.10:1111 (IP=0.0.0.0:389)",
  '6a734745.00000003 0x7f9c1e33a700 conn=1 op=0 BIND dn="uid=APP_A,ou=TrustedApps,dc=x" method=128',
  "6a734745.00000004 0x7f9c1e33a700 conn=1 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text=",
  "6a734745.00000005 0x7f9c1e33a700 conn=1 op=1 SEARCH RESULT tag=101 err=53 qtime=0 etime=1 nentries=0 text=Rule #2",
  "6a734745.00000006 0x7f9c1e33a700 conn=2 fd=13 ACCEPT from IP=192.0.2.12:3333 (IP=0.0.0.0:389)",
  '6a734745.00000007 0x7f9c1e33a700 conn=2 op=0 BIND dn="uid=APP_C,ou=TrustedApps,dc=x" method=128',
  "6a734745.00000008 0x7f9c1e33a700 conn=2 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text=",
  "6a734745.00000009 0x7f9c1e33a700 conn=2 op=1 SEARCH RESULT tag=101 err=53 qtime=0 etime=1 nentries=0 text=Rule #1",
].join("\n") + "\n";

const F1 = path.join(SL.SCRATCH, "app1.log");
const F2 = path.join(SL.SCRATCH, "app2.log");
fs.writeFileSync(F1, FILE1);
fs.writeFileSync(F2, FILE2);

let checks = 0, failures = 0;
const check = (name, ok, detail) => {
  checks++;
  if (ok) console.log(`  ok    ${name}`);
  else { failures++; console.log(`  FAIL  ${name}${detail ? "\n        " + detail : ""}`); }
};
const run = (args) => execFileSync(SL.BIN, ["-q", ...args, F1, F2],
  { encoding: "utf8", maxBuffer: 1 << 28 });

// The application keys are the bind DNs; find them by the fragment.
const byApp = (obj, frag) => Object.entries(obj).find(([k]) => k.includes(frag));

// Expected, after the two files are merged.
const EXPECT = {
  APP_A: { count: 3, texts: { "Rule #1": 2, "Rule #2": 1 } },
  APP_B: { count: 2, texts: { "Rule #9": 2 } },
  APP_C: { count: 1, texts: { "Rule #1": 1 } },
};
const GLOBAL_53 = { count: 6, texts: { "Rule #1": 3, "Rule #2": 1, "Rule #9": 2 } };

const textsOf = (entry) => {
  const out = {};
  for (const t of entry.texts || []) out[t.text.trim()] = t.count;
  return out;
};

// ---------------------------------------------------------------- JSON ------
console.log("json");
const j = JSON.parse(run(["-o", "json"]));
check("error_counts_by_app is present", !!j.error_counts_by_app);

const perApp = j.error_counts_by_app || {};
for (const [frag, exp] of Object.entries(EXPECT)) {
  const found = byApp(perApp, frag);
  const entry = found && found[1]["53"];
  check(`${frag}: code 53 count = ${exp.count}`, !!entry && entry.count === exp.count,
        entry ? `got ${entry.count}` : "no entry");
  check(`${frag}: its own texts (${Object.keys(exp.texts).join(", ")})`,
        !!entry && JSON.stringify(textsOf(entry)) === JSON.stringify(exp.texts),
        entry ? JSON.stringify(textsOf(entry)) : "no entry");
}

// The regression: a client that never emitted Rule #1 must not show it.
const bEntry = byApp(perApp, "APP_B");
check("APP_B does not inherit another client's texts",
      !!bEntry && !JSON.stringify(bEntry[1]).includes("Rule #1"));

// Informational codes (success, compareFalse/True, referral, saslBindInProgress)
// are results, not errors: they stay in the global distribution, and never
// appear in the per-application error table.
const INFO = new Set(["0", "5", "6", "10", "14"]);
check("informational codes stay out of the per-application table",
      Object.values(perApp).every((a) => Object.keys(a).every((c) => !INFO.has(c))),
      JSON.stringify(Object.values(perApp).map((a) => Object.keys(a))));
check("informational codes stay in the global distribution",
      !!j.error_counts["0"] && j.error_counts["0"].count > 0);

// Global and per-application figures must agree, for every *failing* code.
// (An informational code has no per-application row, by design.)
check("global error_counts[53] carries every message",
      JSON.stringify(textsOf(j.error_counts["53"])) === JSON.stringify(GLOBAL_53.texts),
      JSON.stringify(textsOf(j.error_counts["53"])));
let mismatched = 0;
for (const [code, gv] of Object.entries(j.error_counts)) {
  if (INFO.has(code)) continue;
  const apps = Object.values(perApp);
  const sumCount = apps.reduce((n, a) => n + (a[code] ? a[code].count : 0), 0);
  if (sumCount !== gv.count) mismatched++;
  const sumTexts = {};
  for (const a of apps) {
    if (!a[code]) continue;
    for (const [msg, n] of Object.entries(textsOf(a[code]))) sumTexts[msg] = (sumTexts[msg] || 0) + n;
  }
  if (JSON.stringify(sumTexts) !== JSON.stringify(textsOf(gv))) mismatched++;
}
check("every code: per-application counts and texts add up to the global ones",
      mismatched === 0, `${mismatched} mismatch(es)`);

// ---------------------------------------------------------------- HTML ------
console.log("html");
const html = run(["-o", "html"]);
const rows = [...html.matchAll(/<tr>(.*?)<\/tr>/gs)]
  .map((m) => [...m[1].matchAll(/<td[^>]*>(.*?)<\/td>/gs)].map((c) =>
    c[1].replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").trim()))
  .filter((c) => c.length >= 5);
const rowOf = (frag) => rows.find((c) => c[0].includes(frag) && c[1] === "53");
check("no informational row in the per-application table",
      !rows.some((c) => c.length >= 5 && c[1] === "0" && c[0].includes("dc=x")));
check("APP_A's row shows only its own messages",
      (() => { const r = rowOf("APP_A"); return !!r && /2x: Rule #1/.test(r[4]) && /1x: Rule #2/.test(r[4]) && !/Rule #9/.test(r[4]); })());
check("APP_B's row shows its own message and not another's",
      (() => { const r = rowOf("APP_B"); return !!r && /2x: Rule #9/.test(r[4]) && !/Rule #1/.test(r[4]); })());

// ---------------------------------------------------------------- text ------
console.log("text");
const text = run(["-o", "text", "-s", "errors_per_app"]);
check("the text report shows APP_B without Rule #1",
      (() => { const l = text.split("\n").find((x) => x.includes("APP_B") && x.includes("53")); return !!l && l.includes("Rule #9") && !l.includes("Rule #1"); })());

console.log("");
console.log(`  ${failures} failure(s) / ${checks} checks`);
process.exitCode = failures ? 1 : 0;
