#!/usr/bin/env node
// tests/run-ui.cjs — run every harness in tests/ui/ and summarise.
//
// A harness signals success with exit 0, failure with a non-zero exit — that is
// the whole contract.  Harnesses that need the WebAssembly build or jsdom are
// skipped with an explicit notice when the dependency is absent, so `make
// test-ui` still does something useful after a native-only build.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const SL = require("./lib/env.cjs");

const DIR = path.join(SL.ROOT, "tests", "ui");
const files = fs.readdirSync(DIR).filter((f) => f.endsWith(".cjs")).sort();

const haveWasm = fs.existsSync(SL.WASM_JS);
let haveJsdom = true;
try { SL.loadJsdom(); } catch { haveJsdom = false; }

let pass = 0, fail = 0, skip = 0;
for (const f of files) {
  const src = fs.readFileSync(path.join(DIR, f), "utf8");
  if (/@diag/.test(src)) { console.log(`SKIP ${f} (diagnostic tool)`); skip++; continue; }
  if (/slaplog\.js|createSlaplog/.test(src) && !haveWasm) {
    console.log(`SKIP ${f} (needs the WebAssembly build: make wasm)`); skip++; continue;
  }
  if (/loadJsdom|JSDOM/.test(src) && !haveJsdom) {
    console.log(`SKIP ${f} (needs jsdom: npm install --prefix tests jsdom)`); skip++; continue;
  }

  const r = spawnSync(process.execPath, [path.join(DIR, f)], {
    encoding: "utf8", maxBuffer: 1 << 28,
  });
  if (r.status === 0) {
    console.log(`PASS ${f}`);
    pass++;
  } else {
    console.log(`FAIL ${f} (exit ${r.status})`);
    const bad = (r.stdout || "").split("\n").filter((l) => /FAIL|failure|echec|diff/i.test(l));
    for (const l of bad.slice(0, 12)) console.log("     " + l.trim());
    if (r.stderr) console.log("     " + r.stderr.trim().split("\n").slice(-3).join("\n     "));
    fail++;
  }
}

console.log(`\n${pass} passed, ${fail} failed, ${skip} skipped`);
process.exit(fail ? 1 : 0);
