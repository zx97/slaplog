// htmlcmp.cjs — native vs WebAssembly: the two builds must render the same
// HTML report for the same input.  Needs the WebAssembly build (`make wasm`).
//
// SPDX-License-Identifier: AGPL-3.0-or-later
const SL = require("../lib/env.cjs");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const C = require(SL.WASM_JS);
const LOGS = ["a.log", "b.log"].map((f) => path.join(SL.FIXTURES, "logsmall", f));
const norm = (s) => s.replace(/\n+$/, "").split("\n")
  .filter((l) => !/Processing time|lines\/s|Generated/.test(l)).join("\n");

let out = [];
(async () => {
  const m = await C({ print: (l) => out.push(l), printErr: (l) => out.push(l),
                       locateFile: (p) => path.join(SL.WASM_DIR, p) });
  try { m.FS.mkdir("/work"); } catch (e) { /* exists */ }

  const nat = norm(execFileSync(SL.BIN,
    ["-o", "html", "-q", "-j", "1", ...LOGS], { maxBuffer: 1 << 30 }).toString());

  out = [];
  m.ccall("slaplog_begin", "number", ["string"], ["-o html -q"]);
  for (const f of LOGS) {
    const b = new Uint8Array(fs.readFileSync(f));
    m.ccall("slaplog_input_begin", "number", [], []);
    const ptr = m._malloc(b.length);
    m.HEAPU8.set(b, ptr);
    m.ccall("slaplog_add_text", "number", ["number", "number"], [ptr, b.length]);
    m._free(ptr);
    m.ccall("slaplog_input_end", "number", [], []);
  }
  m.ccall("slaplog_end", "number", [], []);

  const wasm = norm(out.join("\n"));
  const a = nat.split("\n"), bb = wasm.split("\n");
  let diffs = 0;
  for (let i = 0; i < Math.max(a.length, bb.length); i++) {
    if (a[i] !== bb[i]) {
      diffs++;
      if (diffs <= 5) console.log(`  @${i}\n    nat :${JSON.stringify(a[i])}\n    wasm:${JSON.stringify(bb[i])}`);
    }
  }
  console.log(`  lines nat=${a.length} wasm=${bb.length} | differences=${diffs} -> ${diffs === 0 ? "IDENTICAL" : "DIFFERENT"}`);
  process.exitCode = diffs ? 1 : 0;
})();
