// state-test.cjs — a state saved by the native build, resumed inside the
// WebAssembly session API, must give the same report as analysing everything
// at once.  This is the browser half of --save-state / --resume.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const SL = require("../lib/env.cjs");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const createSlaplog = require(SL.WASM_JS);
const A = path.join(SL.FIXTURES, "logsmall", "a.log");
const B = path.join(SL.FIXTURES, "logsmall", "b.log");
const STATE = path.join(SL.SCRATCH, "a.slapstate");

// Floats are summed in merge order (the native run parses A then B, the WASM
// run resumes A's state then parses B), so their last digits differ; the counts
// and every string are what this compares.
const norm = (s) => s.replace(/\n+$/, "").split("\n")
  .filter((l) => !/Processing time|Processing speed|Generated|lines\/s/.test(l))
  .map((l) => l.replace(/-?\d+\.\d+(?:[eE][-+]?\d+)?/g, "0"))
  .join("\n");

let checks = 0, failures = 0;
const check = (name, ok, detail) => {
  checks++;
  if (ok) console.log(`  ok    ${name}`);
  else { failures++; console.log(`  FAIL  ${name}${detail ? "\n        " + detail : ""}`); }
};

let out = [];
function* chunksByLine(bytes, target) {
  let from = 0;
  while (from < bytes.length) {
    let to = Math.min(from + target, bytes.length);
    if (to < bytes.length) { let i = to; while (i < bytes.length && bytes[i] !== 0x0a) i++; to = Math.min(i + 1, bytes.length); }
    yield bytes.subarray(from, to);
    from = to;
  }
}

(async () => {
  // The state is written by the command-line build, which is the real scenario:
  // a big run on a server, resumed in the browser.
  execFileSync(SL.BIN, ["-q", "-o", "json", "--save-state", STATE, A],
    { maxBuffer: 1 << 28 });
  check("the native build wrote a state file", fs.existsSync(STATE) && fs.statSync(STATE).size > 0);

  const module = await createSlaplog({ print: (l) => out.push(l), printErr: (l) => out.push(l),
                                       locateFile: (p) => path.join(SL.WASM_DIR, p) });
  try { module.FS.mkdir("/work"); } catch (e) { /* exists */ }

  function wasm(resume, logs, fmt) {
    out = [];
    module.ccall("slaplog_begin", "number", ["string"], [`-o ${fmt} -q`]);
    let rc = 0;
    if (resume) {
      module.FS.writeFile("/work/resume.state", new Uint8Array(fs.readFileSync(resume)));
      rc = module.ccall("slaplog_resume", "number", ["string"], ["/work/resume.state"]);
      try { module.FS.unlink("/work/resume.state"); } catch (e) { /* ignore */ }
    }
    let ptr = 0, cap = 0;
    const ensure = (n) => { if (n > cap) { if (ptr) module._free(ptr); cap = Math.max(n, 1 << 20); ptr = module._malloc(cap); } };
    for (const lp of logs) {
      const bytes = new Uint8Array(fs.readFileSync(lp));
      module.ccall("slaplog_input_begin", "number", [], []);
      for (const ch of chunksByLine(bytes, 4 * 1024 * 1024)) {
        ensure(ch.length);
        module.HEAPU8.set(ch, ptr);
        module.ccall("slaplog_add_text", "number", ["number", "number"], [ptr, ch.length]);
      }
      module.ccall("slaplog_input_end", "number", [], []);
    }
    if (ptr) module._free(ptr);
    module.ccall("slaplog_end", "number", [], []);
    return { rc, text: out.join("\n") };
  }

  const native = (args) => execFileSync(SL.BIN, ["-q", ...args], { maxBuffer: 1 << 30 }).toString();

  for (const fmt of ["json", "text"]) {
    const ref = norm(native(["-o", fmt, "-j", "1", A, B]));
    const got = wasm(STATE, [B], fmt);
    check(`wasm: state + ${path.basename(B)} == native A+B (${fmt})`,
          got.rc === 0 && norm(got.text) === ref);
  }

  const refOnly = norm(native(["-o", "json", "-j", "1", A]));
  const gotOnly = wasm(STATE, [], "json");
  check("wasm: the state alone re-displays the previous analysis",
        gotOnly.rc === 0 && norm(gotOnly.text) === refOnly);

  // A state saved while writing JSON must still replay a complete HTML report:
  // the chart series are always collected, not only when a chart is drawn.
  const normHtml = (s) => s
    .replace(/(Generated<\/div><div class="meta-value">)[^<]*/g, "$1T")
    .replace(/(Processing time<\/div><div class="meta-value">)[^<]*/g, "$1T")
    .replace(/(Speed<\/div><div class="meta-value">)[^<]*/g, "$1T")
    .replace(/<td>[0-9.]+(?:e[+-]?[0-9]+)? s<\/td>/g, "<td>T</td>")
    .replace(/<td>[0-9.]+ lines\/s<\/td>/g, "<td>T</td>");
  const jsonState = path.join(SL.SCRATCH, "from-json.slapstate");
  execFileSync(SL.BIN, ["-q", "-o", "json", "--save-state", jsonState, A], { maxBuffer: 1 << 28 });
  const directHtml = normHtml(native(["-o", "html", "-j", "1", A]));
  const resumedHtml = normHtml(native(["-o", "html", "-j", "1", "--resume", jsonState]));
  check("a state saved from -o json replays the same HTML (charts included)",
        directHtml === resumedHtml);

  // The browser can also produce a state: write it from the module, then fold
  // a log into it with the command-line build.
  wasm(null, [A], "json");
  const SAVED = path.join(SL.SCRATCH, "from-wasm.slapstate");
  const rcSave = module.ccall("slaplog_save_state", "number", ["string"],
                              ["/work/from-wasm.slapstate"]);
  check("wasm: a state file can be written", rcSave === 0);
  if (rcSave === 0) {
    fs.writeFileSync(SAVED, Buffer.from(module.FS.readFile("/work/from-wasm.slapstate")));
    const refSaved = norm(native(["-o", "json", "-j", "1", A, B]));
    const gotSaved = norm(native(["-o", "json", "-j", "1", "--resume", SAVED, B]));
    check("a state written in the browser + B == native A+B", gotSaved === refSaved);
  }

  // A broken state must be reported, not silently ignored.
  module.FS.writeFile("/work/bad.state", new TextEncoder().encode("not a state"));
  out = [];
  module.ccall("slaplog_begin", "number", ["string"], ["-o json -q"]);
  const bad = module.ccall("slaplog_resume", "number", ["string"], ["/work/bad.state"]);
  check("wasm: a foreign file is refused", bad !== 0);
  module.ccall("slaplog_end", "number", [], []);

  console.log("\n" + `${failures} failure(s) / ${checks} checks` + "\n");
  process.exitCode = failures ? 1 : 0;
})().catch((e) => { console.error("harness error:", e); process.exit(2); });
