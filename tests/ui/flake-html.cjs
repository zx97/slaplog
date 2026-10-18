// @diag — a reproduction tool for the historical session-test flake, not a
// pass/fail check; tests/run-ui.cjs skips it.  Run it by hand when the flake
// comes back.
const SL = require("../lib/env.cjs");
// Root cause of the "session-test flake": two one-shot HTML runs separated in
// time, compared with the harness's own normalisation.  No chunking involved —
// if the difference is there, the flake has nothing to do with the session API.
const fs = require("fs"), path = require("path");
const WEB = "" + SL.ROOT + "/wasm/web";
const createSlaplog = require(path.join(WEB, "slaplog.js"));
const S = "" + SL.FIXTURES + "/slaplog-sample";

// Verbatim from session-test.cjs
const normOld = (s) => s.split("\n")
  .filter((l) => !/Processing time|Processing speed|Generated on|lines\/s/.test(l))
  .map((l) => l.replace(/("processing_time":\s*)[0-9.eE+-]+/, "$1X"))
  .join("\n");
// htmlcmp.cjs already normalises exactly this way.
const normNew = (s) => s.split("\n")
  .filter((l) => !/Processing time|Processing speed|Generated on|lines\/s|Generated/.test(l))
  .map((l) => l.replace(/("processing_time":\s*)[0-9.eE+-]+/, "$1X"))
  .join("\n");

let out = [];
(async () => {
  const m = await createSlaplog({ print: (l) => out.push(l), printErr: (l) => out.push(l),
                                  locateFile: (p) => path.join(WEB, p) });
  try { m.FS.mkdir("/work"); } catch (e) { /* exists */ }
  m.FS.writeFile("/work/a.log", new Uint8Array(fs.readFileSync(`${S}/access.log`)));
  const once = () => { out = []; m.ccall("slaplog_run", "number", ["string"], ["-o html -q /work/a.log"]); return out.join("\n"); };

  const A = once();
  await new Promise((r) => setTimeout(r, 1300));   // cross a wall-clock second
  const B = once();

  const diff = (norm) => {
    const a = norm(A).split("\n"), b = norm(B).split("\n");
    const d = [];
    for (let i = 0; i < Math.max(a.length, b.length); i++) if (a[i] !== b[i]) d.push(i);
    return d;
  };
  const do1 = diff(normOld), dn = diff(normNew);
  console.log(`one-shot vs one-shot, 1.3 s apart, html report:`);
  console.log(`  with the harness filter : ${do1.length} differing line(s)  -> ${do1.length ? "FAIL" : "ok"}`);
  for (const i of do1.slice(0, 3)) {
    console.log(`    @${i}: ${JSON.stringify(A.split("\n")[i].slice(0, 140))}`);
    console.log(`    @${i}: ${JSON.stringify(B.split("\n")[i].slice(0, 140))}`);
  }
  console.log(`  filtering "Generated"   : ${dn.length} differing line(s)  -> ${dn.length ? "FAIL" : "ok"}`);
})();
