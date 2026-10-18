const SL = require("../lib/env.cjs");
// End-to-end check: the WASM session API, driven exactly like the browser page
// (line-aligned chunks for plain text, whole-file add for compressed input,
// several files per session), must produce the same report as the native
// binary fed the same files.
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const WEB = "" + SL.ROOT + "/wasm/web";
const NATIVE = "" + SL.ROOT + "/slaplog";
const createSlaplog = require(path.join(WEB, "slaplog.js"));
const D = "" + SL.FIXTURES + "/logsmall";
const MEM = "/work";
const CHUNK = 4 * 1024 * 1024;

let out = [];
const norm = (s) => s.replace(/\n+$/, "").split("\n")
  .filter((l) => !/Processing time|Processing speed|Generated|lines\/s/.test(l))
  .map((l) => l.replace(/("processing_time":\s*)[0-9.eE+-]+/, "$1X"))
  .join("\n");

function snapshot(b) {
  if (b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b) return "gz";
  if (b.length >= 4 && b[0] === 0x42 && b[1] === 0x5a && b[2] === 0x68 &&
      b[3] >= 0x31 && b[3] <= 0x39) return "bz2";
  if (b.length >= 6 && b[0] === 0xfd && b[1] === 0x37 && b[2] === 0x7a &&
      b[3] === 0x58 && b[4] === 0x5a && b[5] === 0x00) return "xz";
  return null;
}
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
  const module = await createSlaplog({ print: (l) => out.push(l), printErr: (l) => out.push(l), locateFile: (p) => path.join(WEB, p) });
  try { module.FS.mkdir(MEM); } catch (e) { /* exists */ }

  const results = [];
  const ok = (n, c) => results.push((c ? "PASS  " : "FAIL  ") + n);

  // Mirror of the page's run(): begin -> per file (chunk or add_file) -> end
  function wasmRun(fmt, hostPaths) {
    out = [];
    module.ccall("slaplog_begin", "number", ["string"], [`-o ${fmt} -q`]);
    let ptr = 0, cap = 0;
    const ensure = (n) => { if (n > cap) { if (ptr) module._free(ptr); cap = Math.max(n, 1 << 20); ptr = module._malloc(cap); } };
    try {
      for (const hp of hostPaths) {
        const bytes = new Uint8Array(fs.readFileSync(hp));
        const kind = snapshot(bytes);
        if (kind) {
          const vp = `${MEM}/input.${kind}`;
          module.FS.writeFile(vp, bytes);
          module.ccall("slaplog_add_file", "number", ["string"], [vp]);
        } else {
          module.ccall("slaplog_input_begin", "number", [], []);
          for (const ch of chunksByLine(bytes, CHUNK)) {
            ensure(ch.length);
            module.HEAPU8.set(ch, ptr);
            module.ccall("slaplog_add_text", "number", ["number", "number"], [ptr, ch.length]);
          }
          module.ccall("slaplog_input_end", "number", [], []);
        }
      }
    } finally { if (ptr) module._free(ptr); }
    module.ccall("slaplog_end", "number", [], []);
    return out.join("\n");
  }

  function nativeRun(fmt, hostPaths) {
    return execFileSync(NATIVE, [`-o`, fmt, `-q`, `-j`, `1`, ...hostPaths], { maxBuffer: 1 << 30 }).toString();
  }

  const groups = {
    "2 plain logs": [`${D}/a.log`, `${D}/b.log`],
    "plain + .gz + .bz2 + .xz (mixed)": [
      `${D}/a.log`, `${D}/b.log.gz`, `${D}/a.log.bz2`, `${D}/b.log.xz`,
    ],
    "3 compressed (.gz, .bz2, .xz)": [
      `${D}/a.log.gz`, `${D}/b.log.bz2`, `${D}/a.log.xz`,
    ],
  };

  for (const [label, paths] of Object.entries(groups)) {
    const sorted = paths.slice().sort();
    for (const fmt of ["text", "json", "replay"]) {
      const a = norm(nativeRun(fmt, sorted));
      const b = norm(wasmRun(fmt, sorted));
      const lines = (/Lines processed\s*\|\s*(\d+)/.exec(a) || [0, "?"])[1];
      ok(`${label} | ${fmt} (lines=${lines}, ${a.length}B)`, a === b);
    }
  }

  console.log("\n" + results.join("\n") + "\n\n" +
    results.filter((r) => r.startsWith("FAIL")).length + " failure(s) / " +
    results.length + " checks\n");
  process.exitCode = results.some((r) => r.startsWith("FAIL")) ? 1 : 0;
})().catch((e) => { console.error("harness error:", e); process.exit(2); });
