const SL = require("../lib/env.cjs");
// Fast isolation matrix: native vs WASM (one-shot and session) on small real
// log extracts, to pinpoint any remaining divergence.
const fs = require("fs"), path = require("path"), { execFileSync } = require("child_process");
const WEB = "" + SL.ROOT + "/wasm/web";
const createSlaplog = require(path.join(WEB, "slaplog.js"));
const D = "" + SL.FIXTURES + "/logsmall";
const MEM = "/work";
let out = [];
const norm = (s) => s.replace(/\n+$/, "").split("\n")
  .filter((l) => !/Processing time|Processing speed|Generated|lines\/s/.test(l))
  .map((l) => l.replace(/("processing_time":\s*)[0-9.eE+-]+/, "$1X")).join("\n");
function snapshot(b) {
  if (b[0] === 0x1f && b[1] === 0x8b) return "gz";
  if (b[0] === 0x42 && b[1] === 0x5a && b[2] === 0x68) return "bz2";
  if (b[0] === 0xfd && b[1] === 0x37 && b[2] === 0x7a) return "xz";
  return null;
}
function* chunksByLine(b, t) {
  let f = 0;
  while (f < b.length) { let to = Math.min(f + t, b.length);
    if (to < b.length) { let i = to; while (i < b.length && b[i] !== 0x0a) i++; to = Math.min(i + 1, b.length); }
    yield b.subarray(f, to); f = to; }
}
(async () => {
  const m = await createSlaplog({ print: (l) => out.push(l), printErr: (l) => out.push(l), locateFile: (p) => path.join(WEB, p) });
  try { m.FS.mkdir(MEM); } catch (e) {}
  const nat = (fmt, paths) => norm(execFileSync("" + SL.ROOT + "/slaplog", ["-o", fmt, "-q", "-j", "1", ...paths], { maxBuffer: 1 << 30 }).toString());
  function wasmSession(fmt, paths, chunk = 4096) {
    out = []; m.ccall("slaplog_begin", "number", ["string"], [`-o ${fmt} -q`]);
    let ptr = 0, cap = 0;
    const en = (n) => { if (n > cap) { if (ptr) m._free(ptr); cap = Math.max(n, 1 << 20); ptr = m._malloc(cap); } };
    for (const hp of paths) {
      const b = new Uint8Array(fs.readFileSync(hp));
      const k = snapshot(b);
      if (k) { const vp = `${MEM}/i${Math.random().toString(36).slice(2)}.${k}`; m.FS.writeFile(vp, b); m.ccall("slaplog_add_file", "number", ["string"], [vp]); }
      else { m.ccall("slaplog_input_begin", "number", [], []);
        for (const c of chunksByLine(b, chunk)) { en(c.length); m.HEAPU8.set(c, ptr); m.ccall("slaplog_add_text", "number", ["number", "number"], [ptr, c.length]); }
        m.ccall("slaplog_input_end", "number", [], []); }
    }
    if (ptr) m._free(ptr);
    m.ccall("slaplog_end", "number", [], []); return norm(out.join("\n"));
  }
  function wasmOnce(fmt, paths) {
    out = []; const vps = paths.map((hp, i) => `${MEM}/o${i}${path.extname(hp)}`);
    vps.forEach((vp, i) => m.FS.writeFile(vp, new Uint8Array(fs.readFileSync(paths[i]))));
    m.ccall("slaplog_run", "number", ["string"], [`-o ${fmt} -q ` + vps.join(" ")]);
    return norm(out.join("\n"));
  }
  const cases = [
    ["a.log", [`${D}/a.log`]],
    ["a.log.gz", [`${D}/a.log.gz`]],
    ["a.log.bz2", [`${D}/a.log.bz2`]],
    ["a.log.xz", [`${D}/a.log.xz`]],
    ["a+b plain", [`${D}/a.log`, `${D}/b.log`]],
    ["a + b.gz", [`${D}/a.log`, `${D}/b.log.gz`]],
    ["a.gz + b.bz2 + a.xz", [`${D}/a.log.gz`, `${D}/b.log.bz2`, `${D}/a.log.xz`]],
  ];
  let fails = 0, total = 0;
  for (const [label, paths0] of cases) {
    const paths = paths0.slice().sort();
    for (const fmt of ["text", "json", "replay"]) {
      total++;
      const a = nat(fmt, paths), s = wasmSession(fmt, paths), o = wasmOnce(fmt, paths);
      if (a === s && a === o) { console.log(`  OK    ${label.padEnd(22)} ${fmt}`); continue; }
      fails++;
      console.log(`  FAIL  ${label.padEnd(22)} ${fmt}   nat/session/oneshot: ${a === s ? "=" : "!"} ${a === o ? "=" : "!"}`);
      const A = a.split("\n"), S = s.split("\n");
      for (let i = 0; i < Math.max(A.length, S.length); i++) if (A[i] !== S[i]) {
        console.log(`        @${i}\n          nat    : ${JSON.stringify(A[i])}\n          session: ${JSON.stringify(S[i])}`);
        break;
      }
      if (a !== o) { const O = o.split("\n"); for (let i = 0; i < Math.max(A.length, O.length); i++) if (A[i] !== O[i]) { console.log(`          oneshot: ${JSON.stringify(O[i])}`); break; } }
    }
  }
  console.log(`\n  ${total - fails}/${total} OK\n`);
  process.exitCode = fails ? 1 : 0;
})();
