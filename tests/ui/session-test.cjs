const SL = require("../lib/env.cjs");
// Equivalence test for the WASM session API.
//
// Proves that:
//   - feeding a plain log in arbitrary line-aligned chunks via slaplog_add_text
//     yields exactly the same report as one slaplog_run() call;
//   - adding several files through the session aggregates them into a single
//     report identical to passing them all to slaplog_run();
//   - .gz / .bz2 / .xz files are accepted through slaplog_add_file and give the
//     same result as the one-shot call.
//
// NOTE: the module uses Emscripten's in-memory filesystem, so every file handed
// to slaplog_run()/slaplog_add_file() must first be written into MEMFS.
const fs = require("fs");
const path = require("path");

const WEB = "" + SL.ROOT + "/wasm/web";
const createSlaplog = require(path.join(WEB, "slaplog.js"));
const S = "" + SL.FIXTURES + "/slaplog-sample";
const MEM = "/work";

let out = [];
const norm = (s) => s.split("\n")
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

// Copy a host file into MEMFS; returns its virtual path.
let seq = 0;
function stage(m, hostPath) {
  const vp = `${MEM}/f${++seq}${path.extname(hostPath)}`;
  m.FS.writeFile(vp, new Uint8Array(fs.readFileSync(hostPath)));
  return vp;
}

function chunkByLines(bytes, target) {
  const chunks = [];
  let from = 0;
  while (from < bytes.length) {
    let to = Math.min(from + target, bytes.length);
    if (to < bytes.length) {
      let i = to;
      while (i < bytes.length && bytes[i] !== 0x0a) i++;
      to = Math.min(i + 1, bytes.length);
    }
    chunks.push(bytes.subarray(from, to));
    from = to;
  }
  return chunks;
}

function runOnce(module, opts, memPaths) {
  out = [];
  module.ccall("slaplog_run", "number", ["string"], [opts + " " + memPaths.join(" ")]);
  return out.join("\n");
}

function runSession(module, opts, hostPaths, chunkSize) {
  out = [];
  module.ccall("slaplog_begin", "number", ["string"], [opts]);
  let ptr = 0, cap = 0;
  const ensure = (n) => {
    if (n > cap) { if (ptr) module._free(ptr); cap = Math.max(n, 1 << 20); ptr = module._malloc(cap); }
  };
  try {
    for (const hp of hostPaths) {
      const bytes = new Uint8Array(fs.readFileSync(hp));
      if (snapshot(bytes)) {
        module.ccall("slaplog_add_file", "number", ["string"], [stage(module, hp)]);
      } else {
        module.ccall("slaplog_input_begin", "number", [], []);
        for (const ch of chunkByLines(bytes, chunkSize)) {
          ensure(ch.length);
          module.HEAPU8.set(ch, ptr);
          module.ccall("slaplog_add_text", "number", ["number", "number"], [ptr, ch.length]);
        }
        module.ccall("slaplog_input_end", "number", [], []);
      }
    }
  } finally {
    if (ptr) module._free(ptr);
  }
  module.ccall("slaplog_end", "number", [], []);
  return out.join("\n");
}

(async () => {
  const module = await createSlaplog({
    print: (l) => out.push(l),
    printErr: (l) => out.push(l),
    locateFile: (p) => path.join(WEB, p),
  });
  try { module.FS.mkdir(MEM); } catch (e) { /* exists */ }

  const results = [];
  const ok = (n, c) => results.push((c ? "PASS  " : "FAIL  ") + n);
  const fmt = (f) => `-o ${f} -q`;

  const plainPaths = [`${S}/access.log`, `${S}/stress.log`];
  const plainMem = plainPaths.map((p) => stage(module, p));

  // Sanity: the reference report must actually contain data.
  ok("reference report is non-trivial",
     /Lines processed\s*\|\s*82\s/.test(runOnce(module, fmt("text"), [plainMem[0]])));

  // 1. chunked session == one-shot, for every format and several chunk sizes
  for (const f of ["text", "json", "html", "replay"]) {
    const ref = norm(runOnce(module, fmt(f), [plainMem[0]])).split("\n");
    for (const cs of [97, 1024, 65536, 4 * 1024 * 1024]) {
      const got = norm(runSession(module, fmt(f), [plainPaths[0]], cs)).split("\n");
      // Point at the first differing line (and its neighbourhood) rather than
      // making the next failure a hunt: the HTML report is 1200 lines, and only
      // one of them differing is the whole diagnostic.
      const at = ref.findIndex((l, k) => l !== got[k]);
      if (at >= 0) {
        console.log(`  DIFF ${f} chunk=${cs}B at line ${at + 1}/${ref.length} vs ${got.length}`);
        console.log(`    ref: ${String(ref[at]).slice(0, 220)}`);
        console.log(`    got: ${String(got[at]).slice(0, 220)}`);
      }
      ok(`${f}: chunked(${cs}B) == one-shot`,
         at < 0 && ref.length === got.length);
    }
  }

  // 2. multi-file session == one-shot over the same files
  for (const f of ["text", "json", "replay"]) {
    ok(`${f}: multi-file session == one-shot over 2 files`,
       norm(runSession(module, fmt(f), plainPaths, 4096)) ===
       norm(runOnce(module, fmt(f), plainMem)));
  }

  // 3. aggregation really covers both files
  const linesOf = (s) => +( /Lines processed\s*\|\s*(\d+)/.exec(s) || [0, 0])[1];
  const both = runSession(module, fmt("text"), plainPaths, 4096);
  const onlyA = runOnce(module, fmt("text"), [plainMem[0]]);
  ok(`aggregation sums both files (${linesOf(both)} = ${linesOf(onlyA)} + 2100)`,
     linesOf(both) === linesOf(onlyA) + 2100);

  // 4. compressed files through the session API
  for (const ext of ["gz", "bz2", "xz"]) {
    const hp = `${S}/access.log.${ext}`;
    const ref = norm(runOnce(module, fmt("text"), [stage(module, hp)]));
    const got = norm(runSession(module, fmt("text"), [hp], 4096));
    ok(`${ext}: session add_file == one-shot (and non-empty)`,
       got === ref && linesOf(ref) === 82);
  }

  // 5. mixed plain + compressed in one session
  const mixHost = [`${S}/access.log`, `${S}/access.log.xz`];
  ok("mixed plain + xz session == one-shot",
     norm(runSession(module, fmt("text"), mixHost, 2048)) ===
     norm(runOnce(module, fmt("text"), mixHost.map((p) => stage(module, p)))));

  console.log("\n" + results.join("\n") + "\n\n" +
    results.filter((r) => r.startsWith("FAIL")).length + " failure(s) / " +
    results.length + " checks\n");
  process.exitCode = results.some((r) => r.startsWith("FAIL")) ? 1 : 0;
})().catch((e) => { console.error("harness error:", e); process.exit(2); });
