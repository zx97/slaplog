const SL = require("../lib/env.cjs");
// Page-level behaviour of wasm/web/index.html: size pre-flight + actionable
// choices, per-file removal, duplicate rejection, footer version, graceful OOM.
const fs = require("fs");
const { JSDOM } = SL.loadJsdom();

const html = fs.readFileSync(SL.PAGE, "utf8");
const calls = [];
let abortMode = false;

const dom = new JSDOM(html, {
  runScripts: "dangerously", pretendToBeVisual: true,
  beforeParse(w) {
    w.createSlaplog = () => Promise.resolve({
      FS: {
        analyzePath: () => ({ exists: true }), mkdir() {},
        writeFile(p) { calls.push(["writeFile", p]); },
        unlink(p) { calls.push(["unlink", p]); },
      },
      _malloc: () => 1, _free() {}, HEAPU8: { set() {} },
      ccall: (n) => {
        calls.push([n]);
        if (abortMode) throw new Error("RuntimeError: Aborted()");
        return n === "slaplog_version" ? "3.8.0" : 0;
      },
    });
    w.URL.createObjectURL = () => "blob:x";
    w.URL.revokeObjectURL = () => {};
  },
});

const { window } = dom, doc = window.document, $ = (id) => doc.getElementById(id);
const fire = (el, t) => el.dispatchEvent(new window.Event(t, { bubbles: true }));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const enc = new TextEncoder();
const GiB = 1024 ** 3;

const mkFile = (n, t) => { const b = enc.encode(t); return { name: n, size: b.length, arrayBuffer: async () => b.buffer }; };
const mkBig = (n, sz) => ({ name: n, size: sz, lastModified: 1, arrayBuffer: async () => new ArrayBuffer(0) });
const mkGz = (n, sz) => { const b = new Uint8Array(sz); b[0] = 0x1f; b[1] = 0x8b; return { name: n, size: sz, arrayBuffer: async () => b.buffer }; };
const drop = (list) => { const e = new window.Event("drop", { bubbles: true }); e.dataTransfer = { files: list }; $("drop").dispatchEvent(e); };
const clear = () => $("clear").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
const rows = () => doc.querySelectorAll("#filelist .f:not(.tot)");
const warn = () => $("warn");
const clickWarn = (kind) => warn().querySelector(`[data-warn="${kind}"]`).dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
const run = async () => { calls.length = 0; $("run").dispatchEvent(new window.MouseEvent("click", { bubbles: true })); await sleep(250); };

// Mirror of the page's calibration: 4 GiB ceiling / (measured ratio x margin).
const limitFor = (charts) => Math.floor((4 * GiB) / ((charts ? 1.12 : 1.02) * 1.30));

const res = [];
const ok = (n, c) => res.push((c ? "PASS  " : "FAIL  ") + n);

(async () => {
  await sleep(150);

  // --- footer version, read from the module ---------------------------------
  ok("version shown in the footer", $("version").textContent === "v3.8.0");

  // --- a reasonable size: no warning ----------------------------------------
  // The reported case: 1.09 GiB used to be flagged.  It must now be silent.
  clear(); drop([mkBig("a.log", 1.09 * GiB)]); await sleep(30);
  ok("1.09 GiB (the reported case): no warning", warn().style.display === "none");

  // --- too large: a warning and the proposed ways out -----------------------
  clear(); drop([mkBig("a.log", 3 * GiB)]); await sleep(30);
  ok("3 GiB: a warning is shown", warn().style.display !== "none");
  ok("the message names the 32-bit limit", /32-bit/.test(warn().innerHTML));
  ok("the message no longer claims it will abort", !/will abort/.test(warn().innerHTML));
  ok("the message states the computed safe size", /safe here/.test(warn().innerHTML));
  ok("the message quantifies the memory growth", /1\.1/.test(warn().innerHTML));
  ok("'Analyse without charts' is proposed", /data-warn="nocharts"/.test(warn().innerHTML));
  ok("the charts' cost is stated honestly (10 %)", /10 %/.test(warn().innerHTML));
  ok("the command-line build is linked", /command-line build/.test(warn().innerHTML));

  // --- the ceiling follows the charts ---------------------------------------
  // 2.9 GiB is over the charts limit (2.75) but under the no-charts one (3.02).
  clear(); drop([mkBig("a.log", 2.9 * GiB)]); await sleep(30);
  ok("2.9 GiB with charts: warning", warn().style.display !== "none");
  clickWarn("nocharts"); await sleep(30);
  ok("clicking 'Analyse without charts' ticks No charts", $("nograph").checked === true);
  ok("2.9 GiB without charts: warning cleared", warn().style.display === "none");
  $("nograph").checked = false; fire($("nograph"), "change"); await sleep(30);
  ok("re-ticking the charts brings the warning back", warn().style.display !== "none");

  // --- the 'trim' button -----------------------------------------------------
  clear(); drop([mkBig("f1.log", 1.5 * GiB), mkBig("f2.log", 1.5 * GiB), mkBig("f3.log", 1.5 * GiB)]);
  await sleep(30);
  ok("'trim' is proposed for 4.5 GiB", /data-warn="trim"/.test(warn().innerHTML));
  clickWarn("trim"); await sleep(30);
  ok("trim keeps only what fits under the ceiling", rows().length === 1);
  ok("warning cleared after trim", warn().style.display === "none");

  // --- the applied ceiling is the computed one ------------------------------
  ok("charts ceiling ~2.75 GiB", Math.abs(limitFor(true) / GiB - 2.75) < 0.05);
  ok("no-charts ceiling ~3.02 GiB", Math.abs(limitFor(false) / GiB - 3.02) < 0.05);

  // --- one trash button per file --------------------------------------------
  clear(); drop([mkFile("a.log", "x\n"), mkFile("b.log", "y\n"), mkFile("c.log", "z\n")]);
  await sleep(30);
  ok("3 files listed", rows().length === 3);
  ok("one trash button per file", doc.querySelectorAll("#filelist .fdel").length === 3);
  rows()[1].querySelector(".fdel").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(30);
  ok("trash: the file is removed", rows().length === 2);
  ok("trash: it is the right one that goes",
     [...rows()].every((r) => !/b\.log/.test(r.textContent)));

  // --- duplicates -----------------------------------------------------------
  const dup = mkFile("dup.log", "q\n");
  clear(); drop([dup, dup]); await sleep(30);
  ok("a duplicate is ignored (a single row)", rows().length === 1);

  // --- a compressed file: no MEMFS leak -------------------------------------
  clear(); drop([mkGz("z.log.gz", 2048)]); await sleep(30);
  await run();
  ok("unlink is called on the compressed file",
     calls.some((c) => c[0] === "unlink" && c[1] === "/work/input.gz"));

  // --- memory abort ---------------------------------------------------------
  clear(); abortMode = true; drop([mkFile("a.log", "x\n")]); await sleep(30);
  await run(); abortMode = false;
  ok("an explicit abort message", /ran out of memory/.test($("status").textContent));
  ok("advice to reload the page", /Reload the page/.test(warn().innerHTML));
  ok("advice to use fewer files at a time", /fewer files at a time/.test(warn().innerHTML));
  ok("the Analyze button is disabled after the abort", $("run").disabled === true);

  console.log("\n" + res.join("\n") + "\n\n" +
              res.filter((r) => r.startsWith("FAIL")).length + " failure(s) / " + res.length + "\n");
  process.exitCode = res.some((r) => r.startsWith("FAIL")) ? 1 : 0;
})();
