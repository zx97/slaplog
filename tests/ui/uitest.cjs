const SL = require("../lib/env.cjs");
// DOM/behaviour test for wasm/web/index.html under jsdom, with a stub of the
// Emscripten module.  Covers the form logic AND the full run flow (multi-file
// selection, sequential session calls, progress indicator, compressed input).
const fs = require("fs");
const { JSDOM } = require("../lib/env.cjs").loadJsdom();

const HTML = "" + SL.ROOT + "/wasm/web/index.html";
const html = fs.readFileSync(HTML, "utf8");

const calls = [];
const dom = new JSDOM(html, {
  runScripts: "dangerously",
  pretendToBeVisual: true,
  beforeParse(window) {
    window.createSlaplog = () => Promise.resolve({
      FS: {
        analyzePath: () => ({ exists: true }),
        mkdir: () => {},
        writeFile: (p, b) => calls.push(["writeFile", p, b.length]),
        readFile: () => new Uint8Array([1, 2, 3]),
        unlink: () => {},
      },
      _malloc: () => 1,
      _free: () => {},
      HEAPU8: { set: () => {} },
      ccall: (name, _r, _t, args) => { calls.push([name].concat(args || [])); return 0; },
    });
    // A download is an anchor click: keep jsdom out of the navigation.
    window.HTMLAnchorElement.prototype.click = function () {};
    window.URL.createObjectURL = () => "blob:stub";
    window.URL.revokeObjectURL = () => {};
  },
});

const { window } = dom;
const doc = window.document;
const $ = (id) => doc.getElementById(id);
const fire = (el, t) => el.dispatchEvent(new window.Event(t, { bubbles: true }));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const count = (sel) => doc.querySelectorAll(sel).length;

const enc = new TextEncoder();
const mkFile = (name, text) => {
  const b = enc.encode(text);
  return { name, size: b.length, arrayBuffer: async () => b.buffer };
};
const mkGz = (name, n) => {
  const b = new Uint8Array(n); b[0] = 0x1f; b[1] = 0x8b;
  return { name, size: n, arrayBuffer: async () => b.buffer };
};
const mkState = (name, n) => {
  const b = new Uint8Array(n);
  b.set(enc.encode("SLAPSTAT"));
  return {
    name, size: n, lastModified: 1,
    slice: (a, z) => ({ arrayBuffer: async () => b.slice(a, z).buffer }),
    arrayBuffer: async () => b.buffer,
  };
};
function dropFiles(list) {
  const ev = new window.Event("drop", { bubbles: true });
  ev.dataTransfer = { files: list };
  $("drop").dispatchEvent(ev);
}
const setFmt = (v) => { $("output").value = v; fire($("output"), "change"); };
const filesCount = () => count("#filelist .f");

const results = [];
const ok = (n, c) => results.push((c ? "PASS  " : "FAIL  ") + n);

(async () => {
  await sleep(120);

  // --- format-dependent panels --------------------------------------
  const rf = $("replay-fields"), sf = $("sections-fields");
  setFmt("html");
  ok("A. replay panel hidden for html", rf.style.display === "none");
  ok("B. sections panel hidden for html", sf.style.display === "none");
  setFmt("replay");
  ok("C. replay panel shown for replay", rf.style.display !== "none");
  ok("D. sections panel hidden for replay", sf.style.display === "none");
  setFmt("text");
  ok("E. sections panel shown for text", sf.style.display !== "none");
  ok("F. replay panel hidden for text", rf.style.display === "none");
  setFmt("json");
  ok("G. both panels hidden for json",
     rf.style.display === "none" && sf.style.display === "none");
  setFmt("html");

  // --- section checkboxes -------------------------------------------
  const all = $("sec-all");
  const others = Array.from(doc.querySelectorAll('#section-boxes input[data-section]'));
  ok("H. 16 individual section checkboxes + one 'all'", others.length === 16);
  ok("I. 'all' checked by default", all.checked && others.every((b) => !b.checked));
  const bySec = (s) => others.find((b) => b.dataset.section === s);
  bySec("stats").checked = true; fire(bySec("stats"), "change");
  bySec("ops").checked = true;   fire(bySec("ops"), "change");
  ok("J. individual picks drop 'all' and accumulate",
     !all.checked && bySec("stats").checked && bySec("ops").checked);
  all.checked = true; fire(all, "change");
  ok("K. 'all' clears every individual pick", all.checked && others.every((b) => !b.checked));
  all.checked = false; fire(all, "change");
  ok("L. empty selection falls back to 'all'", all.checked);

  // --- run button and download share a table row --------------------
  ok("M. download cell is in the same <tr> as the run button",
     $("download").closest("tr") === $("run").closest("tr"));
  ok("N. no 'input log format' selector in the markup",
     !$("logformat") && !/id="logformat"/.test(html));
  ok("O. auto-detect is stated in the page", /always auto-detected/.test(html));
  ok("O2. 'No charts' checkbox exists and is UNCHECKED by default",
     !!$("nograph") && $("nograph").checked === false);
  ok("P. header carries a tool tagline", /OpenLDAP[\s\S]{0,80}access-log analyzer/.test(html));

  // --- multi-file selection & ordering ------------------------------
  dropFiles([mkFile("c.log", "x\n"), mkFile("a.log", "y\n"), mkFile("b.log", "z\n")]);
  await sleep(30);
  const names = Array.from(doc.querySelectorAll("#filelist .f:not(.tot):not(.more) .fpath"))
    .map((s) => s.textContent);
  ok("Q. files sorted by name: " + names.join(","),
     names.join(",") === "a.log,b.log,c.log");
  dropFiles([mkFile("d.log", "w\n")]);
  await sleep(30);
  ok("R. files accumulate across drops", count("#filelist .f:not(.tot)") === 4);
  ok("S. total row shown for >1 file", count("#filelist .f.tot") === 1);

  // --- run over the 4 plain files -----------------------------------
  doc.querySelector('[data-preset="all"]').dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  calls.length = 0;
  $("run").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(400);

  const names2 = calls.map((c) => c[0]);
  const begin = calls.find((c) => c[0] === "slaplog_begin");
  ok("T. slaplog_begin has options, no path, no --log-format: " + begin[1],
     begin[1] === "-o html -q");
  ok("U. one input_begin/input_end pair per plain file",
     names2.filter((n) => n === "slaplog_input_begin").length === 4 &&
     names2.filter((n) => n === "slaplog_input_end").length === 4);
  ok("V. text chunks fed via slaplog_add_text",
     names2.filter((n) => n === "slaplog_add_text").length >= 4);
  ok("W. session closed with slaplog_end", names2[names2.length - 1] === "slaplog_end");
  ok("X. progress bar reaches 100%", parseFloat($("progress-fill").style.width) === 100);
  ok("Y. progress shows the file count: " + $("progress-name").textContent,
     /4\/4/.test($("progress-name").textContent));
  ok("Z. a download link is offered next to the run button",
     !!$("download").querySelector("a"));

  // --- text format passes -s / -c, never --log-format ---------------
  setFmt("text");
  $("compact").checked = true;
  bySec("stats").checked = true; fire(bySec("stats"), "change");
  $("clear").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(20);
  dropFiles([mkFile("a.log", "x\n")]);
  await sleep(20);
  calls.length = 0;
  $("run").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(200);
  const b2 = calls.find((c) => c[0] === "slaplog_begin")[1];
  ok("AA. text args carry -c and -s but no --log-format: " + b2,
     /-o text -q -c -s stats/.test(b2) && !/--log-format/.test(b2));

  // --- compressed input ---------------------------------------------
  $("clear").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(20);
  ok("AB. clear empties the file list", count("#filelist .f:not(.tot)") === 0);
  dropFiles([mkGz("big.log.gz", 4096)]);
  await sleep(20);
  calls.length = 0;
  $("run").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(200);
  const wf = calls.find((c) => c[0] === "writeFile");
  ok("AC. compressed file staged into MEMFS as .gz: " + (wf ? wf[1] : "none"),
     !!wf && wf[1] === "/work/input.gz");
  ok("AD. compressed file analysed via slaplog_add_file",
     calls.some((c) => c[0] === "slaplog_add_file") &&
     !calls.some((c) => c[0] === "slaplog_add_text"));

  // --- charts option reaches the CLI ---------------------------------
  setFmt("html");
  calls.length = 0;
  $("run").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(200);
  ok("O3. html without the box: no --no-graph",
     !/--no-graph/.test(calls.find((c) => c[0] === "slaplog_begin")[1]));
  $("nograph").checked = true;
  calls.length = 0;
  $("run").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(200);
  ok("O4. checking the box passes --no-graph: " + calls.find((c) => c[0] === "slaplog_begin")[1],
     /--no-graph/.test(calls.find((c) => c[0] === "slaplog_begin")[1]));
  setFmt("text");
  calls.length = 0;
  $("run").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(200);
  ok("O5. non-html formats never get --no-graph",
     !/--no-graph/.test(calls.find((c) => c[0] === "slaplog_begin")[1]));
  $("nograph").checked = false;
  ok("O6. report iframe allows scripts but not same-origin",
     /sandbox",\s*"allow-scripts"/.test(html) && !/allow-same-origin/.test(html));

  // --- "Also save the state" -----------------------------------------
  $("save-state").checked = true;
  setFmt("json");
  calls.length = 0;
  $("run").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(250);
  ok("S1. ticking 'Also save the state' writes one after the run",
     calls.some((c) => c[0] === "slaplog_save_state"),
     calls.map((c) => c[0]).join(","));
  ok("S2. and the download link says it is written",
     /— written/.test($("download").textContent));
  $("save-state").checked = false;

  // --- state files are recognised and routed -------------------------
  // The checks above have already put logs in the list: count the delta.
  const before = filesCount();
  dropFiles([mkState("week1.slapstate", 64)]);
  await sleep(50);
  ok("R1. a state file dropped in the log area is not added as a log",
     filesCount() === before && /state file/i.test($("status").textContent));
  ok("R2. it makes the run possible on its own (resume selected)",
     $("run").disabled === false);
  dropFiles([mkFile("access.log", "conn=1 ACCEPT\n")]);
  await sleep(50);
  ok("R3. a log dropped afterwards goes to the log list",
     filesCount() === before + 1);
  $("resume-clear").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(20);
  ok("R4. clearing the state leaves the log in place",
     filesCount() === before + 1);

  // --- static layout ------------------------------------------------
  ok("AE. CSS no longer caps width at 1080px", !/max-width:\s*1080px/.test(html));
  const m = html.match(/main\s*{[^}]*width:\s*([^;]+);/);
  ok("AF. main uses a percentage width (" + (m ? m[1].trim() : "?") + ")", !!m && /%/.test(m[1]));

  console.log("\n" + results.join("\n") + "\n\n" +
    results.filter((r) => r.startsWith("FAIL")).length + " failure(s) / " +
    results.length + " checks\n");
  process.exitCode = results.some((r) => r.startsWith("FAIL")) ? 1 : 0;
})();
