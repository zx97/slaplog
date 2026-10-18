#!/usr/bin/env node
const SL = require("../lib/env.cjs");
// dirpick-test.cjs — folder selection in the WASM page.
//
// The page has to serve the exact shape of a cluster log directory:
//
//   logs/202610_pcache/server1/slapd_2.6.log
//   logs/202610_pcache/server2/slapd_2.6.log
//   logs/202610_pcache/server3/slapd_2.6.log
//
// i.e. N files with the SAME name (and often the same size and mtime) in
// different folders.  A picker cannot span directories, so a folder is the unit:
// it is dropped (walked through webkitGetAsEntry) or picked (webkitdirectory).
//
// What is checked here:
//   1. a dropped folder is walked recursively and every file is tagged with its
//      path inside the selection;
//   2. two same-named files that also share size and mtime BOTH survive -- the
//      dedup key used to be built on the name alone, which dropped the second;
//   3. the list shows the path, not the bare name;
//   4. re-dropping the same folder is idempotent;
//   5. the order follows the path, so a run is reproducible;
//   6. a big folder is summarised instead of listed (capped rows);
//   7. the "Add a folder…" button builds a webkitdirectory input, and neither
//      button lets its click reach the drop zone (which would open a second
//      picker).
const fs = require("fs");
const { JSDOM } = require("../lib/env.cjs").loadJsdom();

const HTML = "" + SL.ROOT + "/wasm/web/index.html";
const html = fs.readFileSync(HTML, "utf8");

const created = [];
const dom = new JSDOM(html, {
  runScripts: "dangerously",
  pretendToBeVisual: true,
  beforeParse(window) {
    window.createSlaplog = () => Promise.resolve({
      FS: { analyzePath: () => ({ exists: true }), mkdir: () => {} },
      _malloc: () => 1, _free: () => {},
      HEAPU8: { set: () => {} },
      ccall: () => 0,
    });
    window.URL.createObjectURL = () => "blob:stub";
    window.URL.revokeObjectURL = () => {};
    // Record the inputs the page builds when a picker is opened.
    const realCreate = window.document.createElement.bind(window.document);
    window.document.createElement = (tag) => {
      const el = realCreate(tag);
      if (String(tag).toLowerCase() === "input") created.push(el);
      return el;
    };
  },
});

const { window } = dom;
const doc = window.document;
const $ = (id) => doc.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rows = () => Array.from(doc.querySelectorAll("#filelist .f:not(.tot):not(.more)"));
const paths = () => rows().map((r) => r.querySelector(".fpath").textContent);

let failures = 0, checks = 0;
function check(name, ok, detail) {
  checks++;
  if (!ok) { failures++; console.log("  FAIL  " + name + (detail ? "\n        " + detail : "")); }
  else console.log("  ok    " + name);
}

const enc = new TextEncoder();

// --- a fake FileSystemEntry tree, as a drop delivers it -------------------
// webkitGetAsEntry() returns a FileSystemFileEntry / FileSystemDirectoryEntry;
// a directory's createReader() hands entries over in batches and then an empty
// batch signals the end -- the walk must respect both.
function entryFromTree(node, fullPath, mtime) {
  if (typeof node === "string") {
    const bytes = enc.encode(node);
    return {
      isFile: true, isDirectory: false,
      name: fullPath.split("/").pop(),
      file: (cb) => cb({
        name: fullPath.split("/").pop(),
        size: bytes.length,
        lastModified: mtime,
        webkitRelativePath: "",
        arrayBuffer: async () => bytes.buffer,
      }),
    };
  }
  const names = Object.keys(node);
  return {
    isFile: false, isDirectory: true,
    name: fullPath ? fullPath.split("/").pop() : "",
    createReader() {
      let i = 0;
      return {
        // One entry per batch, and an empty batch at the end: the walk must
        // keep reading until the empty one arrives.
        readEntries(cb) {
          if (i >= names.length) { cb([]); return; }
          const chunk = [entryFromTree(node[names[i]],
                          fullPath ? `${fullPath}/${names[i]}` : names[i], mtime)];
          i += 1;
          cb(chunk);
        },
      };
    },
  };
}

const TREE = {
  server1: { "slapd_2.6.log": "2026-10-18T08:00:00.000000001Z host1 slapd[1]: conn=1 fd=5 ACCEPT from IP=10.0.0.1:5000 (IP=0.0.0.0:389)\n" },
  server2: { "slapd_2.6.log": "2026-10-18T08:00:01.000000001Z host2 slapd[2]: conn=1 fd=5 ACCEPT from IP=10.0.0.2:5000 (IP=0.0.0.0:389)\n" },
  server3: { "slapd_2.6.log": "2026-10-18T08:00:02.000000001Z host3 slapd[3]: conn=1 fd=5 ACCEPT from IP=10.0.0.3:5000 (IP=0.0.0.0:389)\n" },
};

// Every file in this tree has the SAME size and the SAME mtime, so only the
// path can tell them apart.
function dropFolder(tree, { asItems = true } = {}) {
  const ev = new window.Event("drop", { bubbles: true });
  const root = entryFromTree(tree, "", 1750000000000);
  ev.dataTransfer = asItems
    ? { items: [{ kind: "file", webkitGetAsEntry: () => root }], files: [] }
    : { files: [] };   // no item list at all -> nothing to walk
  $("drop").dispatchEvent(ev);
  return ev;
}

function dropFlat(list) {
  const ev = new window.Event("drop", { bubbles: true });
  ev.dataTransfer = {
    items: list.map((f) => ({ kind: "file", webkitGetAsEntry: () => entryFromTree(f.text, f.path, f.mtime) })),
    files: list.map((f) => ({ name: f.path, size: enc.encode(f.text).length, lastModified: f.mtime })),
  };
  $("drop").dispatchEvent(ev);
}

(async () => {
  await sleep(120);
  console.log("folder selection in the WASM page");

  // --- 1..3, 5: a dropped folder tree ---------------------------------
  dropFolder(TREE);
  await sleep(80);
  const got = paths();
  check("a dropped folder is walked into every file",
        got.length === 3, JSON.stringify(got));
  check("each file keeps its path inside the selection",
        got.join(",") === "server1/slapd_2.6.log,server2/slapd_2.6.log,server3/slapd_2.6.log",
        JSON.stringify(got));
  check("same name + same size + same mtime -> all three survive",
        doc.querySelectorAll("#filelist .fdel").length === 3,
        "distinct entries: " + got.length);
  check("the total row counts them",
        /3 files/.test($("filelist").textContent) &&
        /^3 file\(s\) ready/.test($("status").textContent),
        $("status").textContent);

  // --- 4: idempotent ---------------------------------------------------
  dropFolder(TREE);
  await sleep(60);
  check("re-adding the same folder does not duplicate it",
        paths().length === 3, JSON.stringify(paths()));

  // --- 6: no cap — every file keeps its own remove button ---------------
  const big = { logs: {} };
  for (let i = 1; i <= 30; i++) big.logs["server" + String(i).padStart(2, "0")] = { "slapd_2.6.log": "x\n" };
  dropFolder(big);
  await sleep(80);
  check("a big folder is listed whole, not summarised",
        rows().length === 33 && doc.querySelectorAll("#filelist .f.more").length === 0,
        "rows=" + rows().length);
  check("every one of them can be removed",
        doc.querySelectorAll("#filelist .fdel").length === 33,
        doc.querySelectorAll("#filelist .fdel").length + " button(s)");

  // Removing one file by mistake must be possible, and must remove exactly it.
  const target = rows()[12];
  const targetPath = target.querySelector(".fpath").textContent;
  target.querySelector(".fdel").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(60);
  const left = paths();
  check("the remove button takes out that one file",
        left.length === 32 && !left.includes(targetPath) &&
        left.includes(targetPath.replace(/13/, "14")),
        targetPath + " -> " + left.length + " left");
  check("the total follows the removal",
        /32 files/.test($("filelist").textContent) && /^32 file\(s\) ready/.test($("status").textContent),
        $("status").textContent);
  check("the rows scroll rather than being cut off",
        /#filelist \.frows \{[^}]*max-height/.test(html) &&
        /#filelist \.frows \{[^}]*overflow-y:\s*auto/.test(html));
  $("clear").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(20);

  // --- 6b: more files than fit on screen --------------------------------
  const huge = { logs: {} };
  for (let i = 1; i <= 250; i++) huge.logs["h" + String(i).padStart(3, "0")] = { "slapd_2.6.log": "x\n" };
  dropFolder(huge);
  await sleep(120);
  check("a selection larger than the box is listed whole, not cut off",
        rows().length === 250 && doc.querySelectorAll("#filelist .fdel").length === 250 &&
        doc.querySelectorAll("#filelist .f.more").length === 0,
        rows().length + " rows, " + doc.querySelectorAll("#filelist .fdel").length + " buttons");
  $("clear").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(20);

  // --- 7: the pickers ---------------------------------------------------
  created.length = 0;
  $("pick-folder").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  const dirInput = created[created.length - 1];
  check("“Add a folder…” builds an input with webkitdirectory",
        created.length === 1 && dirInput.webkitdirectory === true &&
        dirInput.getAttribute("directory") === "" && dirInput.multiple === true,
        "inputs=" + created.length);
  created.length = 0;
  $("pick-files").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  const fileInput = created[created.length - 1];
  check("“Choose files…” builds a plain multiple input",
        created.length === 1 && !fileInput.webkitdirectory && fileInput.multiple === true,
        "inputs=" + created.length);
  created.length = 0;
  $("drop").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  check("clicking the zone still opens the file picker (one input, no cascade)",
        created.length === 1, "inputs=" + created.length);

  // --- flat drops of a single file still work (no path) -----------------
  dropFlat([{ path: "access.log", text: "one\n", mtime: 1 }]);
  await sleep(40);
  check("a plain file drop is still listed by its name",
        paths().join(",") === "access.log", JSON.stringify(paths()));

  // --- no item list (older browsers) -> dt.files fallback ---------------
  $("clear").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await sleep(20);
  dropFolder(TREE, { asItems: false });
  await sleep(40);
  check("a drop with no .items is ignored, not crashed on",
        paths().length === 0, JSON.stringify(paths()));

  console.log("");
  console.log(`  ${failures} failure(s) / ${checks} checks`);
  process.exit(failures ? 1 : 0);
})();
