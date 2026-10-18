// tests/lib/env.cjs — single place that resolves every path a harness needs.
//
// The harnesses started life outside the repository, hard-wired to one
// developer's checkout and to fixtures under a tmpfs directory.  That
// made them impossible to run from a clean clone (and the fixtures vanished on
// every reboot).  Everything a harness needs is now derived from this file's
// own location, so `git clone && make test-ui` works anywhere.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const fs = require("fs");
const path = require("path");

// Repository root: this file lives in <root>/tests/lib/.
const ROOT = path.resolve(__dirname, "..", "..");

// Committed fixtures (tests/fixtures/) and the native binary.
const FIXTURES = path.join(ROOT, "tests", "fixtures");
const BIN = path.join(ROOT, "slaplog");

// The WebAssembly build output (gitignored; produced by `make wasm`).
const WASM_DIR = path.join(ROOT, "wasm", "web");
const WASM_JS = path.join(WASM_DIR, "slaplog.js");   // Emscripten loader
const PAGE = path.join(WASM_DIR, "index.html");      // the page under jsdom

// jsdom is a third-party dependency the UI harnesses need.  Prefer a local
// install (tests/node_modules, then the repo root); fall back to NODE_PATH so
// the tests can also run against a system install.
function loadJsdom() {
  const candidates = [
    path.join(ROOT, "tests", "node_modules", "jsdom"),
    path.join(ROOT, "node_modules", "jsdom"),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return require(c);
  }
  return require("jsdom");
}

// A scratch directory for the harnesses that generate their own inputs (a
// synthetic log they then parse).  Prefer tmpfs (/dev/shm) when writable, else
// the system temp dir.  Nothing a harness generates is written into the
// repository: the fixtures are read-only, the scratch is transient.
const os = require("os");
function makeScratch() {
  const base = fs.existsSync("/dev/shm") ? "/dev/shm" : os.tmpdir();
  return fs.mkdtempSync(path.join(base, "slaplog-test-"));
}
const SCRATCH = makeScratch();
process.on("exit", () => { try { fs.rmSync(SCRATCH, { recursive: true, force: true }); } catch { /* best effort */ } });

module.exports = { ROOT, FIXTURES, SCRATCH, BIN, WASM_DIR, WASM_JS, PAGE, loadJsdom };
