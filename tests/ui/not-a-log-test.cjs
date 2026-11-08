// tests/ui/not-a-log-test.cjs — the WASM session refuses a non-log input.
//
// Mirrors tests/native/not-a-log.sh for the browser engine:
//   - slaplog_run() on an LDIF export fails with a clear message and no report;
//   - a plain-text LDIF sent through the session API is refused at
//     slaplog_input_end() (return code 2) and leaves the aggregate untouched;
//   - a real log sent after a refused one produces exactly the report it
//     produces on its own.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
const fs = require("fs");
const path = require("path");
const SL = require("../lib/env.cjs");

const WEB = "" + SL.ROOT + "/wasm/web";
const createSlaplog = require(path.join(WEB, "slaplog.js"));
const MEM = "/work";

const LDIF = [
  "version: 1",
  "",
  "dn: cn=ldapcfmgr,dc=example,dc=com",
  "objectClass: person",
  "cn: ldapcfmgr",
  "sn: ldapcfmgr",
  "",
].join("\n");

let out = [];
let failures = 0;

function check(label, cond, detail) {
  if (cond) {
    console.log(`${label} OK`);
  } else {
    console.log(`${label} FAILED${detail ? " — " + detail : ""}`);
    failures++;
  }
}

const norm = (s) => s.split("\n")
  .filter((l) => !/Processing time|Processing speed|Generated|lines\/s/.test(l))
  .map((l) => l.replace(/("processing_time":\s*)[0-9.eE+-]+/, "$1X"))
  .join("\n");

function stage(module, name, text) {
  const vp = `${MEM}/${name}`;
  module.FS.writeFile(vp, new Uint8Array(Buffer.from(text, "utf8")));
  return vp;
}

function runOnce(module, opts, vpaths) {
  out = [];
  const rc = module.ccall("slaplog_run", "number", ["string"],
                          [opts + " " + vpaths.join(" ")]);
  return { rc, text: out.join("\n") };
}

function sendText(module, text) {
  const bytes = Buffer.from(text, "utf8");
  const ptr = module._malloc(bytes.length);
  try {
    module.HEAPU8.set(bytes, ptr);
    return module.ccall("slaplog_add_text", "number", ["number", "number"],
                        [ptr, bytes.length]);
  } finally {
    module._free(ptr);
  }
}

(async () => {
  const module = await createSlaplog({
    print: (l) => out.push(l),
    printErr: (l) => out.push(l),
    locateFile: (p) => path.join(WEB, p),
  });
  try { module.FS.mkdir(MEM); } catch (e) { /* already exists */ }

  // ----------------------------------------------------------------
  // 1. One-shot call on an LDIF export.
  // ----------------------------------------------------------------
  const ldifPath = stage(module, "export.ldif", LDIF);
  const once = runOnce(module, "-o text", [ldifPath]);
  check("one-shot: exit status is 1", once.rc === 1, `got ${once.rc}`);
  check("one-shot: says it is not a log",
        /no LDAP log file to analyse/.test(once.text), once.text.slice(0, 200));
  check("one-shot: no report emitted",
        !/LDAP Log Analysis Report/.test(once.text));

  // ----------------------------------------------------------------
  // 2. Session API, plain text: refused at input_end (code 2).
  // ----------------------------------------------------------------
  out = [];
  module.ccall("slaplog_begin", "number", ["string"], ["-o text"]);
  module.ccall("slaplog_input_begin", "number", [], []);
  const arc = sendText(module, LDIF);
  const irc = module.ccall("slaplog_input_end", "number", [], []);
  check("session: add_text keeps going", arc === 0, `got ${arc}`);
  check("session: input_end reports not-a-log", irc === 2, `got ${irc}`);
  module.ccall("slaplog_end", "number", [], []);

  // ----------------------------------------------------------------
  // 3. A refused input leaves no trace: the report matches a clean run.
  // ----------------------------------------------------------------
  const real = path.join(SL.FIXTURES, "logsmall", "a.log");
  const realMem = stage(module, "a.log", fs.readFileSync(real, "utf8"));
  const clean = runOnce(module, "-o text", [realMem]);

  out = [];
  module.ccall("slaplog_begin", "number", ["string"], ["-o text"]);
  module.ccall("slaplog_input_begin", "number", [], []);
  sendText(module, LDIF);
  module.ccall("slaplog_input_end", "number", [], []);   // refused, dropped
  module.ccall("slaplog_input_begin", "number", [], []);
  sendText(module, fs.readFileSync(real, "utf8"));
  module.ccall("slaplog_input_end", "number", [], []);
  const mixedRc = module.ccall("slaplog_end", "number", [], []);
  const mixed = out.join("\n");

  check("mixed: exit status is 0", mixedRc === 0, `got ${mixedRc}`);
  check("mixed: report is identical to the clean run",
        norm(mixed) === norm(clean.text),
        "reports differ");

  if (failures) {
    console.log(`\nnot-a-log(wasm): ${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log("\nnot-a-log(wasm): all OK");
})().catch((e) => { console.error(e); process.exit(1); });
