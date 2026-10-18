#!/usr/bin/env node
const SL = require("../lib/env.cjs");
// doctest.cjs — the documentation pair must stay byte-identical.
//
// embedded.hpp used to be a hand-maintained twin of doc/slaplog.md and the two
// drifted 131 lines apart.  It is generated now, so this harness asserts the
// whole chain end to end:
//
//   LICENSE + doc/slaplog.md  --(tools/gen_embedded.py)-->  embedded.hpp  -->  -l / -D
//
// Any of those links breaking means `./slaplog -D` no longer tells what
// doc/slaplog.md says, which the README advertises as the same thing.

const { execFileSync, execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = "" + SL.ROOT + "";
let checks = 0;
let failures = 0;

function check(name, condition, detail) {
  checks++;
  if (condition) {
    console.log(`  ok   ${name}`);
  } else {
    failures++;
    console.log(`  FAIL ${name}${detail ? " — " + detail : ""}`);
  }
}

function run(file, args) {
  return execFileSync(file, args, { cwd: ROOT, encoding: "utf8", maxBuffer: 1 << 28 });
}

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), "utf8");
}

const doc = read("doc/slaplog.md");
const license = read("LICENSE");
const embedded = read("embedded.hpp");
const template = read("tools/embedded.hpp.in");

// ---------------------------------------------------------------- sources
console.log("sources");
check("LICENSE ends with a newline (a literal must not end mid-line)",
  license.endsWith("\n") && !license.endsWith("\n\n"));
check("doc/slaplog.md ends with a newline", doc.endsWith("\n"));
check("the template holds exactly one @LICENSE@ token",
  (template.match(/@LICENSE@/g) || []).length === 1);
check("the template holds exactly one @DOC@ token",
  (template.match(/@DOC@/g) || []).length === 1);
check("embedded.hpp is flagged as generated",
  /GENERATED FILE/.test(embedded) && embedded.includes("tools/gen_embedded.py"));

// ------------------------------------------------- should the generator run?
console.log("generator");
let checkRc = 0;
let checkOut = "";
try {
  checkOut = run("tools/gen_embedded.py", ["--check"]);
} catch (e) {
  checkRc = e.status;
  checkOut = (e.stdout || "") + (e.stderr || "");
}
check("tools/gen_embedded.py --check succeeds", checkRc === 0,
  `rc=${checkRc} ${checkOut.trim()}`);

// ------------------------------------------ binary output == the source files
console.log("binary vs sources");
const outD = run(path.join(ROOT, "slaplog"), ["-D"]);
const outL = run(path.join(ROOT, "slaplog"), ["-l"]);
check("`slaplog -D` is byte-identical to doc/slaplog.md", outD === doc,
  `-D=${outD.length} bytes, doc=${Buffer.byteLength(doc)} bytes`);
check("`slaplog -l` is byte-identical to LICENSE", outL === license,
  `-l=${outL.length} bytes, LICENSE=${Buffer.byteLength(license)} bytes`);

// --------------------------------------------------- the sources are coherent
console.log("coherence");
const versionHpp = (read("version.hpp").match(/#define SLAPLOG_VERSION "([^"]+)"/) || [])[1];
const docVersion = (doc.match(/\*\*Version:\*\*\s*(\S+)/) || [])[1];
check("doc/slaplog.md advertises the version from version.hpp",
  versionHpp && docVersion === versionHpp, `doc=${docVersion} version.hpp=${versionHpp}`);
check("the doc documents the generated embedded.hpp",
  /### `embedded\.hpp`/.test(doc) && /make check-doc/.test(doc));
check("the doc documents version.hpp", /### `version\.hpp`/.test(doc));
check("the doc keeps the recovered replay entry point",
  doc.includes("print_replay_report") && doc.includes("jmeter_replay.csv"));
check("the doc uses the LDAP Result Codes wording",
  doc.includes("LDAP Result Codes") && !/^### Error Counts/m.test(doc));

console.log("");
console.log(`  ${failures} failure(s) / ${checks} checks`);
process.exit(failures === 0 ? 0 : 1);
