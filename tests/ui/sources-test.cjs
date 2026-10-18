#!/usr/bin/env node
const SL = require("../lib/env.cjs");
// sources-test.cjs — the log *source* features added with the four-part request:
// the server(s) the lines name, paged searches (RFC 2696), and the floating
// section index.
//
// The fixture is rfc3339-utc (a host on every line) plus one debug-format line
// (no host), so the server set must come out as exactly the two hosts and must
// not be padded with a name for the debug line.
//
//   hostA  BIND cn=other ... RESULT          (only so the log names two servers)
//   hostB  BIND cn=admin ... RESULT
//   hostB  => get_ctrls paged (critical)   -> SRCH  (page 1)
//   hostB  => get_ctrls 1.3.6.1.4.1.4203.1.10.1 (noncritical) -> SRCH
//   hostB  => get_ctrls paged (critical)   -> SRCH  (page 2)
//
// Two paged controls, both on hostB's conn=1, which bound cn=admin — so the
// count is 2 and it belongs to that DN.  The other control must not be counted.
// hostA also uses conn=1: a connection's identity is (server, conn), so the two
// must not be merged (which is what would hand hostB's searches hostA's DN).
const fs = require("fs");
const { execFileSync } = require("child_process");
const { JSDOM } = require("../lib/env.cjs").loadJsdom();

const SLA = "" + SL.ROOT + "/slaplog";
const LOG = SL.SCRATCH + "/sources.log";
// rfc3339-utc header: <timestamp> <host> slapd[<pid>]: <payload>.  The pid doubles
// as the fractional-second suffix, so every line has a distinct timestamp.
const L = (host, pid, payload) =>
  `2026-10-16T16:16:19.500000${String(pid).padStart(3, "0")}Z ${host} slapd[${pid}]: ${payload}`;

const lines = [
  L("hostA.example.com", 1, 'conn=1 op=0 BIND dn="cn=other,dc=example,dc=com" method=128'),
  L("hostA.example.com", 2, "conn=1 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text="),
  L("hostB.example.com", 3, 'conn=1 op=0 BIND dn="cn=admin,dc=example,dc=com" method=128'),
  L("hostB.example.com", 4, "conn=1 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text="),
  L("hostB.example.com", 5, '=> get_ctrls: oid="1.2.840.113556.1.4.319" (critical)'),
  L("hostB.example.com", 6, 'conn=1 op=1 SRCH base="dc=example,dc=com" scope=2 deref=0 filter="(objectClass=*)"'),
  L("hostB.example.com", 7, "conn=1 op=1 SEARCH RESULT tag=101 err=0 qtime=0 etime=1 nentries=1000 text="),
  L("hostB.example.com", 8, '=> get_ctrls: oid="1.3.6.1.4.1.4203.1.10.1" (noncritical)'),
  L("hostB.example.com", 9, 'conn=1 op=2 SRCH base="dc=example,dc=com" scope=2 deref=0 filter="(uid=a)"'),
  L("hostB.example.com", 10, "conn=1 op=2 SEARCH RESULT tag=101 err=0 qtime=0 etime=1 nentries=1 text="),
  L("hostB.example.com", 11, '=> get_ctrls: oid="1.2.840.113556.1.4.319" (critical)'),
  L("hostB.example.com", 12, 'conn=1 op=3 SRCH base="dc=example,dc=com" scope=2 deref=0 filter="(uid=b)"'),
  L("hostB.example.com", 13, "conn=1 op=3 SEARCH RESULT tag=101 err=0 qtime=0 etime=1 nentries=500 text="),
  // debug format: no host, so it must not add a third server
  '6a734745.00000001 0x7f9c1e33a700 conn=9 op=0 BIND dn="cn=x,dc=y" method=128',
].join("\n") + "\n";
fs.writeFileSync(LOG, lines);

let failures = 0, checks = 0;
function check(name, ok, detail) {
  checks++;
  if (!ok) { failures++; console.log("  FAIL  " + name + (detail ? "\n        " + detail : "")); }
  else console.log("  ok    " + name);
}
const run = (args) => execFileSync(SLA, args, { encoding: "utf8", maxBuffer: 1 << 28 });

console.log("log sources + paged searches");

// ----------------------------------------------------------------- JSON
const json = JSON.parse(run(["-o", "json", "-q", LOG]));
check("JSON: the two hosts are the source, no name for the debug line",
      JSON.stringify(json.servers) === JSON.stringify(["hostA.example.com", "hostB.example.com"]),
      JSON.stringify(json.servers));
check("JSON: two paged controls counted, the other control ignored",
      json.paged_search_count === 2, String(json.paged_search_count));
check("JSON: the paged searches belong to the binding identity",
      JSON.stringify(json.paged_search_by_app) ===
        JSON.stringify({ "cn=admin,dc=example,dc=com": 2 }),
      JSON.stringify(json.paged_search_by_app));

// --------------------------------------------- cluster aggregation + binds
// hostA's conn=1 and hostB's conn=1 are two connections: without the server in
// the key, hostB's searches would have been handed hostA's binding identity.
const lb = json.load_by_server || {};
check("cluster: the load splits per server",
      lb["hostA.example.com"] && lb["hostA.example.com"].operations === 1 &&
      lb["hostB.example.com"] && lb["hostB.example.com"].operations === 4,
      JSON.stringify(lb));

const bu = json.bind_usage || {};
check("bind: the method and the transport are counted",
      bu.total === 3 && bu.by_method && bu.by_method.simple === 3 &&
      bu.by_transport && bu.by_transport.ldap === 3,
      JSON.stringify(bu));

// ----------------------------------------------------------------- HTML
const html = run(["-o", "html", "-q", LOG]);
check("HTML: the meta bar names the servers",
      /meta-label">Servers<\/div><div class="meta-value" title="hostA\.example\.com, hostB\.example\.com">2 servers/.test(html),
      (html.match(/meta-label">Servers[^]*?<\/div>/) || [""])[0].slice(0, 200));
check("HTML: the Statistics table lists the servers",
      /<td class="sl-stat-l">Server\(s\)<\/td><td>hostA\.example\.com, hostB\.example\.com<\/td>/.test(html));
check("HTML: the paged section names the identity and the count",
      html.includes('<h2 id="sec-paged">Paged Searches</h2>') &&
      /<tr><td>cn=admin,dc=example,dc=com<\/td><td>2<\/td><\/tr>/.test(html));
check("HTML: the paged section explains how it is detected",
      /at loglevel <code>trace<\/code>/.test(html) && /by shape/.test(html));
check("HTML: every section heading carries an id",
      (html.match(/<h2 id="sec-/g) || []).length > 10,
      String((html.match(/<h2 id="sec-/g) || []).length));
check("HTML: Load by Server is drawn when the log names two servers",
      /<h2 id="sec-load">Load by Server<\/h2>/.test(html));

// ----------------------------------------------------------------- text
const text = run(["-o", "text", "-q", LOG]);
check("text: the Statistics table lists the servers",
      text.includes("| Server(s)               | hostA.example.com, hostB.example.com |"));
check("text: the Paged Searches section is present",
      text.includes("Paged Searches") && text.includes("cn=admin,dc=example,dc=com"));

// ------------------------------------------- the shape heuristic (no trace)
// Without the trace-level control line, a paged search is recognised by its
// shape: on one connection, the same request repeated, every page returning the
// same count until the last, which is smaller.  This fixture has three
// connections:
//   conn=1  1000, 1000, 500  -> paged, 3 pages
//   conn=2      1,     1     -> equal counts, no end marker: not paged
//   conn=3    250            -> a single search: not paged
const HLOG = SL.SCRATCH + "/paged-heur.log";
const hl = (host, pid, payload) =>
  `2026-10-16T16:16:19.500000${String(pid).padStart(3, "0")}Z ${host} slapd[1]: ${payload}`;
const hr = (conn, op, n) =>
  [hl("hostA", op * 10 + 1, `conn=${conn} op=${op} SRCH base="dc=example,dc=com" scope=2 deref=0 filter="(objectClass=*)"`),
   hl("hostA", op * 10 + 2, `conn=${conn} op=${op} SEARCH RESULT tag=101 err=0 qtime=0 etime=1 nentries=${n} text=`)].join("\n");
const hlines = [
  hl("hostA", 1, 'conn=1 op=0 BIND dn="cn=admin,dc=example,dc=com" method=128'),
  hl("hostA", 2, "conn=1 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text="),
  ...[1, 2, 3].flatMap((op) => hr(1, op, op === 3 ? 500 : 1000).split("\n")),
  hl("hostA", 40, 'conn=2 op=0 BIND dn="cn=probe,dc=example,dc=com" method=128'),
  hl("hostA", 41, "conn=2 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text="),
  ...[1, 2].flatMap((op) => hr(2, op, 1).split("\n")),
  hl("hostA", 50, 'conn=3 op=0 BIND dn="cn=full,dc=example,dc=com" method=128'),
  hl("hostA", 51, "conn=3 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text="),
  ...[1].flatMap((op) => hr(3, op, 250).split("\n")),
  hl("hostA", 60, "conn=1 fd=1 closed"),
  hl("hostA", 61, "conn=2 fd=2 closed"),
  hl("hostA", 62, "conn=3 fd=3 closed"),
].join("\n") + "\n";
fs.writeFileSync(HLOG, hlines);
const hjson = JSON.parse(run(["-o", "json", "-q", HLOG]));
check("heuristic: a run of same-parameter searches ending smaller is paged",
      hjson.paged_search_count === 3 &&
      JSON.stringify(hjson.paged_search_by_app) ===
        JSON.stringify({ "cn=admin,dc=example,dc=com": 3 }),
      `count=${hjson.paged_search_count} ${JSON.stringify(hjson.paged_search_by_app)}`);
check("heuristic: equal counts with no end marker is not paged (conn=2)",
      hjson.paged_search_by_app["cn=probe,dc=example,dc=com"] === undefined);
check("heuristic: a single search is not paged (conn=3)",
      hjson.paged_search_by_app["cn=full,dc=example,dc=com"] === undefined);

// --------------------------------------------------- bind usage (transport)
// The transport is what the connection was doing when the bind ran:
//   conn=1  TLS established, no STARTTLS  -> ldaps
//   conn=2  STARTTLS then TLS established -> ldap + StartTLS
//   conn=3  nothing                       -> ldap (and an empty DN -> anonymous)
//   conn=4  method=163 + mech=EXTERNAL    -> SASL
const BLOG = SL.SCRATCH + "/bind-usage.log";
const blines = [
  // ldaps: implicit TLS, handshake before the bind
  L("hostA", 1, "conn=1 fd=1 TLS established tls_ssf=256 ssf=256 tls_proto=TLSv1.3"),
  L("hostA", 2, 'conn=1 op=0 BIND dn="cn=tls,dc=example,dc=com" method=128'),
  L("hostA", 3, "conn=1 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text="),
  // ldap + StartTLS: the handshake follows the STARTTLS operation
  L("hostA", 4, "conn=2 fd=2 ACCEPT from IP=10.0.0.2:1 (IP=0.0.0.0:389)"),
  L("hostA", 5, "conn=2 op=0 EXT oid=1.3.6.1.4.1.1466.20037"),
  L("hostA", 6, "conn=2 op=0 STARTTLS"),
  L("hostA", 7, "conn=2 op=0 RESULT oid= err=0 qtime=0 etime=1 text="),
  L("hostA", 8, "conn=2 fd=2 TLS established tls_ssf=256 ssf=256 tls_proto=TLSv1.3"),
  L("hostA", 9, 'conn=2 op=1 BIND dn="cn=starttls,dc=example,dc=com" method=128'),
  L("hostA", 10, "conn=2 op=1 RESULT tag=97 err=0 qtime=0 etime=1 text="),
  // plain ldap, anonymous simple bind (empty DN)
  L("hostA", 11, 'conn=3 op=0 BIND dn="" method=128'),
  L("hostA", 12, "conn=3 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text="),
  // SASL: method 163 on the request, the mechanism on the success line
  L("hostA", 13, 'conn=4 op=0 BIND dn="" method=163'),
  L("hostA", 14, 'conn=4 op=0 BIND dn="cn=sasl,dc=example,dc=com" mech=EXTERNAL bind_ssf=0 ssf=256'),
  L("hostA", 15, "conn=4 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text="),
].join("\n") + "\n";
fs.writeFileSync(BLOG, blines);
const bjson = JSON.parse(run(["-o", "json", "-q", BLOG]));
const bju = bjson.bind_usage || {};
check("bind: ldaps / ldap + StartTLS / ldap are told apart",
      JSON.stringify(bju.by_transport) ===
        JSON.stringify({ "ldap": 2, "ldap + StartTLS": 1, "ldaps": 1 }),
      JSON.stringify(bju.by_transport));
check("bind: an empty DN on a simple bind is anonymous",
      bju.by_method && bju.by_method.simple === 2 && bju.by_method.anonymous === 1 &&
      bju.by_method.SASL === 1,
      JSON.stringify(bju.by_method));
check("bind: the SASL mechanism is named, SIMPLE is not",
      JSON.stringify(bju.by_mechanism) === JSON.stringify({ EXTERNAL: 1 }),
      JSON.stringify(bju.by_mechanism));
const bhtml = run(["-o", "html", "-q", BLOG]);
check("HTML: the Bind Usage section is drawn",
      /<h2 id="sec-bind">Bind Usage<\/h2>/.test(bhtml) &&
      /Authentication method/.test(bhtml) && /Transport/.test(bhtml));
check("HTML: no Load by Server section for a single-server log",
      !/<h2 id="sec-load">/.test(bhtml));

// A host-less (debug) log describes one server and cannot be split: no server
// set, and no Load by Server section (which would have one unnamed row).
const DLOG = SL.SCRATCH + "/debug-only.log";
fs.writeFileSync(DLOG,
  '6a734745.00000001 0x7f9c1e33a700 conn=1 op=0 BIND dn="cn=x,dc=y" method=128\n' +
  "6a734745.00000002 0x7f9c1e33a700 conn=1 op=0 RESULT tag=97 err=0 qtime=0 etime=1 text=\n");
const djson = JSON.parse(run(["-o", "json", "-q", DLOG]));
check("cluster: a host-less debug log has no per-server split",
      djson.servers === undefined && djson.load_by_server === undefined,
      JSON.stringify({ servers: djson.servers, load: djson.load_by_server }));
check("HTML: the Load by Server section is absent for a host-less log",
      !/<h2 id="sec-load">/.test(run(["-o", "html", "-q", DLOG])));

// ----------------------------------------------------------------- index
const dom = new JSDOM(html, { runScripts: "dangerously", pretendToBeVisual: true });
const d = dom.window.document;
const hs = [...d.querySelectorAll("h2[id]")];
const links = [...d.querySelectorAll(".sl-index-list a")];
check("index: one link per section, all pointing at a real heading",
      hs.length > 0 && links.length === hs.length &&
      links.every((a) => d.getElementById(a.getAttribute("href").slice(1))),
      `${links.length} link(s) / ${hs.length} heading(s)`);

// The index is a window on the section being read: it opens with the report,
// then tucks itself into three lines (the section being read and its
// neighbours) and opens again when the pointer comes near.  The behaviour —
// proximity, hysteresis, pinning, and where the window sits — is exercised by
// index-test.cjs, which installs a fake layout; jsdom here has no layout at all,
// so this checks the structure and the static contract only.
const idx = d.querySelector(".sl-index");
check("index: it opens with the report", idx && idx.classList.contains("open"));
check("index: one list, two heights — never a hidden list",
      /\.sl-index-list \{ padding:6px 0; height:var\(--sl-win/.test(html) &&
      /\.sl-index\.open \.sl-index-list \{ height:var\(--sl-full/.test(html) &&
      !/\.sl-index-list \{ display:none/.test(html));
check("index: the change of height is animated",
      /\.sl-index-list \{[^}]*transition:height/.test(html));
check("index: the window is three rows and follows the section being read",
      /var WIN = 3;/.test(html) && /list\.scrollTop = rows\[start\]\.offsetTop/.test(html));
check("index: a caret shows the state",
      !!d.querySelector(".sl-index-head .sl-index-caret"));

console.log("\n" + failures + " failure(s) / " + checks + " checks");
process.exit(failures ? 1 : 0);
