#!/usr/bin/env node
const SL = require("../lib/env.cjs");
// index-test.cjs — the floating section index of the HTML report.
//
// What the reader asked for: the index opens with the report, then tucks itself
// away into a three-line window on the section being read — the one before, the
// one read, the one after — and opens again when the pointer comes near.
//
// jsdom has no layout engine — every rect is zero and every offset is zero — so
// this test installs a fake layout on the prototype BEFORE the report's script
// runs (so the very first measurement already sees it), and then drives the real
// code with real events.  The geometry is the real one of a 1300px-wide window:
// the box is anchored top-right (right:12px, top:12px), 260px wide, one 28px
// heading plus a list whose rows are 22px each.
//
// Checked: open at load and not cut short by a far pointer while it is; tucked
// away after the opening view when no pointer is near; opened by approach from
// the left / from below / from inside the closed box; the hysteresis (it does
// not close at the distance that opened it); closed again further away; a click
// pins it open and a second click releases it; leaving the window closes it; the
// window sizes itself to three rows; and the window follows the section being
// read, while an *open* list is left to the reader's own scrolling.
const fs = require("fs");
const { execFileSync } = require("child_process");
const { JSDOM } = require("../lib/env.cjs").loadJsdom();

const SLA = "" + SL.ROOT + "/slaplog";
const LOG = SL.SCRATCH + "/index-test.log";

// A small log with a real bind, a search and an error, so the report draws
// several sections (hence several h2[id]) and the index is built.
let t = 0;
const L = (payload) =>
  `2026-10-18T08:00:${String(t++).padStart(2, "0")}.000000001Z host1 slapd[1]: ${payload}\n`;
fs.writeFileSync(LOG, [
  L('conn=1 op=0 BIND dn="cn=admin,dc=example,dc=com" method=128'),
  L("conn=1 op=0 RESULT tag=97 err=0 qtime=0.000008 etime=0.001 text="),
  L('conn=1 op=1 SRCH base="dc=example,dc=com" scope=2 deref=3 filter="(uid=a)"'),
  L("conn=1 op=1 SEARCH RESULT tag=101 err=0 qtime=0.00001 etime=0.002 nentries=1 text="),
  L('conn=2 op=0 SRCH base="ou=People,dc=example,dc=com" scope=2 deref=3 filter="(uid=b)"'),
  L("conn=2 op=0 SEARCH RESULT tag=101 err=32 qtime=0.00001 etime=0.003 nentries=0 text=No such object"),
  L("conn=2 fd=6 closed"),
].join(""));

const html = execFileSync(SLA, ["-o", "html", "-q", LOG], { encoding: "utf8", maxBuffer: 1 << 28 });

// --- the fake layout ------------------------------------------------------
const HEAD_H = 28, ROW_H = 22, ROWS = 19, PAD = 12;
const rect = (l, t_, r, b) => ({
  left: l, top: t_, right: r, bottom: b, x: l, y: t_,
  width: r - l, height: b - t_, toJSON() { return this; },
});
const HEAD = rect(1028, 12, 1288, 12 + HEAD_H);            // the heading alone
const box_h = HEAD_H + (ROW_H * 3 + PAD);                  // heading + three rows
const CLOSED = rect(1028, 12, 1288, 12 + box_h);
const OPEN = rect(1028, 12, 1288, 12 + HEAD_H + ROW_H * ROWS + PAD);
const H2_TOP = (i) => i * 200;                             // 200px per section

const rowIndex = (el) => Array.prototype.indexOf.call(el.parentNode.children, el);
const cls = (el) => (el.classList ? el.classList : { contains: () => false });

let failures = 0, checks = 0;
function check(name, ok, detail) {
  checks++;
  if (!ok) { failures++; console.log("  FAIL  " + name + (detail ? "\n        " + detail : "")); }
  else console.log("  ok    " + name);
}

// The page scroll position the fake headings are laid out against.
let scrollY = 0;
const h2ids = [...html.matchAll(/<h2 id="([^"]+)"/g)].map((m) => m[1]);

const dom = new JSDOM(html, {
  runScripts: "dangerously",
  pretendToBeVisual: true,
  beforeParse(window) {
    const E = window.Element.prototype;
    E.getBoundingClientRect = function () {
      const c = cls(this);
      if (this.tagName === "H2") {
        const top = H2_TOP(h2ids.indexOf(this.id)) - scrollY;
        return rect(0, top, 800, top + 30);
      }
      if (c.contains("sl-index-head")) return HEAD;
      if (c.contains("sl-index")) return c.contains("open") ? OPEN : CLOSED;
      return rect(0, 0, 0, 0);
    };
    // offsets and the scrollable height, so the window can be computed
    // (offsetHeight/offsetTop live on HTMLElement.prototype, not Element's)
    const H = window.HTMLElement.prototype;
    Object.defineProperty(H, "offsetHeight", {
      configurable: true,
      get() {
        if (cls(this).contains("sl-index-head")) return HEAD_H;
        if (cls(this).contains("sl-index-list")) return ROW_H * ROWS + PAD;
        if (this.tagName === "A") return ROW_H;
        return 0;
      },
    });
    Object.defineProperty(H, "offsetTop", {
      configurable: true,
      get() {
        if (this.tagName === "A") return 12 + HEAD_H + PAD / 2 + ROW_H * rowIndex(this);
        return 0;
      },
    });
    Object.defineProperty(E, "scrollHeight", {
      configurable: true,
      get() {
        return cls(this).contains("sl-index-list") ? ROW_H * ROWS + PAD : 0;
      },
    });
  },
});

const { window } = dom;
const doc = window.document;
const idx = doc.querySelector(".sl-index");
const head = doc.querySelector(".sl-index-head");
const list = doc.querySelector(".sl-index-list");
const rows = [...doc.querySelectorAll(".sl-index-list a")];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function move(x, y) {
  doc.dispatchEvent(new window.MouseEvent("mousemove", { clientX: x, clientY: y, bubbles: true }));
}
function clickHead() {
  head.dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
}
function pageScroll(y) {
  scrollY = y;
  window.dispatchEvent(new window.Event("scroll"));
}
const isOpen = () => idx.classList.contains("open");
const activeIndex = () => rows.findIndex((a) => a.classList.contains("active"));
const varOf = (name) => parseInt(idx.style.getPropertyValue(name), 10);

(async () => {
  await sleep(120);
  console.log("floating section index");

  check("the index was built from the h2 headings",
        !!idx && rows.length === doc.querySelectorAll("h2[id]").length,
        rows.length + " link(s)");

  // --- it opens with the report -------------------------------------------
  check("open at load, before the pointer moves", isOpen());
  check("the caret is there", !!doc.querySelector(".sl-index-caret"));
  check("the window is three rows plus the list's own padding",
        varOf("--sl-win") === ROW_H * 3 + PAD, "--sl-win = " + varOf("--sl-win"));
  check("opened, it is as tall as the whole list",
        varOf("--sl-full") === ROW_H * ROWS + PAD, "--sl-full = " + varOf("--sl-full"));
  check("the window starts at the first section at the top of the page",
        list.scrollTop === 0 && activeIndex() === 0,
        "scrollTop " + list.scrollTop + ", active " + activeIndex());

  // The opening view is the reader's to look at: a pointer that merely happens
  // to be far away before the timer is not allowed to cut it short.
  move(300, 900);
  await sleep(60);
  check("the opening view is not cut short by a far pointer", isOpen());

  await sleep(3300);                  // the opening view is 3s
  check("no pointer near once it is over: it tucks itself away", !isOpen());

  // --- approach from the left --------------------------------------------
  move(990, 26);            // 38px left of the box (NEAR = 48): opens
  await sleep(40);
  check("40px to the left: opens", isOpen());

  // --- hysteresis: it must not close at the distance that opened it -------
  move(950, 26);            // 78px out: beyond NEAR, inside KEEP = 110
  await sleep(40);
  check("80px out: stays open (hysteresis, no flapping)", isOpen());

  move(880, 26);            // 148px out: beyond KEEP, closes
  await sleep(40);
  check("150px out: closes again", !isOpen());

  // --- from below, then inside the opened list ----------------------------
  move(1240, 70);           // 30px under the heading: inside the closed box
  await sleep(40);
  check("approaching from below opens it too", isOpen());

  move(1060, 300);          // inside the opened list
  await sleep(40);
  check("moving into the opened list keeps it open", isOpen());

  move(300, 300);           // away
  await sleep(40);
  check("moving away closes it", !isOpen());

  // --- the corner itself --------------------------------------------------
  move(1284, 20);
  await sleep(40);
  check("the corner itself opens it", isOpen());
  move(300, 900);
  await sleep(40);
  check("and it closes when the pointer leaves", !isOpen());

  // --- pinning ------------------------------------------------------------
  clickHead();
  await sleep(30);
  check("a click pins it open", isOpen());
  move(300, 900);
  await sleep(40);
  check("pinned: moving away no longer closes it", isOpen());
  clickHead();
  await sleep(30);
  check("a second click releases and closes it", !isOpen());

  // --- leaving the window -------------------------------------------------
  move(1240, 26);
  await sleep(40);
  check("open again by approach", isOpen());
  doc.dispatchEvent(new window.Event("mouseleave"));
  await sleep(40);
  check("leaving the window closes it", !isOpen());

  // --- the window follows the section being read --------------------------
  // One list, two heights: closed, it is clipped and scrolled onto the active
  // row, so those three lines are the ones in view.
  check("closed at the top of the page: the window is on the first section",
        list.scrollTop === 0 && activeIndex() === 0,
        "scrollTop " + list.scrollTop + ", active " + activeIndex());

  pageScroll(1000);         // the 6th heading has passed the line (i*200 <= 1100)
  await sleep(60);
  check("the section being read is the active row", activeIndex() === 5,
        "active " + activeIndex());
  check("the window scrolled onto it, the previous row on top",
        list.scrollTop === ROW_H * 4, "scrollTop " + list.scrollTop);

  pageScroll(100000);       // the last heading
  await sleep(60);
  check("at the end of the report the window is clamped to the last rows",
        activeIndex() === ROWS - 1 && list.scrollTop === ROW_H * (ROWS - 3),
        "active " + activeIndex() + ", scrollTop " + list.scrollTop);

  // Open, the list is the reader's: the window must not fight his scrolling.
  move(990, 26);
  await sleep(40);
  list.scrollTop = 200;
  pageScroll(0);
  await sleep(60);
  check("open, the window leaves the reader's own scrolling alone",
        list.scrollTop === 200, "scrollTop " + list.scrollTop);

  move(300, 900);           // closes, and puts the window back on the section
  await sleep(60);
  check("closing puts the window back on the section being read",
        !isOpen() && list.scrollTop === 0, "scrollTop " + list.scrollTop);

  console.log("");
  console.log(`  ${failures} failure(s) / ${checks} checks`);
  process.exit(failures ? 1 : 0);
})();
