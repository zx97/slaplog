// html_chart.cpp

/* 
    SPDX-License-Identifier: AGPL-3.0-or-later
    GNU Affero General Public License v3.0 (https://www.gnu.org/licenses/agpl-3.0.txt)
    Copyright (c) 2026 Manuel FLURY
    All rights reserved.
    
    This file is part of slaplog - an OpenLDAP Log Analysis Tool.
    
    Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later).
    See the LICENSE file distributed with this work for full license text.
    
    THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
    AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


//
// Chart rendering for the HTML report.  See html_chart.hpp for the contract.
//
// Everything is emitted as inline SVG so the report stays a single,
// self-contained file: no external asset, no JavaScript library.  Interaction
// is limited to a tooltip that follows the mouse; it reads the value from the
// data-* attributes of whichever element is under the cursor, so no coordinate
// maths or scale duplication is needed on the JS side.
//
// Seven charts are produced.  Five are fed by aggregates collected during
// parsing only when graphs are requested (--no-graph turns them off); the two
// that draw plain counts (operation types, result codes) exist whatever the
// flag, so html_charts_available() tests the flag explicitly instead of relying
// on those aggregates being empty.
//
//   • simultaneous connections over time   (connection timeline)
//   • errors over time                     (error timestamps, failures only)
//   • response time distribution           (etime histogram)
//   • resource consumers by bind account   (per-account etime)
//   • operation types                      (operation_count)
//   • every result code, successes included(error_count — bars + cumulative)
//   • the failing ones only                (error_count — donut)

#include "html_chart.hpp"
#include "report.hpp"     // ldap_error_name(), ldap_code_class(), …_color()

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

// ---- small helpers --------------------------------------------------------

std::string xml_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '&':  o += "&amp;";  break;
            case '<':  o += "&lt;";   break;
            case '>':  o += "&gt;";   break;
            case '"':  o += "&quot;"; break;
            case '\'': o += "&#39;";  break;
            default:   o += c;
        }
    }
    return o;
}

std::string num(double v, int decimals) {
    char buf[48];
    // The decimals argument is honoured: a bin ratio of 1.5849 has to be able to
    // read "1.58" rather than being silently rounded to one place.
    std::snprintf(buf, sizeof(buf), "%.*f", decimals < 0 ? 0 : decimals, v);
    return buf;
}

// Defined with the donuts below; the stacked error chart uses it first.
std::string share_text(double pct);

// There is no "how to read it" note anywhere in the report, and deliberately no
// helper to print one.  Every chart that needs a word says it in its subtitle, and
// the last note to survive — under the result-code breakdown's cumulative bars —
// went away with the bars: a pie of the same codes says the same thing at a
// glance, so there is nothing left to explain.  The test for ever adding one back:
// does the reader have a question the drawing itself cannot answer?
//
// Class colour shaded by rank inside the class: two client codes would otherwise
// share the same amber and read as one bar.  Shared by the stacked error chart and
// by the result-code breakdown, so a given code keeps one colour all through the
// report — the same colour on its bar and on its slice of the pie.
const double CLASS_SHADES[] = {0.95, 0.70, 0.50, 0.34};

// ---- the hatched "either cause" class -------------------------------------
//
// One class — PolicyOrClient — says the log cannot attribute the refusal: the
// same "no" answers a request the client had no right to make and one it
// legitimately expected to work.  It is drawn as a diagonal amber/violet hatch
// wherever it appears; violet stays the base colour (the label, the tooltip
// text), the hatch carries the amber.  The handoff note for this feature and the
// reasoning behind the code list live in log_parser.hpp.
//
// An SVG paint server (a <pattern>) is resolved per drawing, so the <defs> must
// be emitted inside the very <svg> that fills with it — hence one helper to emit
// the pattern (called only by a chart that actually draws a dual shape) and one
// to produce the paint reference.  The tag must be unique across the page: ids
// are document-global and two patterns sharing one id are a duplicate id.
void print_hatch_defs(const char* tag) {
    const char* base = ldap_code_class_color(LdapCodeClass::Policy);                  // violet
    const char* over = ldap_code_class_hatch_color(LdapCodeClass::PolicyOrClient);    // amber
    std::cout << "<defs><pattern id=\"" << tag
              << "\" width=\"9\" height=\"9\" patternUnits=\"userSpaceOnUse\" "
                 "patternTransform=\"rotate(45)\">"
                 "<rect width=\"9\" height=\"9\" fill=\"" << base << "\"/>"
                 "<rect width=\"4.5\" height=\"9\" fill=\"" << over << "\"/>"
                 "</pattern></defs>\n";
}

// The paint of one class: the hatch for the dual class, its plain colour
// otherwise.  `tag` names the pattern emitted in this same svg.
std::string class_fill(LdapCodeClass cls, const char* tag) {
    if (cls == LdapCodeClass::PolicyOrClient) return std::string("url(#") + tag + ")";
    return ldap_code_class_color(cls);
}

// The same two colours as an HTML background: a legend swatch cannot reference an
// SVG pattern, so the hatch is laid out as a CSS gradient there.
std::string hatch_background_css() {
    return std::string("repeating-linear-gradient(45deg,") +
           ldap_code_class_color(LdapCodeClass::Policy) + " 0 3px," +
           ldap_code_class_hatch_color(LdapCodeClass::PolicyOrClient) + " 3px 6px)";
}

// Shared palette: donut slices take a colour by position, and the per-server
// coverage lanes take the same ones, so a cluster report reads in one set of
// colours.  Nine is what a legend can carry without a repeat.
constexpr size_t PALETTE_N = 9;
const char* const PALETTE[PALETTE_N] = {"#3498db", "#e67e22", "#27ae60", "#9b59b6",
                                        "#e74c3c", "#16a085", "#f1c40f", "#7f8c8d", "#34495e"};

// One tag per chart, never reused: see print_hatch_defs().
const char* const HATCH_TAG_STACK = "sl-hatch-stack";
const char* const HATCH_TAG_BREAKDOWN = "sl-hatch-breakdown";
const char* const HATCH_TAG_DONUT = "sl-hatch-donut";

// A per-element colour is emitted as an inline `style`, never as the SVG
// presentation attribute `fill`: a stylesheet rule on the element's class beats
// a presentation attribute, so `.sl-bar{fill:#3498db}` repainted every
// class-coloured bar blue while `fill="#27ae60"` sat right there in the markup.
// Only a render shows this, so the rule is spelled out here once.

// Round a value down to a "readable" axis tick spacing.
double nice_step(double range, int ticks) {
    if (range <= 0.0 || ticks <= 0) return 1.0;
    const double raw = range / ticks;
    const double mag = std::pow(10.0, std::floor(std::log10(raw)));
    const double n = raw / mag;
    const double step = (n <= 1.0 ? 1.0 : n <= 2.0 ? 2.0 : n <= 5.0 ? 5.0 : 10.0) * mag;
    return step < 1.0 ? 1.0 : step;
}

// ---- shared style and tooltip script -------------------------------------

void print_chart_style() {
    std::cout << R"CSS(<style>
  .sl-chart{background:#fff;border-radius:6px;padding:14px 20px 10px;max-width:1100px;margin:0 auto 18px;position:relative}
  .sl-chart-title{font-size:0.95rem;font-weight:600;color:#2c3e50;margin-bottom:2px}
  .sl-chart-sub{font-size:0.78rem;color:#7f8c9b;margin-bottom:10px}
  .sl-chart svg{width:100%;height:auto;display:block}
  .sl-grid{stroke:#e6eaf0;stroke-width:1}
  .sl-axis{stroke:#c8d0da;stroke-width:1}
  .sl-tick{fill:#7f8c9b;font-size:11px;font-family:'Consolas','Courier New',monospace}
  .sl-area{fill:#3498db;fill-opacity:0.16}
  .sl-line{fill:none;stroke:#3498db;stroke-width:2;stroke-linejoin:round}
  .sl-hit{fill:transparent}
  .sl-ev-line{stroke-dasharray:4 3;stroke-width:1.5}
  .sl-ev-start{stroke:#27ae60}
  .sl-ev-stop{stroke:#e74c3c}
  .sl-ev-dot-start{fill:#27ae60}
  .sl-ev-dot-stop{fill:#e74c3c}
  .sl-slice{stroke:#fff;stroke-width:1.5}
  .sl-downtime{fill:#e74c3c;fill-opacity:0.10}
  .sl-downtime-edge{stroke:#e74c3c;stroke-opacity:0.55;stroke-dasharray:3 3;stroke-width:1}
  .sl-ev-abrupt{stroke:#e67e22;stroke-dasharray:2 2;stroke-width:1.5}
  .sl-ev-dot-abrupt{fill:#e67e22}
  .sl-bar{fill:#3498db;fill-opacity:0.75}
  .sl-legend-name{fill:#2c3e50;font-size:12.5px}
  .sl-legend-val{fill:#7f8c9b;font-size:12.5px;font-family:'Consolas','Courier New',monospace}
  .sl-legend-det{fill:#a4b0be;font-size:11px;font-family:'Consolas','Courier New',monospace}
  .sl-chart-note{font-size:0.78rem;color:#7f8c9b;margin:6px 0 2px}
  /* Latency density: the filled profile of the logarithmic bins. */
  .sl-density-area{fill:#3498db;fill-opacity:0.18}
  .sl-density-line{fill:none;stroke:#2980b9;stroke-width:2;stroke-linejoin:round}
  .sl-density-dot{fill:#2980b9}
  /* Stacked errors: the same silhouette as one total curve, with the colour
     underneath naming the result code that built each part of it. */
  .sl-stack-total{fill:none;stroke:#2c3e50;stroke-width:1.5;stroke-linejoin:round}
  .sl-stack-legend{display:flex;flex-wrap:wrap;gap:5px 18px;font-size:0.76rem;color:#5b6b7c;
                   line-height:1.5;margin:8px 0 2px;padding-left:2px}
  .sl-stack-key{white-space:nowrap}
  .sl-stack-key i{display:inline-block;width:11px;height:11px;border-radius:2px;margin-right:6px;
                  vertical-align:-1px}
  .sl-tip{position:absolute;pointer-events:none;background:#2c3e50;color:#ecf0f1;border-radius:5px;
          padding:4px 9px;font-size:12px;white-space:nowrap;transform:translate(12px,-50%);z-index:9;
          box-shadow:0 2px 6px rgba(0,0,0,.25)}
  /* Per-server time coverage: one lane under the x axis per server — the track
     is the window the chart plots, the filled span is what that server's own
     log covers, so the reader can see where one file stops and another starts. */
  .sl-cov-track{fill:#eef1f5}
  .sl-cov-span{fill-opacity:0.55}
  .sl-cov-key-track{background:#eef1f5;border:1px solid #d3dbe3}
  /* Spans of the chart window that NO server's log covers.  A run that mixes
     logs of unrelated periods (an old file left beside the current ones) plots
     a window that is mostly empty; without this, a flat curve there reads as
     "no traffic" instead of "no data". */
  .sl-nolog-band{fill:#5b6b7c;fill-opacity:0.13}
  .sl-nolog-edge{stroke:#8a97a6;stroke-opacity:0.55;stroke-dasharray:2 4;stroke-width:1}
  .sl-nolog-key{background:repeating-linear-gradient(45deg,#eef1f5 0 3px,#c2ccd6 3px 6px)}
</style>
)CSS";
}

void print_chart_script() {
    // One listener per chart.  event.target is the hit element under the
    // cursor, so its dataset carries the values — no scale duplication here.
    std::cout << R"JS(<script>
(function(){
  var hosts=document.querySelectorAll('.sl-chart');
  for(var i=0;i<hosts.length;i++){(function(host){
    var tip=host.querySelector('.sl-tip'), svg=host.querySelector('svg');
    if(!tip||!svg) return;
    svg.addEventListener('mousemove',function(e){
      var d=e.target&&e.target.dataset?e.target.dataset:null;
      if(!d||d.x===undefined){tip.hidden=true;return;}
      tip.textContent=d.y?d.x+' — '+d.y:d.x;
      tip.hidden=false;
      var r=host.getBoundingClientRect(), x=e.clientX-r.left, y=e.clientY-r.top;
      var maxX=Math.max(0,r.width-tip.offsetWidth-24);
      tip.style.left=Math.max(0,Math.min(x,maxX))+'px';
      tip.style.top=y+'px';
    });
    svg.addEventListener('mouseleave',function(){tip.hidden=true;});
  })(hosts[i]);}
})();
</script>
)JS";
}

// ---- time charts ----------------------------------------------------------

// Emit the plot frame (horizontal and vertical grid plus tick labels) that the
// two time-series charts share.
void print_time_frame(double L, double T, double pw, double ph, double H,
                      long long t0, long long t1, double ytop, double ystep,
                      double ymax_px) {
    const double W = L + pw + 14;
    for (double v = 0.0; v <= ytop + 0.5 * ystep; v += ystep) {
        const double y = T + ph - (ymax_px > 0 ? (v / ytop) * ph : 0.0);
        std::cout << "<line class=\"sl-grid\" x1=\"" << num(L, 0) << "\" y1=\"" << num(y, 1)
                  << "\" x2=\"" << num(W - 14, 0) << "\" y2=\"" << num(y, 1) << "\"/>\n";
        std::cout << "<text class=\"sl-tick\" x=\"" << num(L - 8, 0) << "\" y=\"" << num(y + 4, 1)
                  << "\" text-anchor=\"end\">" << num(v, 0) << "</text>\n";
    }
    const double span = static_cast<double>(t1 - t0);
    const int XT = 5;
    for (int i = 0; i <= XT; ++i) {
        const long long t = t0 + static_cast<long long>(span * i / XT);
        const double x = L + (span > 0 ? (static_cast<double>(t - t0) / span) * pw : 0.0);
        std::cout << "<line class=\"sl-grid\" x1=\"" << num(x, 1) << "\" y1=\"" << num(T, 0)
                  << "\" x2=\"" << num(x, 1) << "\" y2=\"" << num(T + ph, 0) << "\"/>\n";
        std::cout << "<text class=\"sl-tick\" x=\"" << num(x, 1) << "\" y=\"" << num(H - 12, 0)
                  << "\" text-anchor=\"middle\">" << xml_escape(format_epoch_seconds(t)) << "</text>\n";
    }
    std::cout << "<line class=\"sl-axis\" x1=\"" << num(L, 0) << "\" y1=\"" << num(T + ph, 0)
              << "\" x2=\"" << num(W - 14, 0) << "\" y2=\"" << num(T + ph, 0) << "\"/>\n";
}

// ---- per-server coverage band ----------------------------------------------
//
// A cluster's servers are rotated and restarted at different moments, so their
// files do not cover the same window as each other.  A curve that steps up and
// then falls off a cliff at the edge of one server's file is otherwise read as
// the end of a heavy operation, when it is only the end of that log.  Each
// server therefore gets one lane under the x axis: the window the chart plots,
// as a faint track, and the span that server's own log covers, painted on it.

struct CoverageLane {
    std::string server;
    long long first = 0;                 // epoch seconds
    long long last = 0;
};

// One lane per server whose own window is known, ordered by when its log starts.
// Empty when a single server is in play — its window *is* the chart's window, so
// a lane would say nothing — and also when the logs name no host at all, which
// is what the debug format looks like.
std::vector<CoverageLane> coverage_lanes(const Aggregator& agg) {
    std::vector<CoverageLane> lanes;
    if (agg.servers.size() < 2) return lanes;
    for (const auto& [server, w] : agg.time_by_server) {
        auto a = ts_epoch_seconds(w.first), b = ts_epoch_seconds(w.last);
        if (!a || !b) continue;          // unreadable stamp: no lane rather than a wrong one
        lanes.push_back({server, *a, *b});
    }
    if (lanes.size() < 2) return {};     // a single known window has nothing to compare with
    std::sort(lanes.begin(), lanes.end(), [](const CoverageLane& a, const CoverageLane& b) {
        if (a.first != b.first) return a.first < b.first;
        return a.server < b.server;      // deterministic for two logs starting together
    });
    return lanes;
}

constexpr double LANE_H = 7.0;           // height of one server's lane
constexpr double LANE_GAP = 2.0;         // between two lanes
constexpr double LANE_LEAD = 5.0;        // between the x axis and the first lane

// The height the SVG must gain to hold the strip.  The caller adds it to `H`,
// which is exactly what makes room: print_time_frame pins the time labels to
// `H - 12`, so they move down by the same amount and the strip takes the freed
// space between the axis and them.
double coverage_strip_height(size_t lanes) {
    if (lanes == 0) return 0.0;
    return LANE_LEAD + static_cast<double>(lanes) * LANE_H +
           static_cast<double>(lanes - 1) * LANE_GAP;
}

// The spans of [t0, t1] that no server's own log covers: the complement of the
// union of the coverage windows.
std::vector<std::pair<long long, long long>> uncovered_spans(
        const std::vector<CoverageLane>& lanes, long long t0, long long t1) {
    std::vector<std::pair<long long, long long>> gaps;
    if (lanes.empty() || t1 <= t0) return gaps;
    std::vector<std::pair<long long, long long>> iv;
    iv.reserve(lanes.size());
    for (const CoverageLane& l : lanes)
        iv.emplace_back(std::max(l.first, t0), std::min(l.last, t1));
    std::sort(iv.begin(), iv.end());
    long long cur = t0;
    for (const auto& [a, b] : iv) {
        if (b <= cur) continue;
        if (a > cur) gaps.emplace_back(cur, a);
        cur = b;
    }
    if (cur < t1) gaps.emplace_back(cur, t1);
    return gaps;
}

// The bands, drawn behind the data.
void print_nolog_bands(const std::vector<std::pair<long long, long long>>& gaps,
                       long long t0, long long t1, double L, double pw,
                       double T, double ph) {
    if (gaps.empty() || t1 <= t0) return;
    const double span = static_cast<double>(t1 - t0);
    for (const auto& [a, b] : gaps) {
        const double x0 = std::max(L + (static_cast<double>(a - t0) / span) * pw, L);
        const double x1 = std::min(L + (static_cast<double>(b - t0) / span) * pw, L + pw);
        if (x1 <= x0) continue;
        std::cout << "<rect class=\"sl-nolog-band\" x=\"" << num(x0, 1) << "\" y=\"" << num(T, 0)
                  << "\" width=\"" << num(x1 - x0, 1) << "\" height=\"" << num(ph, 0) << "\"/>\n";
        std::cout << "<line class=\"sl-nolog-edge\" x1=\"" << num(x0, 1) << "\" y1=\"" << num(T, 0)
                  << "\" x2=\"" << num(x0, 1) << "\" y2=\"" << num(T + ph, 0) << "\"/>\n";
        std::cout << "<line class=\"sl-nolog-edge\" x1=\"" << num(x1, 1) << "\" y1=\"" << num(T, 0)
                  << "\" x2=\"" << num(x1, 1) << "\" y2=\"" << num(T + ph, 0) << "\"/>\n";
    }
}

// The hover targets, emitted last so they win over the per-bucket strips: a gap
// has no data, so its tooltip must say "missing data", not "0 connection(s)".
void print_nolog_hits(const std::vector<std::pair<long long, long long>>& gaps,
                      long long t0, long long t1, double L, double pw,
                      double T, double ph) {
    if (gaps.empty() || t1 <= t0) return;
    const double span = static_cast<double>(t1 - t0);
    for (const auto& [a, b] : gaps) {
        const double x0 = std::max(L + (static_cast<double>(a - t0) / span) * pw, L);
        const double x1 = std::min(L + (static_cast<double>(b - t0) / span) * pw, L + pw);
        if (x1 <= x0) continue;
        std::cout << "<rect class=\"sl-hit\" x=\"" << num(x0, 1) << "\" y=\"" << num(T, 0)
                  << "\" width=\"" << num(x1 - x0, 1) << "\" height=\"" << num(ph, 0)
                  << "\" data-x=\"missing data\" data-y=\"no server's log covers "
                  << xml_escape(format_epoch_seconds(a)) << " to "
                  << xml_escape(format_epoch_seconds(b)) << "\"/>\n";
    }
}

// The strip itself, drawn in the space reserved above.  Emitted into the SVG the
// caller has already opened, so it is called before `</svg>`.
void print_coverage_lanes(const std::vector<CoverageLane>& lanes,
                          long long t0, long long t1,
                          double L, double pw, double T, double ph) {
    if (lanes.empty()) return;
    const double span = static_cast<double>(t1 - t0);
    if (span <= 0) return;
    auto xof = [&](long long t) { return L + (static_cast<double>(t - t0) / span) * pw; };
    const double top = T + ph + LANE_LEAD;

    std::cout << "<g class=\"sl-cov\">\n";
    for (size_t i = 0; i < lanes.size(); ++i) {
        const CoverageLane& ln = lanes[i];
        const double y = top + static_cast<double>(i) * (LANE_H + LANE_GAP);
        const double x0 = std::max(xof(ln.first), L);
        const double x1 = std::min(xof(ln.last), L + pw);
        std::cout << "<rect class=\"sl-cov-track\" x=\"" << num(L, 0) << "\" y=\"" << num(y, 1)
                  << "\" width=\"" << num(pw, 0) << "\" height=\"" << num(LANE_H, 0) << "\"/>\n";
        if (x1 > x0)
            std::cout << "<rect class=\"sl-cov-span\" x=\"" << num(x0, 1) << "\" y=\"" << num(y, 1)
                      << "\" width=\"" << num(x1 - x0, 1) << "\" height=\"" << num(LANE_H, 0)
                      << "\" style=\"fill:" << PALETTE[i % PALETTE_N] << "\"/>\n";
        // A hit area across the whole lane, so the server and the exact window
        // can be read without measuring pixels.
        std::cout << "<rect class=\"sl-hit\" x=\"" << num(L, 0) << "\" y=\"" << num(y, 1)
                  << "\" width=\"" << num(pw, 0) << "\" height=\"" << num(LANE_H, 0)
                  << "\" data-x=\"" << xml_escape(ln.server) << "\" data-y=\"log covers "
                  << xml_escape(format_epoch_seconds(ln.first)) << " to "
                  << xml_escape(format_epoch_seconds(ln.last)) << "\"/>\n";
    }
    std::cout << "</g>\n";
}

// The key, emitted in HTML beside the other legends.  Without it the lanes are
// just marks: the track has to be told from the covered span, and each span has
// to be told from the others.
void print_coverage_legend(const std::vector<CoverageLane>& lanes,
                           const std::vector<std::pair<long long, long long>>& gaps) {
    if (lanes.empty()) return;
    std::cout << "<div class=\"sl-stack-legend\">"
                 "<span class=\"sl-stack-key\" title=\"the window this chart plots\">"
                 "<i class=\"sl-cov-key-track\"></i>chart window</span>";
    for (size_t i = 0; i < lanes.size(); ++i) {
        std::cout << "<span class=\"sl-stack-key\" title=\"covered by this server's own log\">"
                  << "<i style=\"background:" << PALETTE[i % PALETTE_N] << "\"></i>"
                  << xml_escape(lanes[i].server) << " — "
                  << xml_escape(format_epoch_seconds(lanes[i].first)) << " \xe2\x86\x92 "
                  << xml_escape(format_epoch_seconds(lanes[i].last)) << "</span>";
    }
    if (!gaps.empty())
        std::cout << "<span class=\"sl-stack-key\" title=\"no server's log covers this period\">"
                     "<i class=\"sl-nolog-key\"></i>no log</span>";
    std::cout << "</div>\n";
}

void print_connection_chart(const Aggregator& agg) {
    if (agg.conn_timeline.empty()) return;
    std::vector<ConnEvent> ev = agg.conn_timeline;
    // Stable sort on time only: the timeline is collected in log order, and
    // reordering events that share a second would change the running count
    // (timestamps are truncated to the second here) and inflate the peak.
    // Stability keeps the original order within a second, so for a single file
    // the curve reproduces the parser's own connection count exactly.
    std::stable_sort(ev.begin(), ev.end(),
                     [](const ConnEvent& a, const ConnEvent& b) { return a.t < b.t; });

    long long t0 = ev.front().t, t1 = ev.back().t;
    if (auto a = ts_epoch_seconds(agg.firsttime)) t0 = std::min(t0, *a);
    if (auto b = ts_epoch_seconds(agg.lasttime))  t1 = std::max(t1, *b);
    if (t1 <= t0) t1 = t0 + 1;

    const int NB = 240;                       // hover granularity
    const double span = static_cast<double>(t1 - t0);
    std::vector<long long> peak_in(NB, 0);
    long long running = 0;
    size_t next = 0;
    for (int b = 0; b < NB; ++b) {
        const long long upto = t0 + static_cast<long long>(span * (b + 1) / NB);
        while (next < ev.size() && ev[next].t <= upto) {
            running += ev[next].delta;
            if (running < 0) running = 0;     // tolerate logs with missing closes
            if (running > peak_in[b]) peak_in[b] = running;
            ++next;
        }
        if (running > peak_in[b]) peak_in[b] = running;
    }
    if (next < ev.size()) {                   // events past the last bucket
        for (size_t i = next; i < ev.size(); ++i) {
            running += ev[i].delta;
            if (running < 0) running = 0;
        }
    }

    long long ymax = 0;
    for (int b = 0; b < NB; ++b) ymax = std::max(ymax, peak_in[b]);
    if (ymax <= 0) return;                    // nothing meaningful to draw
    // The curve is a bucketed view, so it can miss a short spike; the parser's
    // own peak is authoritative and keeps the chart consistent with the
    // "Peak active connections" line of the Statistics table.
    const long long peak = std::max(ymax, agg.peak_active_connections);
    ymax = peak;

    const double step = nice_step(static_cast<double>(ymax), 5);
    const long long ytop = static_cast<long long>(std::ceil(ymax / step) * step);

    // SVG geometry.  The per-server coverage lanes are measured before anything
    // is drawn: the strip grows the canvas by its own height, which is the only
    // way to seat it under the axis without pushing the time labels off the
    // bottom — print_time_frame pins those to `H - 12`, so they follow.
    const double W = 1000, H0 = 300, L = 68, R = 14, T = 14, B = 34;
    const double ph = H0 - T - B;
    const std::vector<CoverageLane> lanes = coverage_lanes(agg);
    const double H = H0 + coverage_strip_height(lanes.size());
    const double pw = W - L - R;
    const std::vector<std::pair<long long, long long>> gaps = uncovered_spans(lanes, t0, t1);
    auto xof = [&](long long t) { return L + (static_cast<double>(t - t0) / span) * pw; };
    auto yof = [&](double v) { return T + ph - (v / static_cast<double>(ytop)) * ph; };

    // ---- server lifecycle events -------------------------------------------
    // Turned into:
    //   • downtime bands — from the first shutdown event of a group to the next
    //     start (or to the end of the window when the server never came back),
    //     drawn as a shaded background;
    //   • abrupt restarts — a start NOT preceded by a shutdown, which means the
    //     previous instance died without logging one (crash, OOM, kill -9 …).
    struct SrvEvent { long long t; std::string what; bool start; };
    std::vector<SrvEvent> sev;
    sev.reserve(agg.server_event_list.size());
    for (const auto& [ts, what] : agg.server_event_list) {
        if (auto t = ts_epoch_seconds(ts)) {
            sev.push_back({*t, what, what.rfind("slapd starting", 0) == 0});
        }
    }
    std::stable_sort(sev.begin(), sev.end(), [](const SrvEvent& a, const SrvEvent& b) {
        if (a.t != b.t) return a.t < b.t;
        return a.what < b.what;      // deterministic for events sharing a second
    });

    std::vector<std::pair<long long, long long>> raw_bands;
    std::vector<SrvEvent> abrupt;
    std::optional<long long> outage;             // set while the server is down
    for (size_t i = 0; i < sev.size(); ++i) {
        if (sev[i].start) {
            if (outage) { raw_bands.emplace_back(*outage, sev[i].t); outage.reset(); }
            else if (i > 0) abrupt.push_back(sev[i]);
        } else if (!outage) {
            outage = sev[i].t;                   // first shutdown event of the outage
        }
    }
    if (outage) raw_bands.emplace_back(*outage, t1);   // no start before the end

    // Only keep the bands the log actually corroborates.  An outage means *no
    // traffic*, so a stop followed by connection activity was not an outage:
    // this happens when the log mixes several slapd instances, when a restart
    // line carries an unexpected wording, or when the file was rotated between
    // the stop and the next start — the following start then lives in another
    // file.  Without this check a single unmatched stop shaded 43 % of a real
    // two-day log.
    std::vector<std::pair<long long, long long>> bands;
    std::vector<std::pair<double, double>> band_x;      // pixel span, floored
    for (const auto& [a, b] : raw_bands) {
        if (b <= a) continue;                        // no measurable downtime
        auto it = std::upper_bound(ev.begin(), ev.end(), a,
                                   [](long long v, const ConnEvent& e) { return v < e.t; });
        if (it != ev.end() && it->t < b) continue;   // traffic during the "outage"
        double x0 = xof(a), x1 = xof(b);
        // A two-minute outage is 0.4 px on a two-day chart; floor the width so
        // it stays visible.  The tooltip still reports the real duration.
        const double MIN_W = 5.0;
        if ((x1 - x0) < MIN_W) {
            const double c = (x0 + x1) / 2.0;
            x0 = c - MIN_W / 2.0;
            x1 = c + MIN_W / 2.0;
        }
        x0 = std::max(x0, L);
        x1 = std::min(x1, W - R);
        bands.emplace_back(a, b);
        band_x.emplace_back(x0, x1);
    }

    std::cout << "<h2>Simultaneous Connections</h2>\n";
    std::cout << "<div class=\"sl-chart\">\n";
    std::cout << "<div class=\"sl-chart-sub\">" << xml_escape(agg.firsttime)
              << " &rarr; " << xml_escape(agg.lasttime)
              << " &middot; peak " << peak << " connection(s)";
    if (!bands.empty()) std::cout << " &middot; " << bands.size() << " downtime period(s)";
    if (!gaps.empty()) std::cout << " &middot; shaded: no server's log covers it";
    // The marker key belongs with the legend, not in a note: these three marks
    // are the whole of the chart's vocabulary and nothing else explains them.
    std::cout << " &middot; markers: green start, red stop, orange restart without a clean shutdown";
    std::cout << "</div>\n";
    std::cout << "<svg viewBox=\"0 0 1000 " << num(H, 0) << "\" role=\"img\" "
                 "aria-label=\"Simultaneous connections over time\">\n";

    // downtime bands, behind everything else
    for (const auto& [x0, x1] : band_x) {
        std::cout << "<rect class=\"sl-downtime\" x=\"" << num(x0, 1) << "\" y=\"" << num(T, 0)
                  << "\" width=\"" << num(x1 - x0, 1) << "\" height=\"" << num(ph, 0) << "\"/>\n";
    }
    // Spans no server's log covers, on the same layer as the downtime bands.
    print_nolog_bands(gaps, t0, t1, L, pw, T, ph);

    print_time_frame(L, T, pw, ph, H, t0, t1, static_cast<double>(ytop), step,
                     static_cast<double>(ytop));

    // area + line, one point per bucket
    std::string area = "M " + num(xof(t0), 1) + "," + num(yof(0), 1);
    std::string line;
    for (int b = 0; b < NB; ++b) {
        const long long t = t0 + static_cast<long long>(span * (b + 1) / NB);
        const double x = xof(t), y = yof(static_cast<double>(peak_in[b]));
        area += " L " + num(x, 1) + "," + num(y, 1);
        line += (line.empty() ? "M " : " L ") + num(x, 1) + "," + num(y, 1);
    }
    area += " L " + num(xof(t1), 1) + "," + num(yof(0), 1) + " Z";
    std::cout << "<path class=\"sl-area\" d=\"" << area << "\"/>\n";
    std::cout << "<path class=\"sl-line\" d=\"" << line << "\"/>\n";

    // vertical rules for every lifecycle event.  Dots are staggered so that the
    // several events of one restart (shutdown requested / waiting / stopped /
    // starting), which land within a few pixels of each other, stay visible
    // instead of being overdrawn by the last one.
    auto is_abrupt = [&](const SrvEvent& e) {
        for (const auto& a : abrupt) if (a.t == e.t && a.what == e.what) return true;
        return false;
    };
    double last_dot_x = -1e9;
    int dot_level = 0;
    for (const auto& e : sev) {
        if (e.t < t0 || e.t > t1) continue;
        const bool ab = is_abrupt(e);
        const char* cls = e.start ? (ab ? "sl-ev-start sl-ev-abrupt" : "sl-ev-start") : "sl-ev-stop";
        const double x = xof(e.t);
        std::cout << "<line class=\"sl-ev-line " << cls << "\" x1=\"" << num(x, 1) << "\" y1=\""
                  << num(T, 0) << "\" x2=\"" << num(x, 1) << "\" y2=\"" << num(T + ph, 0) << "\"/>\n";
        if (std::fabs(x - last_dot_x) < 10.0) dot_level = (dot_level + 1) % 4; else dot_level = 0;
        last_dot_x = x;
        const char* dot = ab ? "sl-ev-dot-abrupt" : (e.start ? "sl-ev-dot-start" : "sl-ev-dot-stop");
        std::cout << "<circle class=\"" << dot << "\" cx=\"" << num(x, 1) << "\" cy=\""
                  << num(T + 5 + dot_level * 12.0, 1) << "\" r=\"4\"/>\n";
    }

    // one hit strip per bucket, carrying the tooltip values
    for (int b = 0; b < NB; ++b) {
        const long long ta = t0 + static_cast<long long>(span * b / NB);
        const long long tb = t0 + static_cast<long long>(span * (b + 1) / NB);
        std::cout << "<rect class=\"sl-hit\" x=\"" << num(xof(ta), 1) << "\" y=\"" << num(T, 0)
                  << "\" width=\"" << num(xof(tb) - xof(ta), 2) << "\" height=\"" << num(ph, 0)
                  << "\" data-x=\"" << xml_escape(format_epoch_seconds(ta))
                  << "\" data-y=\"" << peak_in[b] << " connection(s)\"/>\n";
    }

    // Downtime-band and event hit areas come LAST so they sit on top of the
    // bucket strips; emitted before them they would never receive the hover.
    for (size_t i = 0; i < bands.size(); ++i) {
        const auto& [a, b] = bands[i];
        const auto& [x0, x1] = band_x[i];
        std::cout << "<rect class=\"sl-hit\" x=\"" << num(x0, 1) << "\" y=\"" << num(T, 0)
                  << "\" width=\"" << num(x1 - x0, 1) << "\" height=\""
                  << num(ph, 0) << "\" data-x=\"" << xml_escape(format_epoch_seconds(a)) << " down"
                  << "\" data-y=\"" << (b - a) << " s without the server\"/>\n";
    }
    for (const auto& e : sev) {
        if (e.t < t0 || e.t > t1) continue;
        const std::string note = is_abrupt(e)
            ? e.what + " — restarted without a clean shutdown (previous instance likely died)"
            : e.what;
        std::cout << "<rect class=\"sl-hit\" x=\"" << num(xof(e.t) - 4, 1) << "\" y=\"" << num(T, 0)
                  << "\" width=\"9\" height=\"" << num(ph, 0)
                  << "\" data-x=\"" << xml_escape(format_epoch_seconds(e.t))
                  << "\" data-y=\"" << xml_escape(note) << "\"/>\n";
    }

    print_coverage_lanes(lanes, t0, t1, L, pw, T, ph);
    print_nolog_hits(gaps, t0, t1, L, pw, T, ph);

    std::cout << "</svg>\n<div class=\"sl-tip\" hidden></div>\n";
    print_coverage_legend(lanes, gaps);
    // No reading note here: how many connections were open at a glance needs no
    // explaining, and the marker key is in the subtitle.
    std::cout << "</div>\n";
}

// One band of the stacked "errors over time" chart: a result code, its colour
// (the class colour, shaded by rank inside the class), and its count per time
// slice.  The folded tail of small codes shares a single grey band.  `hatched`
// marks the dual class, whose paint is an SVG pattern reference and whose legend
// swatch must therefore be drawn as a CSS gradient instead of a flat background.
struct ErrorBand {
    int code = 0;
    std::string label;              // "49 invalidCredentials", or "other"
    std::string fill;
    double fill_opacity = 1.0;
    bool hatched = false;
    std::vector<long long> series;  // one count per time slice
    long long total = 0;
};

// "Errors over time", stacked by result code.  The outline is exactly what a
// single total curve would draw — it *is* the total — but the colour underneath
// says which code built each part of it, so a peak that is one code (a client
// spraying wrong passwords, a directory that stopped accepting writes) can be
// told apart from a general rise.  The bands keep the class colours of the rest
// of the report, so amber still means "the client asked", violet "the
// configuration refuses", red "slapd failed".
void print_error_series_chart(const Aggregator& agg, long long t0, long long t1,
                              const std::string& sub) {
    if (agg.error_times_by_code.empty() || t1 <= t0) return;

    const int NB = 240;
    const double span = static_cast<double>(t1 - t0);

    std::vector<ErrorBand> bands;
    for (const auto& [code, times] : agg.error_times_by_code) {
        ErrorBand b;
        b.code = code;
        b.label = std::to_string(code) + " " + ldap_error_name(code);
        b.total = static_cast<long long>(times.size());
        b.series.assign(NB, 0);
        for (long long t : times) {
            long long k = static_cast<long long>((t - t0) / span * NB);
            if (k < 0) k = 0;
            if (k >= NB) k = NB - 1;
            b.series[static_cast<size_t>(k)]++;
        }
        bands.push_back(std::move(b));
    }
    // Tallest band at the bottom: the stack is then stable to read across the
    // whole width, and the biggest contributor is always the one in view.
    std::sort(bands.begin(), bands.end(), [](const ErrorBand& a, const ErrorBand& b) {
        if (a.total != b.total) return a.total > b.total;
        return a.code < b.code;                    // deterministic tie-break
    });

    // Six bands are what a legend can carry; the tail is honest summed rather
    // than dropped, and the tooltips still name the codes underneath it.
    constexpr size_t KEEP = 6;
    long long grand = 0;
    for (const auto& b : bands) grand += b.total;
    if (bands.size() > KEEP) {
        ErrorBand other;
        other.label = "other";
        other.fill = "#7f8c8d";
        other.fill_opacity = 0.45;
        other.series.assign(NB, 0);
        for (size_t i = KEEP; i < bands.size(); ++i) {
            other.total += bands[i].total;
            for (int k = 0; k < NB; ++k) other.series[static_cast<size_t>(k)] += bands[i].series[static_cast<size_t>(k)];
        }
        bands.resize(KEEP);
        bands.push_back(std::move(other));
    }

    // Class colour, shaded by rank inside the class: two client codes would
    // otherwise share the same amber and read as one band.  The dual class is
    // painted with the hatch instead of the flat colour and flagged so its legend
    // swatch can be drawn the HTML way.
    int rank_by_class[5] = {0, 0, 0, 0, 0};
    bool any_hatch = false;
    for (auto& b : bands) {
        if (!b.fill.empty()) continue;              // the folded grey band
        const LdapCodeClass cls = ldap_code_class(b.code);
        b.fill = class_fill(cls, HATCH_TAG_STACK);
        b.hatched = (cls == LdapCodeClass::PolicyOrClient);
        any_hatch = any_hatch || b.hatched;
        const int rank = rank_by_class[static_cast<int>(cls)]++;
        b.fill_opacity = CLASS_SHADES[rank < 4 ? rank : 3];
    }
    std::vector<long long> total_per(NB, 0);
    for (const auto& b : bands) {
        for (int k = 0; k < NB; ++k) total_per[static_cast<size_t>(k)] += b.series[static_cast<size_t>(k)];
    }
    long long ymax = 0;
    for (auto c : total_per) ymax = std::max(ymax, c);
    if (ymax <= 0) return;

    const double step = nice_step(static_cast<double>(ymax), 4);
    const double ytop = std::ceil(ymax / step) * step;
    const double W = 1000, H0 = 260, L = 68, R = 14, T = 14, B = 34;
    const double ph = H0 - T - B;
    const std::vector<CoverageLane> lanes = coverage_lanes(agg);
    const double H = H0 + coverage_strip_height(lanes.size());
    const double pw = W - L - R;
    const std::vector<std::pair<long long, long long>> gaps = uncovered_spans(lanes, t0, t1);
    auto yof = [&](double v) { return T + ph - (v / ytop) * ph; };
    // Slice k covers [k/NB, (k+1)/NB) of the window.  The fractions are used
    // directly rather than round-tripped through a timestamp: span/NB truncates
    // to 0 s on a short window, which made the first slice zero pixels wide.
    auto xat = [&](int k) { return L + pw * k / NB; };

    std::cout << "<h2>Errors Over Time</h2>\n<div class=\"sl-chart\">\n";
    std::cout << "<div class=\"sl-chart-sub\">" << xml_escape(sub);
    if (!gaps.empty()) std::cout << " &middot; shaded: no server's log covers it";
    std::cout << "</div>\n";
    std::cout << "<svg viewBox=\"0 0 1000 " << num(H, 0) << "\" role=\"img\" aria-label=\"Errors over time, "
                 "stacked by result code\">\n";
    if (any_hatch) print_hatch_defs(HATCH_TAG_STACK);
    print_nolog_bands(gaps, t0, t1, L, pw, T, ph);
    print_time_frame(L, T, pw, ph, H, t0, t1, ytop, step, ytop);

    // One filled band per code: the same profile stacked on top of each other,
    // so the top edge is the total and the colours underneath are the detail.
    std::vector<long long> base(NB, 0);
    for (const auto& b : bands) {
        std::string lower, upper;
        for (int k = 0; k < NB; ++k) {
            lower += (k ? " L " : "M ") + num(xat(k + 1), 1) + "," +
                     num(yof(static_cast<double>(base[static_cast<size_t>(k)])), 1);
        }
        for (int k = NB - 1; k >= 0; --k) {
            upper += " L " + num(xat(k + 1), 1) + "," +
                     num(yof(static_cast<double>(base[static_cast<size_t>(k)] +
                                                b.series[static_cast<size_t>(k)])), 1);
        }
        std::string band = "M " + num(L, 1) + "," +
                           num(yof(static_cast<double>(base[0])), 1) + " L " +
                           lower.substr(2) + upper + " L " + num(L, 1) + "," +
                           num(yof(static_cast<double>(base[0] + b.series[0])), 1) + " Z";
        std::cout << "<path class=\"sl-stack\" style=\"fill:" << b.fill << ";fill-opacity:"
                  << num(b.fill_opacity, 2) << "\" d=\"" << band << "\"/>\n";
        for (int k = 0; k < NB; ++k) base[static_cast<size_t>(k)] += b.series[static_cast<size_t>(k)];
    }

    // The total, drawn over the stack so the silhouette stays crisp.
    std::string line;
    for (int k = 0; k < NB; ++k) {
        line += (line.empty() ? "M " : " L ") + num(xat(k + 1), 1) + "," +
                num(yof(static_cast<double>(total_per[static_cast<size_t>(k)])), 1);
    }
    std::cout << "<path class=\"sl-stack-total\" d=\"" << line << "\"/>\n";

    // One hover strip per slice, naming what the stack is made of there.
    for (int k = 0; k < NB; ++k) {
        const long long ta = t0 + static_cast<long long>(span * k / NB);
        std::string det = num(static_cast<double>(total_per[static_cast<size_t>(k)]), 0) + " error(s)";
        int shown = 0, hidden = 0;
        for (const auto& b : bands) {
            const long long v = b.series[static_cast<size_t>(k)];
            if (v <= 0) continue;
            if (shown >= 3) { hidden++; continue; }
            det += shown ? ", " : " — ";
            det += num(static_cast<double>(v), 0) + " \xc2\xb7 " + b.label;
            shown++;
        }
        if (hidden > 0) det += " (+" + std::to_string(hidden) + " more code(s))";
        std::cout << "<rect class=\"sl-hit\" x=\"" << num(xat(k), 1) << "\" y=\"" << num(T, 0)
                  << "\" width=\"" << num(xat(k + 1) - xat(k), 1) << "\" height=\"" << num(ph, 0)
                  << "\" data-x=\"" << xml_escape(format_epoch_seconds(ta))
                  << "\" data-y=\"" << xml_escape(det) << "\"/>\n";
    }

    print_coverage_lanes(lanes, t0, t1, L, pw, T, ph);
    print_nolog_hits(gaps, t0, t1, L, pw, T, ph);

    std::cout << "</svg>\n<div class=\"sl-tip\" hidden></div>\n";
    print_coverage_legend(lanes, gaps);
    // Legend in HTML rather than in the drawing: it wraps, and the bands are
    // read by name here (the colours alone would not say which code is which).
    std::cout << "<div class=\"sl-stack-legend\">";
    for (const auto& b : bands) {
        const std::string kind =
            b.code ? std::string("result class: ") + ldap_code_class_name(ldap_code_class(b.code))
                   : std::string("smaller codes, folded together");
        // b.fill is an SVG paint reference for the dual class, which means
        // nothing in HTML; the swatch draws the same hatch as a CSS gradient.
        const std::string bg = b.hatched ? hatch_background_css() : b.fill;
        std::cout << "<span class=\"sl-stack-key\" title=\"" << xml_escape(kind)
                  << "\"><i style=\"background:" << bg << ";opacity:" << num(b.fill_opacity, 2)
                  << "\"></i>" << xml_escape(b.label) << " — " << num(static_cast<double>(b.total), 0)
                  << " (" << share_text(100.0 * static_cast<double>(b.total) /
                                        static_cast<double>(grand)) << ")</span>";
    }
    std::cout << "</div>\n";
    std::cout << "</div>\n";
}

// ---- donuts ---------------------------------------------------------------

std::string metric(double v, bool seconds) {
    return seconds ? num(v, 1) + " s" : num(v, 0);
}

// A share is only readable at the scale it is read at.  Four significant digits
// do that uniformly: 63.4 %, 3.571 %, 99.98 % for the big ones, 0.008333 % and
// 0.0002097 % for a code seen three times in 1.4 M results — where "%.1f" would
// have said "0.0 %", and "%.1f" on 99.98 % would have claimed a whole 100 %.
std::string share_text(double pct) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.4g%%", pct);
    return buf;
}

// One donut slice: the label, the value the slice is sized by, an optional
// secondary line shown in the legend and the tooltip (e.g. operation count and
// average time per operation), an optional explicit paint — the result codes use
// their class colour so a slice matches its row in the table, or `url(#tag)` for
// the dual class, which is hatched — and the opacity of that paint, for the
// charts that shade a code by rank inside its class.
struct Slice {
    std::string label;
    double value = 0.0;
    std::string detail;
    std::string fill;
    double opacity = 1.0;
};

// Keep the largest `keep` entries, folding the rest into a single slice.
std::vector<Slice> keep_top(std::vector<Slice> rows, size_t keep, const char* other) {
    std::sort(rows.begin(), rows.end(), [](const Slice& a, const Slice& b) {
        if (a.value != b.value) return a.value > b.value;
        return a.label < b.label;                 // deterministic tie-break
    });
    if (rows.size() > keep) {
        double rest = 0.0;
        for (size_t i = keep; i < rows.size(); ++i) rest += rows[i].value;
        rows.resize(keep);
        if (rest > 0.0) rows.push_back({other, rest, "", ""});
    }
    return rows;
}

// The colour of one slice: its own when it carries one, a palette colour by
// position otherwise.  A slice with an opacity — the result-code breakdown shades
// each code by its rank inside its class — is emitted with fill-opacity beside it.
// An explicit value may be a paint reference (`url(#…)`), used for the hatched
// dual class; the pattern it names is emitted by whichever chart built the rows.
const char* slice_fill(const std::vector<Slice>& rows, size_t i) {
    return rows[i].fill.empty() ? PALETTE[i % PALETTE_N] : rows[i].fill.c_str();
}

std::string slice_style(const std::vector<Slice>& rows, size_t i) {
    std::string style = "fill:";
    style += slice_fill(rows, i);
    if (rows[i].opacity < 1.0) style += ";fill-opacity:" + num(rows[i].opacity, 2);
    return style;
}

// The wedges of one pie, drawn into the svg the caller has already opened.
// Split out of print_donut because a chart that already lists its codes — the
// result-code breakdown puts the pie beside its bars — wants the shape without a
// second legend.  Slices start at twelve o'clock and run clockwise, so they follow
// the rows of a list drawn top to bottom.
void print_pie_slices(const std::vector<Slice>& rows, double total,
                      double cx, double cy, double r, bool seconds) {
    double angle = -M_PI / 2;
    for (size_t i = 0; i < rows.size(); ++i) {
        const double frac = rows[i].value / total;
        const double a2 = angle + frac * 2.0 * M_PI;
        std::string what = metric(rows[i].value, seconds) + "  (" + share_text(frac * 100.0) + ")";
        if (!rows[i].detail.empty()) what += " — " + rows[i].detail;
        const std::string style = slice_style(rows, i);
        if (rows.size() == 1) {
            std::cout << "<circle class=\"sl-slice\" cx=\"" << num(cx, 0) << "\" cy=\"" << num(cy, 0)
                      << "\" r=\"" << num(r, 0) << "\" style=\"" << style << "\" data-x=\""
                      << xml_escape(rows[i].label) << "\" data-y=\"" << xml_escape(what) << "\"/>\n";
        } else {
            const double x1 = cx + r * std::cos(angle), y1 = cy + r * std::sin(angle);
            const double x2 = cx + r * std::cos(a2),    y2 = cy + r * std::sin(a2);
            std::cout << "<path class=\"sl-slice\" style=\"" << style << "\" d=\"M "
                      << num(cx, 0) << "," << num(cy, 0) << " L " << num(x1, 1) << "," << num(y1, 1)
                      << " A " << num(r, 0) << "," << num(r, 0) << " 0 " << (frac > 0.5 ? 1 : 0)
                      << " 1 " << num(x2, 1) << "," << num(y2, 1) << " Z\" data-x=\""
                      << xml_escape(rows[i].label) << "\" data-y=\"" << xml_escape(what) << "\"/>\n";
        }
        angle = a2;
    }
}

void print_donut(const std::string& title, const std::string& sub,
                 std::vector<Slice> rows, bool seconds,
                 const std::string& footnote = "") {
    double total = 0.0;
    for (const auto& r : rows) total += r.value;
    if (total <= 0.0 || rows.empty()) return;
    rows = keep_top(std::move(rows), 8, "other");

    const double cx = 190, cy = 150, r = 115, lx = 400;
    const double H = 300 + std::max(0.0, (static_cast<double>(rows.size()) - 8) * 24);

    std::cout << "<h2>" << xml_escape(title) << "</h2>\n<div class=\"sl-chart\">\n";
    std::cout << "<div class=\"sl-chart-sub\">" << xml_escape(sub) << "</div>\n";
    std::cout << "<svg viewBox=\"0 0 1000 " << num(H, 0) << "\" role=\"img\" aria-label=\""
              << xml_escape(title) << "\">\n";

    // A dual-class slice is painted with an SVG pattern, which must be defined in
    // this same svg.  The tag is read back from the fill the caller set, so the
    // defs are emitted exactly when — and only when — a slice actually needs them
    // (the folded "other" slice carries a plain colour and never a reference).
    for (const auto& r : rows) {
        if (r.fill.rfind("url(#", 0) != 0) continue;
        const std::string tag = r.fill.substr(5, r.fill.size() - 6);   // url(#tag) -> tag
        print_hatch_defs(tag.c_str());
        break;
    }

    print_pie_slices(rows, total, cx, cy, r, seconds);

    double ly = 30;
    for (size_t i = 0; i < rows.size(); ++i) {
        const double frac = rows[i].value / total;
        std::cout << "<rect x=\"" << num(lx, 0) << "\" y=\"" << num(ly - 9, 0)
                  << "\" width=\"12\" height=\"12\" rx=\"2\" style=\"" << slice_style(rows, i)
                  << "\"/>\n";
        std::string name = rows[i].label;
        if (name.size() > 40) name = name.substr(0, 37) + "...";
        std::cout << "<text class=\"sl-legend-name\" x=\"" << num(lx + 20, 0) << "\" y=\"" << num(ly, 0)
                  << "\">" << xml_escape(name) << "</text>\n";
        if (!rows[i].detail.empty()) {
            std::cout << "<text class=\"sl-legend-det\" x=\"800\" y=\"" << num(ly, 0)
                      << "\" text-anchor=\"end\">" << xml_escape(rows[i].detail) << "</text>\n";
        }
        std::cout << "<text class=\"sl-legend-val\" x=\"980\" y=\"" << num(ly, 0)
                  << "\" text-anchor=\"end\">"
                  << xml_escape(metric(rows[i].value, seconds) + "  (" + share_text(frac * 100.0) + ")")
                  << "</text>\n";
        ly += 24;
    }
    std::cout << "</svg>\n<div class=\"sl-tip\" hidden></div>";
    // A line under the legend, for what the donut deliberately does not show.
    if (!footnote.empty())
        std::cout << "\n<div class=\"sl-chart-note\">" << xml_escape(footnote) << "</div>";
    std::cout << "\n</div>\n";
}

// ---- the individual charts ------------------------------------------------

void print_account_chart(const Aggregator& agg) {
    // "Resource" means cumulative operation time (etime, in seconds); if the log
    // carries no timing at all, fall back to the operation count so the chart
    // still says something useful.  The detail line exposes the other
    // dimension: an account can top the chart through volume (many short
    // operations) or through weight (a few very long ones).
    double total_etime = 0.0;
    for (const auto& [name, ui] : agg.user_stats) total_etime += ui.etime_total;
    const bool by_etime = total_etime > 0.0;

    std::vector<Slice> rows;
    rows.reserve(agg.user_stats.size());
    for (const auto& [name, ui] : agg.user_stats) {
        const double v = by_etime ? ui.etime_total : static_cast<double>(ui.count);
        if (v <= 0.0) continue;
        std::string detail = num(static_cast<double>(ui.count), 0) + " ops";
        if (ui.count > 0 && ui.etime_total > 0.0) {
            const double avg_ms = ui.etime_total * 1000.0 / static_cast<double>(ui.count);
            detail += avg_ms >= 1000.0 ? " · " + num(avg_ms / 1000.0, 2) + " s/op"
                                       : " · " + num(avg_ms, 0) + " ms/op";
        }
        rows.push_back({name, v, detail, ""});
    }
    print_donut("Resource Consumers by Bind Account",
                by_etime ? "share of the cumulative operation time (etime)"
                         : "share of the operations",
                std::move(rows), by_etime);
}

// Load split across the servers the log names.  The same share donut as the
// other charts; only drawn when the log carries a hostname (syslog/rfc3339),
// which the debug format does not.  A cluster's logs are aggregated, and this
// is the one chart that says which server carried which part of it.
void print_server_chart(const Aggregator& agg) {
    std::vector<Slice> rows;
    for (const auto& [server, n] : agg.ops_by_server) {
        if (n <= 0) continue;
        rows.push_back({server, static_cast<double>(n),
                        std::to_string(n) + " operation(s)", ""});
    }
    if (rows.empty()) return;
    print_donut("Load by Server", "share of the operations each server handled",
                std::move(rows), false);
}

void print_optype_chart(const Aggregator& agg) {
    std::vector<Slice> rows;
    for (const auto& [op, count] : agg.operation_count) {
        if (count > 0) rows.push_back({op, static_cast<double>(count), "", ""});
    }
    if (rows.empty()) return;
    print_donut("Operation Types", "share of each operation type", std::move(rows), false);
}

// How clients authenticated, as a share of the BIND requests.  The detail line
// carries the transport split, because a reader who sees "simple" wants to know
// whether that simple bind ran in the clear or under TLS.
void print_bind_chart(const Aggregator& agg) {
    std::vector<Slice> rows;
    for (const auto& [method, count] : agg.bind_method_count) {
        if (count <= 0) continue;
        rows.push_back({method, static_cast<double>(count),
                        std::to_string(count) + " bind(s)", ""});
    }
    if (rows.empty()) return;
    long long over_tls = 0;
    for (const auto& [transport, n] : agg.bind_transport_count) {
        if (transport != "ldap") over_tls += n;
    }
    print_donut("Bind Usage", "share of each authentication method",
                std::move(rows), false,
                std::to_string(over_tls) + " of " + std::to_string(agg.bind_total) +
                    " bind(s) ran over TLS (ldaps or ldap + StartTLS)");
}

// The donut answers "of what failed, what failed how?", so it holds the failing
// codes only.  The informational ones (success, both Compare answers, a
// referral, saslBindInProgress) are counted and named in the footnote instead:
// on the real 1 GiB log the Compare answers alone were 48 % of the slices, so
// the donut read as if the directory failed twice as often as it did.
void print_error_chart(const Aggregator& agg) {
    std::vector<Slice> rows;
    long long normal = 0;                    // informational results left out
    std::string normal_what;                 // …and which codes they were
    for (const auto& [code, count] : agg.error_count) {
        if (count <= 0) continue;
        const LdapCodeClass cls = ldap_code_class(code);
        if (cls == LdapCodeClass::Info) {
            normal += count;
            if (!normal_what.empty()) normal_what += ", ";
            normal_what += std::to_string(code) + " " + ldap_error_name(code);
            continue;
        }
        // Every failing slice carries its class paint, so the donut reads like
        // the table above it: amber = what the client asked, violet = what the
        // configuration refuses, amber-over-violet hatch = a refusal the log
        // cannot attribute, red = what slapd failed to do.
        rows.push_back({std::to_string(code) + " " + ldap_error_name(code),
                        static_cast<double>(count), ldap_code_class_name(cls),
                        class_fill(cls, HATCH_TAG_DONUT)});
    }
    if (rows.empty()) return;
    std::string footnote;
    if (normal > 0) {
        footnote = std::to_string(normal) +
                   " further result(s) are not failures and are left out here: " +
                   normal_what + ".";
    }
    print_donut("Failing Result Codes", "share of each result code other than information",
                std::move(rows), false, footnote);
}

// Response time distribution: one bar per etime bucket, each labelled with its
// exact count and share.  A cumulative curve used to run down the right-hand side
// with its own 0-100 % axis; it was removed because the bars beside it already say
// everything the curve divided by itself, and a reader could not tell what the
// percentages referred to (every row past the second reads 100 % — the buckets are
// ordered, so the sum saturates immediately).  The bars now have the width the
// curve and its label column used to take.
void print_latency_chart(const Aggregator& agg) {
    static const char* LABELS[OP_ETIME_BUCKETS] = {
        "0 ms", "<= 1 ms", "1-5 ms", "5-10 ms", "10-50 ms", "50-100 ms",
        "100-500 ms", "0.5-1 s", "1-2 s", "2-5 s", "> 5 s"};

    std::vector<std::pair<std::string, double>> rows;
    double total = 0.0;
    for (int i = 0; i < OP_ETIME_BUCKETS; ++i) {
        total += static_cast<double>(agg.op_etime_hist[i]);
        if (agg.op_etime_hist[i] > 0) {
            rows.emplace_back(LABELS[i], static_cast<double>(agg.op_etime_hist[i]));
        }
    }
    if (rows.empty() || total <= 0.0) return;
    double maxv = 0.0;
    for (const auto& r : rows) maxv = std::max(maxv, r.second);

    const double rowH = 26, top = 36, bot = 12;
    const double LAB_R = 118;                    // labels, right-aligned here
    const double BX0 = 130, BX1 = 780;           // bar area, the freed width included
    const double H = top + static_cast<double>(rows.size()) * rowH + bot;

    std::cout << "<h2>Response Time Distribution</h2>\n<div class=\"sl-chart\">\n";
    std::cout << "<div class=\"sl-chart-sub\">" << num(total, 0)
              << " completed operation(s) — bars: operations per etime bucket, "
                 "each with its share of the total</div>\n";
    std::cout << "<svg viewBox=\"0 0 1000 " << num(H, 0) << "\" role=\"img\" "
                 "aria-label=\"Response time distribution\">\n";

    // The bars, each with its exact count and share written after it: between them
    // they answer the question the removed curve was there for ("how many finish
    // under X") without a second reading axis to misread.
    for (size_t i = 0; i < rows.size(); ++i) {
        const double y = top + static_cast<double>(i) * rowH;
        const double cy = y + rowH / 2.0;
        const double w = (rows[i].second / maxv) * (BX1 - BX0);
        const double share = rows[i].second / total;

        std::cout << "<text class=\"sl-tick\" x=\"" << num(LAB_R, 0) << "\" y=\"" << num(cy + 4, 1)
                  << "\" text-anchor=\"end\">" << xml_escape(rows[i].first) << "</text>\n";
        std::cout << "<rect class=\"sl-bar\" x=\"" << num(BX0, 0) << "\" y=\"" << num(y + 6, 0)
                  << "\" width=\"" << num(w, 1) << "\" height=\"14\" rx=\"2\"/>\n";
        std::cout << "<text class=\"sl-legend-val\" x=\"" << num(BX0 + w + 8, 0) << "\" y=\""
                  << num(cy + 4, 1) << "\">"
                  << xml_escape(num(rows[i].second, 0) + "  (" + share_text(share * 100.0) + ")")
                  << "</text>\n";

        // One hover target per row, over the whole width: there is no second
        // reading to tell apart any more.
        std::cout << "<rect class=\"sl-hit\" x=\"0\" y=\"" << num(y, 0) << "\" width=\"1000\""
                  << " height=\"" << num(rowH, 0) << "\" data-x=\""
                  << xml_escape(rows[i].first) << "\" data-y=\""
                  << xml_escape(num(rows[i].second, 0) + " ops (" + share_text(share * 100.0) + ")")
                  << "\"/>\n";
    }

    std::cout << "</svg>\n<div class=\"sl-tip\" hidden></div>\n";
    std::cout << "</div>\n";
}

// Axis label of a decade of the logarithmic time axis: 10^-3 ms is 1 us, 10^3 ms
// is 1 s, and so on.
std::string etime_axis_label(int decade) {
    char buf[24];
    if (decade < 0)       std::snprintf(buf, sizeof(buf), "%g \xc2\xb5s", std::pow(10.0, decade + 3));
    else if (decade == 0) std::snprintf(buf, sizeof(buf), "1 ms");
    else if (decade < 3)  std::snprintf(buf, sizeof(buf), "%g ms", std::pow(10.0, decade));
    else                  std::snprintf(buf, sizeof(buf), "%g s", std::pow(10.0, decade - 3));
    return buf;
}

// The *shape* of the operation-time distribution, which the histogram above
// cannot show.  On a real 1 GiB access log 99.9992 % of the operations finish
// under 1 ms, so that chart is one tall bar and one sliver: a reader can tell
// neither a tight latency from a spread-out one, nor see a second hump.  Here
// the bins are equal on a logarithmic scale and the window follows the data, so
// the shape appears at the scale where the traffic actually is.
//
// It is also the only axis on which a "bell" has ever been legitimate: a
// log-normal latency — the usual model — is a bell *in log space* and looks
// nothing like one on a linear axis.  The curve drawn is the real density and
// not a fitted normal: if the traffic were log-normal it would look like a bell
// here, and where it shows two humps, that is the finding, not a defect.
void print_latency_density_chart(const Aggregator& agg) {
    int first = -1, last = -1;
    long long total = 0, maxc = 0;
    for (int i = 0; i < ETIME_LOG_BINS; ++i) {
        const long long c = agg.op_etime_log_hist[i];
        total += c;
        if (c > 0) {
            if (first < 0) first = i;
            last = i;
            if (c > maxc) maxc = c;
        }
    }
    if (first < 0 || total <= 0 || maxc <= 0) return;

    const double step = 1.0 / ETIME_LOG_BINS_PER_DECADE;
    const double logmin = std::log10(ETIME_LOG_MIN_MS);
    // Half a decade of margin on each side, so the profile comes back down to
    // the baseline instead of being cut by the frame.
    const double xlo = logmin + (first - 0.5) * step;
    const double xhi = logmin + (last + 1.5) * step;
    const double L = 84, R = 962, T = 34, B = 254;
    auto X = [&](double logms) { return L + (logms - xlo) / (xhi - xlo) * (R - L); };
    auto Y = [&](double c) { return B - (c / static_cast<double>(maxc)) * (B - T); };
    auto lower = [&](int bin) { return logmin + bin * step; };

    std::cout << "<h2>Response Time Density</h2>\n<div class=\"sl-chart\">\n";
    std::cout << "<div class=\"sl-chart-sub\">" << num(static_cast<double>(total), 0)
              << " operation(s) &middot; one point per bin, each bin "
              << num(std::pow(10.0, step), 2) << "&times; wider in time than the one before "
                 "&middot; logarithmic x axis</div>\n";
    std::cout << "<svg viewBox=\"0 0 1000 300\" role=\"img\" "
                 "aria-label=\"Operation time distribution on a logarithmic scale\">\n";

    // Horizontal grid: the baseline, the middle, and the tallest bin.
    for (int g = 0; g <= 2; ++g) {
        const double c = static_cast<double>(maxc) * g / 2.0;
        std::cout << "<line class=\"sl-grid\" x1=\"" << num(L, 0) << "\" y1=\"" << num(Y(c), 1)
                  << "\" x2=\"" << num(R, 0) << "\" y2=\"" << num(Y(c), 1) << "\"/>\n";
        std::cout << "<text class=\"sl-tick\" x=\"" << num(L - 8, 0) << "\" y=\""
                  << num(Y(c) + 4, 1) << "\" text-anchor=\"end\">" << num(c, 0) << "</text>\n";
    }
    std::cout << "<line class=\"sl-axis\" x1=\"" << num(L, 0) << "\" y1=\"" << num(B, 0)
              << "\" x2=\"" << num(R, 0) << "\" y2=\"" << num(B, 0) << "\"/>\n";

    // A tick per decade present in the window.
    for (int d = -3; d <= 4; ++d) {
        if (d < xlo || d > xhi) continue;
        const double x = X(d);
        std::cout << "<line class=\"sl-axis\" x1=\"" << num(x, 1) << "\" y1=\"" << num(B, 0)
                  << "\" x2=\"" << num(x, 1) << "\" y2=\"" << num(B + 5, 0) << "\"/>\n";
        std::cout << "<text class=\"sl-tick\" x=\"" << num(x, 1) << "\" y=\"" << num(B + 20, 0)
                  << "\" text-anchor=\"middle\">" << etime_axis_label(d) << "</text>\n";
    }

    // The profile: one point per bin that holds something, at its centre, and an
    // area closed down to the baseline at both edges of the window.  The bins
    // outside [first, last] are empty by definition, and mapping them would push
    // their points past the plot box (the window is only 0.5 decade wider than
    // the data), so they are simply not walked.
    std::string line;
    for (int i = first; i <= last; ++i) {
        const double xc = X(lower(i) + step / 2.0);
        const double y = Y(static_cast<double>(agg.op_etime_log_hist[i]));
        line += (i == first ? "M " : " L ") + num(xc, 1) + "," + num(y, 1);
    }
    std::cout << "<path class=\"sl-density-area\" d=\"M " << num(L, 1) << "," << num(B, 0)
              << " L " << num(X(lower(first) + step / 2.0), 1) << "," << num(B, 0) << " L "
              << line.substr(2) << " L " << num(X(lower(last) + step / 2.0), 1) << "," << num(B, 0)
              << " L " << num(R, 1) << "," << num(B, 0) << " Z\"/>\n";
    std::cout << "<path class=\"sl-density-line\" d=\"" << line << "\"/>\n";
    for (int i = first; i <= last; ++i) {
        if (agg.op_etime_log_hist[i] <= 0) continue;
        std::cout << "<circle class=\"sl-density-dot\" cx=\"" << num(X(lower(i) + step / 2.0), 1)
                  << "\" cy=\"" << num(Y(static_cast<double>(agg.op_etime_log_hist[i])), 1)
                  << "\" r=\"2.6\"/>\n";
    }

    // One hover target per bin the plot shows, tooltip included.  The loop starts
    // at the bottom bin and runs one past the last populated one, because the
    // window is padded on both sides: clamping to [L, R] then makes the whole
    // plot hoverable.  The first strip reaches the left edge because everything
    // under 1 us was binned there, and an empty bin reports zero rather than
    // nothing — silence is also an answer.
    const int hover_last = last + 1 < ETIME_LOG_BINS ? last + 1 : last;
    for (int i = 0; i <= hover_last; ++i) {
        double x0 = X(lower(i)), x1 = X(lower(i + 1));
        if (i == 0) x0 = L;                     // nothing exists before that bin
        if (x0 < L) x0 = L;
        if (x1 > R) x1 = R;
        if (x1 <= x0) continue;
        const long long c = agg.op_etime_log_hist[i];
        char buf[160];
        if (i == 0) {
            // The first bin catches the operations the log itself could not time
            // (etime=0): saying so is the difference between a readable chart and
            // a mysterious tower at the left edge.
            std::snprintf(buf, sizeof(buf), "%lld operation(s) at 0 or under 1 \xc2\xb5s (%s)",
                          c, share_text(100.0 * static_cast<double>(c) / total).c_str());
        } else {
            std::snprintf(buf, sizeof(buf), "%lld operation(s) between %s and %s (%s)", c,
                          format_etime_log_bin(i).c_str(), format_etime_log_bin(i + 1).c_str(),
                          share_text(100.0 * static_cast<double>(c) / total).c_str());
        }
        std::cout << "<rect class=\"sl-hit\" x=\"" << num(x0, 1) << "\" y=\"" << num(T, 0)
                  << "\" width=\"" << num(x1 - x0, 1) << "\" height=\""
                  << num(B - T, 0) << "\" data-x=\"" << etime_axis_label(i / ETIME_LOG_BINS_PER_DECADE)
                  << " decade\" data-y=\"" << xml_escape(buf) << "\"/>\n";
    }

    std::cout << "</svg>\n<div class=\"sl-tip\" hidden></div>\n";
    std::cout << "</div>\n";
}

// Every result code present in the log, successful ones included.  This is the
// chart that answers "what did this directory actually answer?" — the donut
// further down answers the narrower "of what failed, what failed how?".
//
// Two deliberate choices:
//   • bars are on a log scale.  Counts here span five orders of magnitude
//     (907 111 successes against 3 adminLimitExceeded on the reference log) and
//     a linear scale would leave every code but the first invisible; each bar
//     therefore carries its exact count and share, and the scale under the bars
//     says the axis is logarithmic.
//   • the pie on the right draws the same codes — same order, same colours — as
//     areas: one huge slice, then crumbs.  It is the only "distribution" a
//     categorical variable has, and it says the same thing as the cumulative bars
//     it replaces (on the reference log the first two codes already cover 81 % of
//     all results) without an axis, a curve, or a note to explain it.  A bell
//     curve would need a continuous, symmetric variable; result codes are neither.
void print_result_code_chart(const Aggregator& agg) {
    std::vector<Slice> rows;
    long long total = 0;
    bool any_hatch = false;
    for (const auto& [code, count] : agg.error_count) {
        if (count <= 0) continue;
        total += count;
        const LdapCodeClass cls = ldap_code_class(code);
        any_hatch = any_hatch || cls == LdapCodeClass::PolicyOrClient;
        rows.push_back({std::to_string(code) + " " + ldap_error_name(code),
                        static_cast<double>(count), ldap_code_class_name(cls),
                        class_fill(cls, HATCH_TAG_BREAKDOWN)});
    }
    if (rows.empty() || total <= 0) return;
    // Same order as the table above (most frequent first), so the two read
    // together without a mental reversal — and the pie starts at twelve o'clock
    // and turns clockwise, which is that same order.
    std::sort(rows.begin(), rows.end(), [](const Slice& a, const Slice& b) {
        if (a.value != b.value) return a.value > b.value;
        return a.label < b.label;                 // deterministic tie-break
    });

    // One colour per code, shaded by rank inside its class, so two codes of the
    // same class stay distinguishable — and so the colour a code shows on its bar
    // is the colour of its slice.  The label starts with the code, which is how it
    // was built three lines up.
    {
        int rank_by_class[5] = {0, 0, 0, 0, 0};
        for (auto& r : rows) {
            const LdapCodeClass row_cls = ldap_code_class(std::stoi(r.label));
            const int rank = rank_by_class[static_cast<int>(row_cls)]++;
            r.opacity = CLASS_SHADES[rank < 4 ? rank : 3];
        }
    }

    const double rowH = 24, top = 30, bot = 28;   // bot leaves room for the bar axis
    const double LAB_X = 8;                      // labels, left-aligned here
    const double BX0 = 215, BX1 = 560;           // bar area (log scale)
    const double PIE_X = 700;                    // the pie owns everything right of here
    // Tall enough for a readable pie even when only two codes were ever seen.
    const double H = std::max(250.0, top + static_cast<double>(rows.size()) * rowH + bot);
    const double y_end = top + static_cast<double>(rows.size()) * rowH;
    const double maxv = rows.front().value;
    const double lmax = std::log10(maxv);
    const bool use_log = lmax > 1.0;             // below that, log says nothing

    std::cout << "<h2>Result Code Breakdown</h2>\n<div class=\"sl-chart\">\n";
    std::cout << "<div class=\"sl-chart-sub\">" << num(static_cast<double>(total), 0)
              << " result(s) &middot; bars: "
              << (use_log ? "log scale (one step = &times;10, axis labelled under the bars)"
                          : "share of the busiest code (axis labelled under the bars)")
              << ", coloured by who is at fault (see the key above) &middot; right: the same codes "
                 "as one pie, biggest slice first"
              << "</div>\n";
    std::cout << "<svg viewBox=\"0 0 1000 " << num(H, 0) << "\" role=\"img\" "
                 "aria-label=\"Every LDAP result code, by volume\">\n";
    // The hatch pattern, for the bars and the pie slices of the dual class — and
    // only for them: emitted here, in this svg, because a paint reference is
    // resolved per drawing.
    if (any_hatch) print_hatch_defs(HATCH_TAG_BREAKDOWN);

    // Scale of the bars, without which the drawing cannot be read: a bar's
    // length is a logarithm, so the steps are decades — one look says "each step
    // is ten times the one before" — or quarters of the busiest code when the
    // range is too small for a log to mean anything.  The exact count is written
    // beside each bar, so the axis only has to give the structure.
    {
        auto short_count = [](double v) {
            const char* suffix = "";
            if (v >= 1e6)      { v /= 1e6; suffix = "M"; }
            else if (v >= 1e3) { v /= 1e3; suffix = "k"; }
            // A decimal only where it carries something: "1.5k", never "1.0k".
            const bool carries = v < 100.0 && std::fabs(v - std::floor(v)) > 0.05;
            return num(v, carries ? 1 : 0) + suffix;
        };
        // A step is a decade.  The top of the scale is the busiest code, which is
        // rarely a round power of ten — so the position comes from the bars' own
        // mapping (log10(v) / log10(max)), never an even spread, which would put
        // "100k" under a bar of 907k.  When the busiest code is under 10 the whole
        // axis is a handful of counts, and then each integer gets its own step.
        std::vector<std::pair<double, std::string>> ticks;   // (fraction, label)
        if (use_log) {
            for (int k = 0; k <= static_cast<int>(std::floor(lmax)); ++k)
                ticks.emplace_back(static_cast<double>(k) / lmax, short_count(std::pow(10.0, k)));
        } else {
            for (int k = 0; k <= static_cast<int>(maxv); ++k)
                ticks.emplace_back(static_cast<double>(k) / maxv, num(k, 0));
        }
        for (size_t i = 0; i < ticks.size(); ++i) {
            const double x = BX0 + ticks[i].first * (BX1 - BX0);
            std::cout << "<line class=\"sl-grid\" x1=\"" << num(x, 1) << "\" y1=\"" << num(top - 14, 0)
                      << "\" x2=\"" << num(x, 1) << "\" y2=\"" << num(y_end, 0) << "\"/>\n";
            std::cout << "<text class=\"sl-tick\" x=\"" << num(x, 1) << "\" y=\"" << num(y_end + 15, 0)
                      << "\" text-anchor=\"" << (i == 0 ? "start" : "middle") << "\">"
                      << ticks[i].second << "</text>\n";
        }
        std::cout << "<line class=\"sl-axis\" x1=\"" << num(BX0, 0) << "\" y1=\"" << num(y_end, 0)
                  << "\" x2=\"" << num(BX1, 0) << "\" y2=\"" << num(y_end, 0) << "\"/>\n";
    }

    for (size_t i = 0; i < rows.size(); ++i) {
        const double y = top + static_cast<double>(i) * rowH;
        const double cy = y + rowH / 2.0;
        const double frac = use_log ? std::log10(rows[i].value) / lmax
                                    : rows[i].value / maxv;
        double w = frac * (BX1 - BX0);
        if (w < 3.0) w = 3.0;                    // a single occurrence stays visible
        const double share = rows[i].value / static_cast<double>(total);

        // The label is text, and a hatch over text is unreadable: the dual class
        // keeps its plain class colour (violet) for the label while its bar and
        // its slice carry the pattern.  The code is the first word of the label,
        // which is how it was built.
        const LdapCodeClass row_cls = ldap_code_class(std::stoi(rows[i].label));
        std::cout << "<text class=\"sl-legend-name\" x=\"" << num(LAB_X, 0) << "\" y=\""
                  << num(cy + 4, 1) << "\" style=\"fill:" << ldap_code_class_color(row_cls) << "\">"
                  << xml_escape(rows[i].label) << "</text>\n";
        std::cout << "<rect class=\"sl-bar\" x=\"" << num(BX0, 0) << "\" y=\"" << num(y + 5, 0)
                  << "\" width=\"" << num(w, 1) << "\" height=\"14\" rx=\"2\" style=\"fill:"
                  << rows[i].fill << ";fill-opacity:" << num(rows[i].opacity, 2) << "\"/>\n";
        std::cout << "<text class=\"sl-legend-val\" x=\"" << num(BX0 + w + 8, 0) << "\" y=\""
                  << num(cy + 4, 1) << "\">"
                  << xml_escape(num(rows[i].value, 0) + "  " + share_text(share * 100.0))
                  << "</text>\n";

        // One hover target per row, over the label and the bar only: the pie
        // carries its own, slice by slice.
        std::cout << "<rect class=\"sl-hit\" x=\"0\" y=\"" << num(y, 0) << "\" width=\""
                  << num(PIE_X - 6, 0) << "\" height=\"" << num(rowH, 0) << "\" data-x=\""
                  << xml_escape(rows[i].label) << "\" data-y=\""
                  << xml_escape(num(rows[i].value, 0) + " result(s), " +
                                share_text(share * 100.0) + " of all — " + rows[i].detail)
                  << "\"/>\n";
    }

    // The pie: the same codes, same order, same colours, drawn by area.  One huge
    // slice and a tail of slivers is the entire reading — that is what a
    // result-code distribution looks like, and it needs no axis and no note.
    print_pie_slices(rows, static_cast<double>(total), 830, H / 2.0,
                     std::min(115.0, H / 2.0 - 16.0), false);

    std::cout << "</svg>\n<div class=\"sl-tip\" hidden></div>\n";
    std::cout << "</div>\n";
}

} // namespace

bool html_charts_available(const Aggregator& agg) {
    // --no-graph (and any non-HTML output) clears the graph aggregates and must
    // also silence the charts fed by counts that exist either way (operation
    // types, result codes), so the flag is tested explicitly rather than relying
    // on those aggregates happening to be empty.
    if (!collect_graph_data_enabled()) return false;
    long long hist = 0;
    for (int i = 0; i < OP_ETIME_BUCKETS; ++i) hist += agg.op_etime_hist[i];
    return !agg.conn_timeline.empty() || !agg.user_stats.empty() ||
           !agg.error_times_by_code.empty() || hist > 0 ||
           !agg.error_count.empty() || !agg.operation_count.empty();
}

void print_html_chart_style() { print_chart_style(); }
void print_html_chart_script() { print_chart_script(); }

void print_html_chart(const Aggregator& agg, HtmlChart which) {
    // Nothing to draw at all — this is also what makes --no-graph suppress every
    // chart, including the two whose aggregates (operation and result-code
    // counts) exist regardless of the graph flag.
    if (!html_charts_available(agg)) return;

    switch (which) {
        case HtmlChart::Connections:
            print_connection_chart(agg);
            break;

        case HtmlChart::ErrorsOverTime: {
            if (agg.error_times_by_code.empty()) break;
            // Same time window as the connection chart, so the two curves can be
            // read against each other; falls back to the analysed range when the
            // timeline is not available.
            long long t0 = 0, t1 = 0;
            bool have = false;
            for (const auto& e : agg.conn_timeline) {
                t0 = have ? std::min(t0, e.t) : e.t;
                t1 = have ? std::max(t1, e.t) : e.t;
                have = true;
            }
            if (auto a = ts_epoch_seconds(agg.firsttime)) {
                t0 = have ? std::min(t0, *a) : *a;
                t1 = have ? std::max(t1, *a) : *a;
                have = true;
            }
            if (auto b = ts_epoch_seconds(agg.lasttime)) {
                t0 = have ? std::min(t0, *b) : *b;
                t1 = have ? std::max(t1, *b) : *b;
                have = true;
            }
            if (!have) break;
            // The series holds the failing results only (see log_parser.cpp), so
            // the subtitle says so: this curve must never be read as "everything
            // that was not a success", which is what it used to show.
            long long failing = 0;
            for (const auto& [code, count] : agg.error_count) {
                if (ldap_code_is_error(code)) failing += count;
            }
            print_error_series_chart(
                agg, t0, t1,
                std::to_string(failing) +
                    " failing result(s) \xc2\xb7 stacked by result code \xc2\xb7 the "
                    "informational ones (success, Compare answers, referral, …) are not plotted");
            break;
        }

        case HtmlChart::Latency:
            print_latency_chart(agg);
            break;

        case HtmlChart::LatencyDensity:
            print_latency_density_chart(agg);
            break;

        case HtmlChart::Accounts:
            print_account_chart(agg);
            break;

        case HtmlChart::LoadByServer:
            print_server_chart(agg);
            break;

        case HtmlChart::OperationTypes:
            print_optype_chart(agg);
            break;

        case HtmlChart::BindMethod:
            print_bind_chart(agg);
            break;

        case HtmlChart::ResultCodeBreakdown:
            print_result_code_chart(agg);
            break;

        case HtmlChart::ResultCodes:
            print_error_chart(agg);
            break;
    }
}
