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

#include "html_chart.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <iostream>
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
    std::snprintf(buf, sizeof(buf), decimals == 0 ? "%.0f" : "%.1f", v);
    return buf;
}

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
  .sl-chart{background:#fff;border-radius:6px;padding:14px 20px 10px;margin:0 0 18px;position:relative}
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
  .sl-legend-name{fill:#2c3e50;font-size:12.5px}
  .sl-legend-val{fill:#7f8c9b;font-size:12.5px;font-family:'Consolas','Courier New',monospace}
  .sl-tip{position:absolute;pointer-events:none;background:#2c3e50;color:#ecf0f1;border-radius:5px;
          padding:4px 9px;font-size:12px;white-space:nowrap;transform:translate(12px,-50%);z-index:9;
          box-shadow:0 2px 6px rgba(0,0,0,.25)}
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

// ---- simultaneous connections --------------------------------------------

void print_connection_chart(const Aggregator& agg) {
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

    // SVG geometry
    const double W = 1000, H = 300, L = 68, R = 14, T = 14, B = 34;
    const double pw = W - L - R, ph = H - T - B;
    auto xof = [&](long long t) { return L + (static_cast<double>(t - t0) / span) * pw; };
    auto yof = [&](double v) { return T + ph - (v / static_cast<double>(ytop)) * ph; };

    std::cout << "<h2>Simultaneous Connections</h2>\n";
    std::cout << "<div class=\"sl-chart\">\n";
    std::cout << "<div class=\"sl-chart-sub\">" << xml_escape(agg.firsttime)
              << " &rarr; " << xml_escape(agg.lasttime)
              << " &middot; peak " << peak << " connection(s)</div>\n";
    std::cout << "<svg viewBox=\"0 0 1000 300\" role=\"img\" "
                 "aria-label=\"Simultaneous connections over time\">\n";

    // horizontal grid + y labels
    for (long long v = 0; v <= ytop; v += static_cast<long long>(step)) {
        const double y = yof(static_cast<double>(v));
        std::cout << "<line class=\"sl-grid\" x1=\"" << num(L, 0) << "\" y1=\"" << num(y, 1)
                  << "\" x2=\"" << num(W - R, 0) << "\" y2=\"" << num(y, 1) << "\"/>\n";
        std::cout << "<text class=\"sl-tick\" x=\"" << num(L - 8, 0) << "\" y=\"" << num(y + 4, 1)
                  << "\" text-anchor=\"end\">" << v << "</text>\n";
    }
    // vertical grid + x labels
    const int XT = 5;
    for (int i = 0; i <= XT; ++i) {
        const long long t = t0 + static_cast<long long>(span * i / XT);
        const double x = xof(t);
        std::cout << "<line class=\"sl-grid\" x1=\"" << num(x, 1) << "\" y1=\"" << num(T, 0)
                  << "\" x2=\"" << num(x, 1) << "\" y2=\"" << num(T + ph, 0) << "\"/>\n";
        std::cout << "<text class=\"sl-tick\" x=\"" << num(x, 1) << "\" y=\"" << num(H - 12, 0)
                  << "\" text-anchor=\"middle\">" << xml_escape(format_epoch_seconds(t)) << "</text>\n";
    }
    std::cout << "<line class=\"sl-axis\" x1=\"" << num(L, 0) << "\" y1=\"" << num(T + ph, 0)
              << "\" x2=\"" << num(W - R, 0) << "\" y2=\"" << num(T + ph, 0) << "\"/>\n";

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

    // server start/stop markers
    for (const auto& [ts, what] : agg.server_event_list) {
        auto t = ts_epoch_seconds(ts);
        if (!t || *t < t0 || *t > t1) continue;
        const bool start = what.rfind("slapd starting", 0) == 0;
        const double x = xof(*t);
        std::cout << "<line class=\"sl-ev-line " << (start ? "sl-ev-start" : "sl-ev-stop")
                  << "\" x1=\"" << num(x, 1) << "\" y1=\"" << num(T, 0)
                  << "\" x2=\"" << num(x, 1) << "\" y2=\"" << num(T + ph, 0) << "\"/>\n";
        std::cout << "<circle class=\"" << (start ? "sl-ev-dot-start" : "sl-ev-dot-stop")
                  << "\" cx=\"" << num(x, 1) << "\" cy=\"" << num(T + 5, 0) << "\" r=\"4\"/>\n";
        std::cout << "<rect class=\"sl-hit\" x=\"" << num(x - 4, 1) << "\" y=\"" << num(T, 0)
                  << "\" width=\"8\" height=\"" << num(ph, 0)
                  << "\" data-x=\"" << xml_escape(format_epoch_seconds(*t))
                  << "\" data-y=\"" << xml_escape(what) << "\"/>\n";
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

    std::cout << "</svg>\n<div class=\"sl-tip\" hidden></div>\n</div>\n";
}

// ---- resource consumers by bind account ----------------------------------

void print_account_chart(const Aggregator& agg) {
    // "Resource" means cumulative operation time (etime); if the log carries no
    // timing at all, fall back to the operation count so the chart still says
    // something useful.
    double total_etime = 0.0;
    long long total_count = 0;
    for (const auto& [name, ui] : agg.user_stats) {
        total_etime += ui.etime_total;
        total_count += ui.count;
    }
    const bool by_etime = total_etime > 0.0;
    const double total = by_etime ? total_etime : static_cast<double>(total_count);
    if (total <= 0.0) return;

    std::vector<std::pair<std::string, double>> rows;
    rows.reserve(agg.user_stats.size());
    for (const auto& [name, ui] : agg.user_stats) {
        const double v = by_etime ? ui.etime_total : static_cast<double>(ui.count);
        if (v > 0.0) rows.emplace_back(name, v);
    }
    if (rows.empty()) return;
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;             // deterministic tie-break
    });

    const size_t MAXS = 8;
    if (rows.size() > MAXS) {
        double rest = 0.0;
        for (size_t i = MAXS; i < rows.size(); ++i) rest += rows[i].second;
        rows.resize(MAXS);
        rows.emplace_back("other accounts", rest);
    }

    static const char* PALETTE[] = {"#3498db", "#e67e22", "#27ae60", "#9b59b6",
                                    "#e74c3c", "#16a085", "#f1c40f", "#7f8c8d",
                                    "#34495e"};

    const double cx = 190, cy = 170, r = 130;
    std::cout << "<h2>Resource Consumers by Bind Account</h2>\n";
    std::cout << "<div class=\"sl-chart\">\n";
    std::cout << "<div class=\"sl-chart-sub\">share of "
              << (by_etime ? "cumulative operation time (etime)" : "operations")
              << " over " << rows.size() << " account(s)</div>\n";
    std::cout << "<svg viewBox=\"0 0 1000 340\" role=\"img\" "
                 "aria-label=\"Resource consumers by bind account\">\n";

    // slices, starting at 12 o'clock and going clockwise
    double angle = -M_PI / 2;
    for (size_t i = 0; i < rows.size(); ++i) {
        const double frac = rows[i].second / total;
        const double sweep = frac * 2.0 * M_PI;
        const double a2 = angle + sweep;
        const std::string what = by_etime ? num(rows[i].second, 1) + " s" : num(rows[i].second, 0) + " ops";
        const std::string pct = num(frac * 100.0, 1) + "%";

        if (rows.size() == 1) {
            std::cout << "<circle class=\"sl-slice\" cx=\"" << num(cx, 0) << "\" cy=\"" << num(cy, 0)
                      << "\" r=\"" << num(r, 0) << "\" fill=\"" << PALETTE[0] << "\""
                      << " data-x=\"" << xml_escape(rows[i].first)
                      << "\" data-y=\"" << xml_escape(what + " (" + pct + ")") << "\"/>\n";
        } else {
            const double x1 = cx + r * std::cos(angle), y1 = cy + r * std::sin(angle);
            const double x2 = cx + r * std::cos(a2),    y2 = cy + r * std::sin(a2);
            const int large = sweep > M_PI ? 1 : 0;
            std::cout << "<path class=\"sl-slice\" fill=\"" << PALETTE[i % 9] << "\" d=\"M "
                      << num(cx, 0) << "," << num(cy, 0) << " L " << num(x1, 1) << "," << num(y1, 1)
                      << " A " << num(r, 0) << "," << num(r, 0) << " 0 " << large << " 1 "
                      << num(x2, 1) << "," << num(y2, 1) << " Z\""
                      << " data-x=\"" << xml_escape(rows[i].first)
                      << "\" data-y=\"" << xml_escape(what + " (" + pct + ")") << "\"/>\n";
        }
        angle = a2;
    }

    // legend
    const double lx = 400;
    double ly = 34;
    for (size_t i = 0; i < rows.size(); ++i) {
        const double frac = rows[i].second / total;
        const std::string what = by_etime ? num(rows[i].second, 1) + " s" : num(rows[i].second, 0) + " ops";
        std::cout << "<rect x=\"" << num(lx, 0) << "\" y=\"" << num(ly - 9, 0)
                  << "\" width=\"12\" height=\"12\" rx=\"2\" fill=\"" << PALETTE[i % 9] << "\"/>\n";
        std::string name = rows[i].first;
        if (name.size() > 46) name = name.substr(0, 43) + "...";
        std::cout << "<text class=\"sl-legend-name\" x=\"" << num(lx + 20, 0) << "\" y=\""
                  << num(ly, 0) << "\">" << xml_escape(name) << "</text>\n";
        std::cout << "<text class=\"sl-legend-val\" x=\"" << num(980, 0) << "\" y=\"" << num(ly, 0)
                  << "\" text-anchor=\"end\">" << xml_escape(what + "  ("
                  + num(frac * 100.0, 1) + "%)") << "</text>\n";
        ly += 26;
    }

    std::cout << "</svg>\n<div class=\"sl-tip\" hidden></div>\n</div>\n";
}

} // namespace

void print_html_charts(const Aggregator& agg) {
    const bool have_conn = !agg.conn_timeline.empty();
    const bool have_acct = !agg.user_stats.empty();
    if (!have_conn && !have_acct) return;

    print_chart_style();
    if (have_conn) print_connection_chart(agg);
    if (have_acct) print_account_chart(agg);
    print_chart_script();
}
