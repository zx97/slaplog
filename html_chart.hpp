// html_chart.hpp

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
// Inline SVG charts for the HTML report.  See html_chart.cpp for what each one
// draws.  They are emitted one at a time so the report can place every chart
// under the section whose data it visualises, and the stylesheet/script are
// emitted separately (once, in the head and at the end of the page).
//
// The data these charts draw is only collected when set_collect_graph_data()
// was enabled before parsing (the CLI/WASM entries do that for the HTML output
// unless --no-graph was given); when nothing was collected, nothing is printed.

#ifndef HTML_CHART_HPP
#define HTML_CHART_HPP

#include "log_parser.hpp"

enum class HtmlChart {
    Connections,          // simultaneous connections over time  (after Statistics)
    LoadByServer,         // load split across the log's servers   (after Statistics)
    OperationTypes,       // operation mix                      (after Operation Counts)
    BindMethod,           // authentication method mix          (after Bind Usage)
    ResultCodeBreakdown,  // every result code, successful ones included
                          //                                    (right after the table)
    ResultCodes,          // failing result codes only          (after LDAP Result Codes)
    ErrorsOverTime,       // errors over time                   (after LDAP Result Codes)
    Latency,              // etime distribution                 (after Top Long Operations)
    LatencyDensity,       // the shape of that distribution, on a log scale
    Accounts,             // resource consumers per bind DN     (after Top Applications)
};

// True when at least one chart will be drawn, so the report can skip the chart
// stylesheet and script entirely when there is nothing to display.
bool html_charts_available(const Aggregator& agg);

void print_html_chart_style();                  // once, inside <head>
void print_html_chart_script();                 // once, at the end of <body>
void print_html_chart(const Aggregator& agg, HtmlChart which);

#endif // HTML_CHART_HPP
