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
// Inline SVG charts for the HTML report.
//
//   • print_html_charts - emits two sections: simultaneous connections over the
//     analysed time range (filled line chart, with a marker on every server
//     start/stop event), and the share of the total operation time (etime)
//     consumed by each bind account (pie chart with a legend).
//
// Both are plain SVG (no external dependency) and both are interactive: an
// invisible hit area per point carries the value in data-* attributes, which a
// small inline script turns into a tooltip that follows the mouse.  The style
// and the script are emitted once, by the single entry point below.
//
// The data these charts draw is only collected when set_collect_graph_data()
// was enabled before parsing (the CLI/WASM entries do that for the HTML output
// unless --no-graph was given); when nothing was collected, nothing is printed.

#ifndef HTML_CHART_HPP
#define HTML_CHART_HPP

#include "log_parser.hpp"

void print_html_charts(const Aggregator& agg);

#endif // HTML_CHART_HPP
