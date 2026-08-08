// report.hpp

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
// Declares three output-format entry points for slaplog's aggregated LDAP log
// analysis.  Each function consumes the same Aggregator data structure and
// serialises it to a different target: plain text, HTML, or JSON.

#ifndef REPORT_HPP
#define REPORT_HPP

#include "log_parser.hpp"
#include <string>
#include <set>
#include <vector>

void print_text_report(const Aggregator& agg, double duration, bool compact = false, int color_mode = 1, const std::set<std::string>& sections = {"all"}, const std::string& output_date_format = "rfc3339");

void print_html_report(const Aggregator& agg, double duration, bool compact = false, const std::string& output_date_format = "rfc3339");

void print_json_report(const Aggregator& agg, double duration, bool compact = false, const std::string& output_date_format = "rfc3339");

void print_replay_report(const Aggregator& agg, double duration, const std::string& output_date_format = "rfc3339", const std::string& separator = "|");

#endif
