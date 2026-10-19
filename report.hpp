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

void print_text_report(const Aggregator& agg, double duration, bool compact = false, int color_mode = 1, const std::set<std::string>& sections = {"all"}, const std::string& output_date_format = "rfc3339", const std::string& custom_title = "");

// Omit the "slaplog vX.Y.Z" mention from the report footer (--no-version).
void set_show_version(bool on);

void print_html_report(const Aggregator& agg, double duration, bool compact = false, const std::string& output_date_format = "rfc3339", const std::string& custom_title = "", bool tabs = false);

void print_json_report(const Aggregator& agg, double duration, bool compact = false, const std::string& output_date_format = "rfc3339", const std::string& custom_title = "");

void print_replay_report(const Aggregator& agg, double duration, const std::string& output_date_format = "rfc3339", const std::string& separator = "|");

// Short human-readable name for an LDAP result code ("invalidCredentials",
// "noSuchObject", …), or "unknown" when the code is not in the table.
std::string ldap_error_name(int code);

// A result code is not just "error or not": it accuses a different party
// depending on the code, and only one of the five classes says anything about
// slapd's health.  The classification (LdapCodeClass, ldap_code_class(),
// ldap_code_is_error()) lives in log_parser.hpp, next to the aggregates it also
// filters; what is declared here is how it is presented.
//
// Short human-readable name for a class ("informational", "client-side", …).
const char* ldap_code_class_name(LdapCodeClass c);

// HTML colour for a class, shared by the report tables and the charts so a
// result code keeps the same colour everywhere on the page.
const char* ldap_code_class_color(LdapCodeClass c);

// The second colour of a class that is drawn hatched rather than in one flat
// colour — the colour the class's own colour cannot carry.  Only
// LdapCodeClass::PolicyOrClient ("either cause") is hatched, amber over violet,
// so this returns amber for it and nullptr for every other class.  HTML has no
// paint server outside SVG: the report's inline backgrounds and legends draw the
// hatch as a CSS `repeating-linear-gradient` built from the same two colours.
const char* ldap_code_class_hatch_color(LdapCodeClass c);

#endif
