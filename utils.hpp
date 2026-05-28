// utils.hpp

/* 
    SPDX-License-Identifier: AGPL-3.0-or-later
    GNU Affero General Public License v3.0 (https://www.gnu.org/licenses/agpl-3.0.txt)
    Copyright (c) 2026 Manuel FLURY
    All rights reserved.
    
    This file is part of slaplog - an OpenLDAP Log Analysis Tool.
    
    Licensed under the GNU General Public License v3.0 (GPL-3.0-or-later).
    See the LICENSE file distributed with this work for full license text.
    
    THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
    AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


//
// Small utility functions shared across the slaplog codebase:
//   • ends_with           – simple suffix check.
//   • parse_timestamp     – ISO 8601 / custom-format string → time_point.
//   • format_time         – time_point → formatted string.
//   • get_cached_regex    – std::regex factory with an LRU-like cache.
//
// All functions are declared `inline` so the header can be included from
// multiple translation units without ODR violations.

#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <regex>
#include <unordered_map>

namespace utils {

    /**
     * ends_with – Test whether `str` ends with the given `suffix`.
     *
     * Performs a fast length check before calling std::string::compare.
     * Returns false if str is shorter than suffix.
     *
     * @param str     The string to examine.
     * @param suffix  The suffix to look for.
     * @return true   iff str ends with suffix.
     */
    inline bool ends_with(const std::string& str, const std::string& suffix) {
        if (str.length() >= suffix.length()) {
            return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
        }
        return false;
    }

    /**
     * parse_timestamp – Parse an ISO 8601 timestamp (YYYY-MM-DDTHH:MM:SS)
     * into a std::chrono::system_clock::time_point.
     *
     * The format string "%Y-%m-%dT%H:%M:%S" is used via std::get_time.
     * Throws std::runtime_error if parsing fails.
     *
     * @param timestamp  String in ISO 8601 format.
     * @return           Corresponding time_point (local time, not UTC).
     */
    inline std::chrono::system_clock::time_point parse_timestamp(const std::string& timestamp) {
        std::tm tm = {};
        std::istringstream ss(timestamp);
        ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
        if (ss.fail()) throw std::runtime_error("Failed to parse timestamp");
        return std::chrono::system_clock::from_time_t(std::mktime(&tm));
    }

    /**
     * format_time – Convert a system_clock time_point to a human-readable
     * string in the form "YYYY-MM-DD HH:MM:SS".
     *
     * Uses std::put_time with the local time zone via std::localtime.
     *
     * @param tp  The time point to format.
     * @return    Formatted date-time string.
     */
    inline std::string format_time(std::chrono::system_clock::time_point tp) {
        auto time = std::chrono::system_clock::to_time_t(tp);
        std::tm tm = *std::localtime(&time);
        std::stringstream ss;
        ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    /**
     * get_cached_regex – Retrieve or compile a std::regex, caching the
     * result in a function-local static unordered_map.
     *
     * Compiling a regex is expensive; this cache ensures each unique
     * pattern is compiled only once per process lifetime.
     *
     * @param pattern  The regex pattern string.
     * @return         Reference to the (possibly newly compiled) regex.
     */
    inline const std::regex& get_cached_regex(const std::string& pattern) {
        static std::unordered_map<std::string, std::regex> cache;
        auto it = cache.find(pattern);
        if (it == cache.end()) {
            it = cache.emplace(pattern, std::regex(pattern)).first;
        }
        return it->second;
    }
}

#endif
