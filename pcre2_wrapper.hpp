// pcre2_wrapper.hpp
//
// PCRE2 wrapper providing a std::regex-like interface for drop-in replacement.
// Uses PCRE2 with JIT for high performance.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// GNU Affero General Public License v3.0 (https://www.gnu.org/licenses/agpl-3.0.txt)
// Copyright (c) 2026 Manuel FLURY
// All rights reserved.
//
// This file is part of slaplog - an OpenLDAP Log Analysis Tool.
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later).
// See the LICENSE file distributed with this work for full license text.
//
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#pragma once

#define PCRE2_CODE_UNIT_WIDTH 8
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <pcre2.h>

namespace slaplog_pcre2 {

// Forward declaration
class Regex;

// Match results container, mimicking std::smatch
class MatchResults {
public:
    MatchResults() = default;
    
    // Number of sub-matches (0 = full match, 1+ = capture groups)
    size_t size() const { return matches_.size(); }
    
    // Access by index
    const std::string& operator[](size_t i) const { return matches_[i]; }
    std::string& operator[](size_t i) { return matches_[i]; }
    
    // Check if match succeeded
    bool matched() const { return matched_; }
    
    // Position/length of a sub-match
    size_t position(size_t i) const { return positions_[i].first; }
    size_t length(size_t i) const { return positions_[i].second; }
    
    // String view of a sub-match (avoids copy when possible)
    std::string_view str_view(size_t i) const {
        return std::string_view(matches_[i]);
    }
    
    // For compatibility with std::smatch
    std::string str(size_t i) const { return matches_[i]; }
    
    // Clear for reuse
    void clear() {
        matches_.clear();
        positions_.clear();
        matched_ = false;
    }
    
    // Reserve space for expected number of groups
    void reserve(size_t n) {
        matches_.reserve(n);
        positions_.reserve(n);
    }
    
    // Internal: set match results
    void set_match(bool m, std::vector<std::string>&& matches, 
                   std::vector<std::pair<size_t, size_t>>&& pos) {
        matched_ = m;
        matches_ = std::move(matches);
        positions_ = std::move(pos);
    }

private:
    bool matched_ = false;
    std::vector<std::string> matches_;
    std::vector<std::pair<size_t, size_t>> positions_;
    
    friend class Regex;
};

// Regex class mimicking std::regex
class Regex {
public:
    // Flag bits (subset of std::regex_constants::syntax_option_type)
    enum Flag {
        None = 0,
        icase = 1 << 0,
    };
    
    using flag_type = int;
    
    Regex() = default;
    
    explicit Regex(const std::string& pattern, flag_type flags = None) {
        compile(pattern, flags);
    }
    
    Regex(const Regex&) = delete;
    Regex& operator=(const Regex&) = delete;
    
    Regex(Regex&& other) noexcept 
        : re_(std::move(other.re_)), pattern_(std::move(other.pattern_)),
          num_groups_(other.num_groups_) {}
    
    Regex& operator=(Regex&& other) noexcept {
        re_ = std::move(other.re_);
        pattern_ = std::move(other.pattern_);
        num_groups_ = other.num_groups_;
        return *this;
    }
    
    ~Regex() = default;
    
    void compile(const std::string& pattern, flag_type flags = None) {
        pattern_ = pattern;
        
        int pcre2_flags = PCRE2_UTF | PCRE2_UCP;
        if (flags & icase) pcre2_flags |= PCRE2_CASELESS;
        
        int error_code = 0;
        PCRE2_SIZE error_offset = 0;
        
        re_.reset(pcre2_compile(
            reinterpret_cast<const PCRE2_UCHAR*>(pattern.c_str()),
            PCRE2_ZERO_TERMINATED,
            pcre2_flags,
            &error_code,
            &error_offset,
            nullptr
        ));
        
        if (!re_) {
            // Pattern compilation failed
            num_groups_ = 0;
            return;
        }
        
        // Enable JIT compilation for faster matching
        pcre2_jit_compile(re_.get(), PCRE2_JIT_COMPLETE);
        
        // Get number of capture groups
        PCRE2_SIZE count = 0;
        pcre2_pattern_info(re_.get(), PCRE2_INFO_CAPTURECOUNT, &count);
        num_groups_ = static_cast<size_t>(count);
    }
    
    bool ok() const { return re_ != nullptr; }
    const std::string& pattern() const { return pattern_; }
    size_t mark_count() const { return num_groups_; }
    
    // Full match (entire string must match) - like std::regex_match
    bool match(const std::string& str, MatchResults& m) const {
        return match(std::string_view(str), m);
    }
    
    bool match(std::string_view str, MatchResults& m) const {
        return do_match(str, m, PCRE2_ANCHORED);
    }
    
    // Partial match (substring) - like std::regex_search
    bool search(const std::string& str, MatchResults& m) const {
        return search(std::string_view(str), m);
    }
    
    bool search(std::string_view str, MatchResults& m) const {
        return do_match(str, m, 0);
    }

private:
    struct Pcre2Deleter {
        void operator()(pcre2_code* p) const { if (p) pcre2_code_free(p); }
    };
    std::unique_ptr<pcre2_code, Pcre2Deleter> re_;
    std::string pattern_;
    size_t num_groups_ = 0;
    
    // Internal matching implementation using ovector for positions
    bool do_match(std::string_view str, MatchResults& m, uint32_t options) const {
        if (!re_) {
            m.clear();
            m.set_match(false, {}, {});
            return false;
        }
        
        // Create match data block with space for all capture groups + full match
        pcre2_match_data* match_data = pcre2_match_data_create(num_groups_ + 1, nullptr);
        if (!match_data) {
            m.clear();
            m.set_match(false, {}, {});
            return false;
        }
        
        int rc = pcre2_match(
            re_.get(),
            reinterpret_cast<const PCRE2_UCHAR*>(str.data()),
            str.size(),
            0,              // start offset
            options,        // 0 = search, PCRE2_ANCHORED = full match
            match_data,
            nullptr
        );
        
        if (rc < 0) {
            pcre2_match_data_free(match_data);
            m.clear();
            m.set_match(false, {}, {});
            return false;
        }
        
        // Get ovector (offset vector) - array of [start, end] pairs for each capture group
        // ovector[0] = start of full match, ovector[1] = end of full match
        // ovector[2*i] = start of group i, ovector[2*i+1] = end of group i
        PCRE2_SIZE* ovector = pcre2_get_ovector_pointer(match_data);
        
        // Extract captures using ovector - use num_groups_ to ensure we always have
        // entries for all capture groups, even if some didn't participate in the match.
        // This is critical for optional capture groups that may not match.
        std::vector<std::string> matches;
        std::vector<std::pair<size_t, size_t>> positions;
        matches.reserve(num_groups_ + 1);
        positions.reserve(num_groups_ + 1);
        
        for (size_t i = 0; i <= num_groups_; ++i) {
            PCRE2_SIZE start = ovector[2 * i];
            PCRE2_SIZE end = ovector[2 * i + 1];
            
            if (start != PCRE2_UNSET && end != PCRE2_UNSET) {
                matches.emplace_back(str.data() + start, end - start);
                positions.emplace_back(start, end - start);
            } else {
                matches.emplace_back("");
                positions.emplace_back(0, 0);
            }
        }
        
        pcre2_match_data_free(match_data);
        
        m.set_match(true, std::move(matches), std::move(positions));
        return true;
    }
};

// Convenience functions mimicking std::regex_match / regex_search
inline bool regex_match(const std::string& str, MatchResults& m, const Regex& re) {
    return re.match(str, m);
}

inline bool regex_match(std::string_view str, MatchResults& m, const Regex& re) {
    return re.match(str, m);
}

inline bool regex_search(const std::string& str, MatchResults& m, const Regex& re) {
    return re.search(str, m);
}

inline bool regex_search(std::string_view str, MatchResults& m, const Regex& re) {
    return re.search(str, m);
}

} // namespace slaplog_pcre2