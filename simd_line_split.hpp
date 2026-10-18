// simd_line_split.hpp
//
// SIMD-accelerated line finding and field extraction.
// Uses AVX2/AVX-512 intrinsics for fast scanning of large log files.
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

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string_view>
#include <string>
#include <algorithm>
#include <memory>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// Detect available SIMD instruction sets
#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512BW__)
#  define SLAPLOG_HAVE_AVX512 1
#else
#  define SLAPLOG_HAVE_AVX512 0
#endif

#if defined(__AVX2__)
#  define SLAPLOG_HAVE_AVX2 1
#else
#  define SLAPLOG_HAVE_AVX2 0
#endif

#if defined(__SSE4_2__)
#  define SLAPLOG_HAVE_SSE42 1
#else
#  define SLAPLOG_HAVE_SSE42 0
#endif

// Include immintrin.h here (outside any namespace) to avoid pulling std into our namespace
#if SLAPLOG_HAVE_AVX2 || SLAPLOG_HAVE_AVX512
#  include <immintrin.h>
#endif

namespace slaplog_simd {

// ============================================================================
// Line finding: find all '\n' positions in a buffer
// ============================================================================

// Scalar fallback: find all line endings
inline ::std::vector<size_t> find_lines_scalar(const char* data, size_t len) {
    ::std::vector<size_t> lines;
    lines.reserve(len / 80);  // rough estimate
    
    for (size_t i = 0; i < len; ++i) {
        if (data[i] == '\n') {
            lines.push_back(i);
        }
    }
    return lines;
}

#if SLAPLOG_HAVE_AVX2

// AVX2 implementation: process 32 bytes at a time
inline ::std::vector<size_t> find_lines_avx2(const char* data, size_t len) {
    ::std::vector<size_t> lines;
    lines.reserve(len / 80);
    
    const __m256i newline = _mm256_set1_epi8('\n');
    size_t i = 0;
    
    // Process full 32-byte chunks
    for (; i + 32 <= len; i += 32) {
        __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
        __m256i cmp = _mm256_cmpeq_epi8(chunk, newline);
        uint32_t mask = _mm256_movemask_epi8(cmp);
        
        while (mask) {
            // Find position of least significant set bit
            unsigned long bit = __builtin_ctz(mask);
            lines.push_back(i + bit);
            mask &= mask - 1;  // clear that bit
        }
    }
    
    // Process remainder
    for (; i < len; ++i) {
        if (data[i] == '\n') lines.push_back(i);
    }
    
    return lines;
}
#endif

#if SLAPLOG_HAVE_AVX512

// AVX-512 implementation: process 64 bytes at a time
inline ::std::vector<size_t> find_lines_avx512(const char* data, size_t len) {
    ::std::vector<size_t> lines;
    lines.reserve(len / 80);
    
    const __m512i newline = _mm512_set1_epi8('\n');
    size_t i = 0;
    
    // Process full 64-byte chunks
    for (; i + 64 <= len; i += 64) {
        __m512i chunk = _mm512_loadu_si512(data + i);
        __mmask64 mask = _mm512_cmpeq_epi8_mask(chunk, newline);
        
        while (mask) {
            unsigned long bit = __builtin_ctzll(mask);
            lines.push_back(i + bit);
            mask &= mask - 1;
        }
    }
    
    // Process remainder
    for (; i < len; ++i) {
        if (data[i] == '\n') lines.push_back(i);
    }
    
    return lines;
}
#endif

// Dispatch to best available implementation
inline ::std::vector<size_t> find_lines(const char* data, size_t len) {
#if SLAPLOG_HAVE_AVX512
    return find_lines_avx512(data, len);
#elif SLAPLOG_HAVE_AVX2
    return find_lines_avx2(data, len);
#else
    return find_lines_scalar(data, len);
#endif
}

// ============================================================================
// Fast field extraction: find "key=" patterns
// ============================================================================

// Find all occurrences of a 4-char key like "conn", "op=", "fd="
// Returns positions of the '=' character (or start of value)
inline ::std::vector<size_t> find_key_positions(const char* data, size_t len, const char* key, size_t key_len) {
    ::std::vector<size_t> positions;
    
    if (key_len < 1 || len < key_len + 1) return positions;
    
    // Scalar implementation - fast enough for short keys
    for (size_t i = 0; i + key_len < len; ++i) {
        if (data[i] == key[0]) {
            bool match = true;
            for (size_t k = 1; k < key_len; ++k) {
                if (data[i + k] != key[k]) { match = false; break; }
            }
            if (match && data[i + key_len] == '=') {
                positions.push_back(i + key_len + 1);  // position of value start
            }
        }
    }
    
    return positions;
}

// Extract integer value starting at position (assumes digits follow)
inline int extract_int_at(const char* data, size_t len, size_t pos) {
    if (pos >= len) return 0;
    
    int value = 0;
    bool negative = false;
    
    if (data[pos] == '-') {
        negative = true;
        ++pos;
    }
    
    for (; pos < len; ++pos) {
        char c = data[pos];
        if (c < '0' || c > '9') break;
        value = value * 10 + (c - '0');
    }
    
    return negative ? -value : value;
}

// Extract double value starting at position
inline double extract_double_at(const char* data, size_t len, size_t pos) {
    if (pos >= len) return 0.0;
    
    const char* start = data + pos;
    char* end = nullptr;
    double val = ::std::strtod(start, &end);
    return val;
}

// ============================================================================
// Memory-mapped file reader
// ============================================================================

class MmapReader {
public:
    MmapReader() : data_(nullptr), size_(0), fd_(-1) {}
    
    ~MmapReader() { close(); }
    
    // Non-copyable, movable
    MmapReader(const MmapReader&) = delete;
    MmapReader& operator=(const MmapReader&) = delete;
    
    MmapReader(MmapReader&& other) noexcept
        : data_(other.data_), size_(other.size_), fd_(other.fd_) {
        other.data_ = nullptr;
        other.size_ = 0;
        other.fd_ = -1;
    }
    
    MmapReader& operator=(MmapReader&& other) noexcept {
        if (this != &other) {
            close();
            data_ = other.data_;
            size_ = other.size_;
            fd_ = other.fd_;
            other.data_ = nullptr;
            other.size_ = 0;
            other.fd_ = -1;
        }
        return *this;
    }
    
    bool open(const char* path) {
        close();
        
        fd_ = ::open(path, O_RDONLY);
        if (fd_ < 0) return false;
        
        // Get file size
        struct stat st;
        if (::fstat(fd_, &st) < 0) {
            ::close(fd_);
            fd_ = -1;
            return false;
        }
        size_ = st.st_size;
        
        if (size_ == 0) {
            data_ = nullptr;
            return true;
        }
        
        // Memory map the file
        data_ = static_cast<const char*>(::mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0));
        if (data_ == MAP_FAILED) {
            data_ = nullptr;
            size_ = 0;
            ::close(fd_);
            fd_ = -1;
            return false;
        }
        
        // Advise sequential access
        ::madvise(const_cast<char*>(data_), size_, MADV_SEQUENTIAL | MADV_WILLNEED);
        
        return true;
    }
    
    void close() {
        if (data_ && data_ != MAP_FAILED) {
            ::munmap(const_cast<char*>(data_), size_);
            data_ = nullptr;
        }
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
        size_ = 0;
    }
    
    const char* data() const { return data_; }
    size_t size() const { return size_; }
    bool empty() const { return size_ == 0 || data_ == nullptr; }
    bool is_open() const { return data_ != nullptr && fd_ >= 0; }
    
    // Get a string_view of the entire mapped region
    ::std::string_view view() const {
        return ::std::string_view(data_, size_);
    }

private:
    const char* data_;
    size_t size_;
    int fd_;
};

// ============================================================================
// Parallel decompression using external tools (pigz, lbzip2, xz -T)
// ============================================================================

class DecompressPipe {
public:
    DecompressPipe() : pipe_(nullptr) {}
    ~DecompressPipe() { close(); }
    
    DecompressPipe(const DecompressPipe&) = delete;
    DecompressPipe& operator=(const DecompressPipe&) = delete;
    
    // Open a decompression pipe for the given file
    // Returns true on success, false if file doesn't need decompression or tool unavailable
    static ::std::unique_ptr<DecompressPipe> open(const char* path) {
        ::std::string ext = get_extension(path);
        const char* cmd = nullptr;
        
        if (ext == ".gz") {
            // pigz -dc for parallel gzip decompression (falls back to gzip -dc)
            if (tool_exists("pigz")) cmd = "pigz -dc";
            else if (tool_exists("gzip")) cmd = "gzip -dc";
        } else if (ext == ".bz2") {
            // lbzip2 -dc for parallel bzip2 decompression (falls back to bzip2 -dc)
            if (tool_exists("lbzip2")) cmd = "lbzip2 -dc";
            else if (tool_exists("bzip2")) cmd = "bzip2 -dc";
        } else if (ext == ".xz") {
            // xz -T0 for parallel xz decompression (uses all cores)
            if (tool_exists("xz")) cmd = "xz -T0 -dc";
        }
        
        if (!cmd) return nullptr;
        
        // Build full command
        ::std::string full_cmd = ::std::string(cmd) + " \"" + path + "\"";
        
        FILE* pipe = ::popen(full_cmd.c_str(), "r");
        if (!pipe) return nullptr;
        
        auto result = ::std::unique_ptr<DecompressPipe>(new DecompressPipe());
        result->pipe_ = pipe;
        return result;
    }
    
    // Read up to 'size' bytes into buffer
    // Returns number of bytes read (0 = EOF, -1 = error)
    ssize_t read(void* buffer, size_t size) {
        if (!pipe_) return -1;
        return ::fread(buffer, 1, size, pipe_);
    }
    
    // Read entire stream into a string (for small files)
    ::std::string read_all() {
        if (!pipe_) return "";
        
        ::std::string result;
        constexpr size_t BUFSIZE = 65536;
        char buf[BUFSIZE];
        ssize_t n;
        
        while ((n = ::fread(buf, 1, BUFSIZE, pipe_)) > 0) {
            result.append(buf, n);
        }
        
        return result;
    }
    
    void close() {
        if (pipe_) {
            ::pclose(pipe_);
            pipe_ = nullptr;
        }
    }
    
    bool is_open() const { return pipe_ != nullptr; }
    
    FILE* get() const { return pipe_; }

private:
    FILE* pipe_;
    
    static ::std::string get_extension(const char* path) {
        ::std::string_view p(path);
        size_t dot = p.rfind('.');
        if (dot == ::std::string_view::npos) return "";
        return ::std::string(p.substr(dot));
    }
    
    static bool tool_exists(const char* tool) {
        ::std::string cmd = "which " + ::std::string(tool) + " >/dev/null 2>&1";
        return ::std::system(cmd.c_str()) == 0;
    }
};

// ============================================================================
// SIMD-accelerated line processor: iterate lines with SIMD finding
// ============================================================================

// Iterator-like class for processing lines from a buffer
class LineProcessor {
public:
    LineProcessor(const char* data, size_t len) 
        : data_(data), len_(len), line_starts_(), current_(0) {
        // Find all line endings
        auto endings = find_lines(data, len);
        
        // Convert to line start positions
        size_t start = 0;
        for (size_t end : endings) {
            line_starts_.push_back(start);
            start = end + 1;  // skip '\n'
        }
        // Add final line if not terminated by newline
        if (start < len) {
            line_starts_.push_back(start);
        }
    }
    
    // Get next line as string_view
    // Returns empty string_view at end
    ::std::string_view next() {
        if (current_ >= line_starts_.size()) return {};
        
        size_t start = line_starts_[current_];
        size_t end = (current_ + 1 < line_starts_.size()) 
            ? line_starts_[current_ + 1] - 1  // -1 to exclude '\n'
            : len_;
        
        ++current_;
        
        // Handle \r\n line endings
        if (end > start && data_[end - 1] == '\r') --end;
        
        return ::std::string_view(data_ + start, end - start);
    }
    
    // Get current line number (1-based)
    size_t line_number() const { return current_; }
    
    // Total lines
    size_t total_lines() const { return line_starts_.size(); }
    
    // Reset to beginning
    void reset() { current_ = 0; }

private:
    const char* data_;
    size_t len_;
    ::std::vector<size_t> line_starts_;
    size_t current_;
};

} // namespace slaplog_simd