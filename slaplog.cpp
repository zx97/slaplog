// slaplog.cpp

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


#include "progress_bar_manager.hpp"
#include <thread>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <mutex>
#include <nlohmann/json.hpp>

static const std::regex &rx(const std::string &pat) {
    static std::unordered_map<std::string, std::regex> cache;
    auto it = cache.find(pat);
    if (it == cache.end()) {
        it = cache.emplace(pat, std::regex(pat)).first;
    }
    return it->second;
}

static const std::regex &rx(const std::string &pat, std::regex::flag_type flags) {
    static std::unordered_map<std::string, std::regex> cache;
    const std::string key = pat + "\n#flags=" + std::to_string(static_cast<unsigned long>(flags));
    auto it = cache.find(key);
    if (it == cache.end()) {
        it = cache.emplace(key, std::regex(pat, flags)).first;
    }
    return it->second;
}
namespace fs = std::filesystem;
using json = nlohmann::json;

static const std::string VERSION = "3.0.0";
static const std::string AUTHOR = "Manuel FLURY";
static const std::string RELEASE_DATE = "2026/05/20";

static void usage(const char *prog) {
    std::cout << "Usage: " << prog << " [options] <file|dir> [file|dir ...]\n";
    std::cout << "Options:\n";
    std::cout << "  -d, --debug                Enable debug mode\n";
    std::cout << "  -o, --output STRING        Output format: text | dynatrace | text,dynatrace\n";
    std::cout << "  -r, --recursive            Recurse into directories\n";
    std::cout << "      --per-file             Also output one report per input file\n";
    std::cout << "      --per-file-summary-only  Show only a short summary for each file\n";
    std::cout << "      --unknown-lines FILE   Write unknown parsed lines to FILE\n";
    std::cout << "      --unknown-only         Only scan and emit unknown lines, no final report\n";
    std::cout << "      --jobs N               Parallel workers by file (not implemented in this C++ version)\n";
    std::cout << "  -V, --version             Show version\n";
    std::cout << "  -h, --help                Show help\n\n";
    std::cout << "Accepted inputs: plain files, directories, and compressed logs (gzip/bzip2/xz/zstd).\n";
}

static std::string normalize_output(const std::string &raw) {
    if (raw == "dynatrace")
        return "dynatrace";
    if (raw == "text,dynatrace" || raw == "dynatrace,text")
        return "textdynatrace";
    return "text";
}

static std::string dequote(std::string s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        s.erase(s.begin());
        s.pop_back();
    }
    return s;
}

static double safe_div(double a, double b) {
    if (b == 0.0)
        return 0.0;
    return a / b;
}

static std::string trim(const std::string &s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b])))
        ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
        --e;
    return s.substr(b, e - b);
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static std::string normalize_filter(std::string f) {
    if (f.empty())
        return "";
    f = dequote(f);

    std::string out;
    bool prev_space = false;
    for (char c : f) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!prev_space)
                out.push_back(' ');
            prev_space = true;
        } else {
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            prev_space = false;
        }
    }
    return trim(out);
}

static std::string normalize_attrs(const std::string &s) {
    if (s.empty())
        return "";
    std::istringstream iss(s);
    std::vector<std::string> attrs;
    std::string a;
    while (iss >> a)
        attrs.push_back(to_lower(a));
    std::sort(attrs.begin(), attrs.end());

    std::ostringstream oss;
    for (size_t i = 0; i < attrs.size(); ++i) {
        if (i)
            oss << ' ';
        oss << attrs[i];
    }
    return oss.str();
}

static std::string classify_nentries_bucket(const std::optional<int> &n) {
    if (!n.has_value())
        return "unknown";
    if (*n == 0)
        return "0";
    if (*n == 1)
        return "1";
    if (*n <= 9)
        return "2-9";
    if (*n <= 99)
        return "10-99";
    if (*n <= 999)
        return "100-999";
    return "1000+";
}

static std::string ts_sort_key(const std::string &ts) {
    if (ts.empty())
        return "";

    static const std::regex rfc3339(R"(^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}))");
    static const std::regex syslog(R"(^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})$)");
    std::smatch m;

    if (std::regex_search(ts, m, rfc3339)) {
        std::ostringstream oss;
        oss << m[1].str() << m[2].str() << m[3].str() << m[4].str() << m[5].str() << m[6].str();
        return oss.str();
    }

    if (std::regex_match(ts, m, syslog)) {
        static const std::map<std::string, int> mon = {{"Jan", 1}, {"Feb", 2},  {"Mar", 3},  {"Apr", 4},
            {"May", 5}, {"Jun", 6},  {"Jul", 7},  {"Aug", 8},
            {"Sep", 9}, {"Oct", 10}, {"Nov", 11}, {"Dec", 12}};

        int month = 0;
        auto it = mon.find(m[1].str());
        if (it != mon.end())
            month = it->second;

        std::ostringstream oss;
        oss << "0000" << std::setw(2) << std::setfill('0') << month << std::setw(2) << std::setfill('0')
            << std::stoi(m[2].str()) << m[3].str() << m[4].str() << m[5].str();
        return oss.str();
    }

    return ts;
}

static const std::unordered_map<int, std::string> LDAP_ERRORS = {{0, "success"},
    {1, "operationsError"},
    {2, "protocolError"},
    {3, "timeLimitExceeded"},
    {4, "sizeLimitExceeded"},
    {5, "compareFalse"},
    {6, "compareTrue"},
    {7, "authMethodNotSupported"},
    {8, "strongerAuthRequired"},
    {10, "referral"},
    {11, "adminLimitExceeded"},
    {12, "unavailableCriticalExtension"},
    {13, "confidentialityRequired"},
    {14, "saslBindInProgress"},
    {16, "noSuchAttribute"},
    {17, "undefinedAttributeType"},
    {18, "inappropriateMatching"},
    {19, "constraintViolation"},
    {20, "attributeOrValueExists"},
    {21, "invalidAttributeSyntax"},
    {32, "noSuchObject"},
    {33, "aliasProblem"},
    {34, "invalidDNSyntax"},
    {36, "aliasDereferencingProblem"},
    {48, "inappropriateAuthentication"},
    {49, "invalidCredentials"},
    {50, "insufficientAccessRights"},
    {51, "busy"},
    {52, "unavailable"},
    {53, "unwillingToPerform"},
    {54, "loopDetect"},
    {64, "namingViolation"},
    {65, "objectClassViolation"},
    {66, "notAllowedOnNonLeaf"},
    {67, "notAllowedOnRDN"},
    {68, "entryAlreadyExists"},
    {69, "objectClassModsProhibited"},
    {71, "affectsMultipleDSAs"},
    {80, "other"}};

static const std::unordered_map<std::string, std::string> EXT_OID_NAME = {{"1.3.6.1.4.1.1466.20037", "StartTLS"},
    {"1.3.6.1.4.1.4203.1.11.1", "PasswordModify"},
    {"1.3.6.1.4.1.4203.1.11.3", "WhoAmI"},
    {"1.3.6.1.1.8", "Cancel"}};

enum class CompressionType { Plain, Gz, Bz2, Xz, Zst };

static std::string compression_to_string(CompressionType t) {
    switch (t) {
        case CompressionType::Plain:
            return "plain";
        case CompressionType::Gz:
            return "gz";
        case CompressionType::Bz2:
            return "bz2";
        case CompressionType::Xz:
            return "xz";
        case CompressionType::Zst:
            return "zst";
    }
    return "plain";
}

static CompressionType detect_compression_type(const std::string &file) {
    if (file.empty() || !fs::is_regular_file(file))
        return CompressionType::Plain;

    std::string lower = to_lower(file);

    if (std::regex_search(lower, rx(R"(\.gz(?:$|[._-]))")) || std::regex_search(lower, rx(R"(\.tgz(?:$|[._-]))"))) {
        return CompressionType::Gz;
    }
    if (std::regex_search(lower, rx(R"(\.bz2(?:$|[._-]))"))) {
        return CompressionType::Bz2;
    }
    if (std::regex_search(lower, rx(R"(\.xz(?:$|[._-]))"))) {
        return CompressionType::Xz;
    }
    if (std::regex_search(lower, rx(R"(\.zst(?:$|[._-]))")) || std::regex_search(lower, rx(R"(\.zstd(?:$|[._-]))"))) {
        return CompressionType::Zst;
    }

    std::string cmd = "file -b \"" + file + "\" 2>/dev/null";
    FILE *p = popen(cmd.c_str(), "r");
    if (p) {
        char buf[512];
        std::string desc;
        while (fgets(buf, sizeof(buf), p))
            desc += buf;
        pclose(p);

        std::string d = to_lower(desc);
        if (d.find("gzip compressed") != std::string::npos)
            return CompressionType::Gz;
        if (d.find("bzip2 compressed") != std::string::npos)
            return CompressionType::Bz2;
        if (d.find("xz compressed") != std::string::npos)
            return CompressionType::Xz;
        if (d.find("zstandard compressed") != std::string::npos)
            return CompressionType::Zst;
    }

    return CompressionType::Plain;
}

class LineReader {
    public:
        explicit LineReader(const std::string &path, CompressionType ctype) : is_pipe_(false), pipe_(nullptr) {
            if (ctype == CompressionType::Plain) {
                in_.open(path);
                if (!in_)
                    throw std::runtime_error("Cannot open " + path);
            } else {
                std::string cmd;
                switch (ctype) {
                    case CompressionType::Gz:
                        cmd = "gzip -dc -- \"" + path + "\"";
                        break;
                    case CompressionType::Bz2:
                        cmd = "bzip2 -dc -- \"" + path + "\"";
                        break;
                    case CompressionType::Xz:
                        cmd = "xz -dc -- \"" + path + "\"";
                        break;
                    case CompressionType::Zst:
                        cmd = "zstd -dc -- \"" + path + "\"";
                        break;
                    default:
                        break;
                }
                pipe_ = popen(cmd.c_str(), "r");
                if (!pipe_)
                    throw std::runtime_error("Cannot open decompression stream for " + path);
                is_pipe_ = true;
            }
        }

        ~LineReader() {
            if (pipe_)
                pclose(pipe_);
        }

        bool getline(std::string &line) {
            if (!is_pipe_) {
                return static_cast<bool>(std::getline(in_, line));
            }

            line.clear();
            char buffer[8192];
            if (!fgets(buffer, sizeof(buffer), pipe_))
                return false;
            line = buffer;

            while (!line.empty() && line.back() != '\n') {
                if (!fgets(buffer, sizeof(buffer), pipe_))
                    break;
                line += buffer;
                if (!line.empty() && line.back() == '\n')
                    break;
            }

            if (!line.empty() && line.back() == '\n')
                line.pop_back();
            return true;
        }

    private:
        bool is_pipe_;
        std::ifstream in_;
        FILE *pipe_;
};

static bool wanted_log_file(const std::string &path) {
    if (path.empty())
        return false;
    if (!fs::is_regular_file(path))
        return false;
    if (fs::file_size(path) == 0)
        return false;

    std::string base = fs::path(path).filename().string();
    std::string lower = to_lower(base);

    if (!base.empty() && base[0] == '.')
        return false;
    if (std::regex_search(lower, rx(R"(~$)")))
        return false;
    if (std::regex_search(lower, rx(R"(\.swp$)")))
        return false;
    if (std::regex_search(lower, rx(R"(\.tmp$)")))
        return false;
    if (std::regex_search(lower, rx(R"(\.bak$)")))
        return false;
    if (std::regex_search(lower, rx(R"(\.old$)")))
        return false;
    if (std::regex_search(lower, rx(R"(\.disabled$)")))
        return false;

    if (std::regex_search(base, rx(R"(^slapd(?:[-_.].*)?$)", std::regex::icase)))
        return true;
    if (lower.find("slapd") != std::string::npos)
        return true;
    if (lower.find("ldap") != std::string::npos)
        return true;
    if (std::regex_search(lower, rx(R"(\.log(?:\.[0-9]+)?$)")))
        return true;
    if (std::regex_search(lower, rx(R"(\.log(?:\.[0-9]+)?\.(gz|bz2|xz|zst)$)")))
        return true;
    if (std::regex_search(lower, rx(R"((gz|bz2|xz|zst)$)")) && lower.find("log") != std::string::npos)
        return true;

    return false;
}

static std::vector<std::string> collect_input_files(const std::vector<std::string> &inputs, bool recursive) {
    std::set<std::string> uniq;

    for (const auto &path : inputs) {
        if (path.empty())
            continue;

        std::error_code ec;
        if (fs::is_regular_file(path, ec)) {
            if (!ec && fs::file_size(path, ec) > 0)
                uniq.insert(path);
            continue;
        }

        if (!fs::is_directory(path, ec) || ec)
            continue;

        if (recursive) {
            for (auto const &entry : fs::recursive_directory_iterator(path)) {
                if (!entry.is_regular_file())
                    continue;
                std::string full = entry.path().string();
                if (wanted_log_file(full))
                    uniq.insert(full);
            }
        } else {
            for (auto const &entry : fs::directory_iterator(path)) {
                if (!entry.is_regular_file())
                    continue;
                std::string full = entry.path().string();
                if (wanted_log_file(full))
                    uniq.insert(full);
            }
        }
    }

    return std::vector<std::string>(uniq.begin(), uniq.end());
}

struct Event {
    std::string kind;
    std::string raw;
    std::string rest;
    std::string ts;
    std::string host;
    std::string proc;

    std::optional<int> conn;
    std::optional<int> op;
    std::optional<int> fd;
    std::optional<int> err;
    std::optional<int> tag;
    std::optional<int> scope;
    std::optional<int> deref;
    std::optional<int> nentries;
    std::optional<int> method;
    std::optional<int> msgid;
    std::optional<int> manage;

    std::optional<double> qtime;
    std::optional<double> etime;

    std::string reason;
    std::string src;
    std::string authcid;
    std::string authzid;
    std::string binddn;
    std::string dn;
    std::string base;
    std::string filter;
    std::string attrs;
    std::string text;
    std::string oid;
    std::string csn;
    std::string mech;

    std::map<std::string, std::string> track;
};

static const std::regex RE_HDR_RFC3339(R"(^(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+(\S+):\s+(.*)$)");
static const std::regex RE_HDR_SYSLOG(R"(^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+(.*)$)");
static const std::regex RE_CONN_OP(R"(^conn=(\d+)\s+op=(\d+)\s+(.*)$)");
static const std::regex RE_SASL_FAILURE(R"(^SASL\s+

$$
conn=(\d+)
$$

\s+(.*)$)");
static const std::regex RE_TRACK(R"(^

$$
(.*)
$$

$)");
static const std::regex RE_ACCEPT_PATH(R"(^conn=(\d+)\s+fd=(\d+)\s+ACCEPT\s+from\s+PATH=(.+?)(?:\s+$.*$)?$)");
static const std::regex RE_ACCEPT_IP(R"(^conn=(\d+)\s+fd=(\d+)\s+ACCEPT\s+from\s+IP=(.+?)(?:\s+$.*$)?$)");
static const std::regex RE_CLOSED(R"(^conn=(\d+)\s+fd=(\d+)\s+closed(?:\s+(.*))?$)", std::regex::icase);
static const std::regex RE_TLS(R"(^conn=(\d+)\s+fd=(\d+)\s+TLS established)", std::regex::icase);

static Event parse_line(const std::string &input_line) {
    Event ev;
    ev.raw = input_line;

    std::string line = input_line;
    std::smatch m;
    std::string ts, host, proc, rest;

    if (std::regex_match(line, m, RE_HDR_RFC3339)) {
        ts = m[1];
        host = m[2];
        proc = m[3];
        rest = m[4];
    } else if (std::regex_match(line, m, RE_HDR_SYSLOG)) {
        ts = m[1];
        host = m[2];
        proc = m[3];
        rest = m[4];
    } else {
        ev.kind = "UNKNOWN_LINE";
        return ev;
    }

    ev.ts = ts;
    ev.host = host;
    ev.proc = proc;
    ev.rest = rest;

    if (std::regex_match(rest, m, RE_ACCEPT_PATH) || std::regex_match(rest, m, RE_ACCEPT_IP)) {
        ev.kind = "ACCEPT";
        ev.conn = std::stoi(m[1]);
        ev.fd = std::stoi(m[2]);
        ev.src = m[3];
        return ev;
    }

    if (std::regex_match(rest, m, RE_CLOSED)) {
        ev.kind = "CLOSED";
        ev.conn = std::stoi(m[1]);
        ev.fd = std::stoi(m[2]);
        if (m.size() > 3)
            ev.reason = m[3];
        return ev;
    }

    if (std::regex_search(rest, m, RE_TLS)) {
        ev.kind = "TLS";
        ev.conn = std::stoi(m[1]);
        ev.fd = std::stoi(m[2]);
        return ev;
    }

    if (std::regex_match(rest, m, RE_SASL_FAILURE)) {
        ev.kind = "SASL";
        ev.conn = std::stoi(m[1]);
        ev.raw = m[2];
        return ev;
    }

    if (std::regex_match(rest, m, RE_TRACK)) {
        std::string body = m[1];

        std::smatch m2;
        if (std::regex_match(body, m2, RE_CONN_OP)) {
            ev.kind = "TRACK";
            ev.conn = std::stoi(m2[1]);
            ev.op = std::stoi(m2[2]);
            std::string kvbody = m2[3];

            std::regex kv_re(R"(([A-Z_]+)=(".*?"|\S+))");
            auto begin = std::sregex_iterator(kvbody.begin(), kvbody.end(), kv_re);
            auto end = std::sregex_iterator();

            for (auto it = begin; it != end; ++it) {
                std::string k = (*it)[1];
                std::string v = (*it)[2];
                ev.track[k] = dequote(v);
            }
            ev.raw = body;
            return ev;
        }
    }

    if (std::regex_match(rest, m, RE_CONN_OP)) {
        int conn = std::stoi(m[1]);
        int op = std::stoi(m[2]);
        std::string msg = m[3];
        ev.conn = conn;
        ev.op = op;

        std::smatch x;

        if (std::regex_match(msg, x, rx(R"REGEX(^BIND\s+authcid="([^"]*)"\s+authzid="([^"]*)"$)REGEX"))) {
            ev.kind = "BIND_AUTH";
            ev.authcid = x[1];
            ev.authzid = x[2];
            ev.binddn = ev.authzid.empty() ? ev.authcid : ev.authzid;
            ev.mech = "EXTERNAL";
            ev.raw = msg;
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"(^BIND\s+dn=(.*)\s+method=(\d+)$)"))) {
            ev.kind = "BIND";
            ev.binddn = x[1];
            ev.method = std::stoi(x[2]);
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"(^BIND\s+anonymous\s+method=(\d+)$)"))) {
            ev.kind = "BIND_ANON";
            ev.method = std::stoi(x[1]);
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"REGEX(^BIND\s+dn="([^"]*)"\s+mech=([A-Za-z0-9_-]+).*$)REGEX"))) {
            ev.kind = "BIND_DN_INFO";
            ev.dn = x[1];
            ev.mech = x[2];
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"(^BIND\s+dn=([^\s]+).*$)"))) {
            ev.kind = "BIND_DN_INFO";
            ev.dn = x[1];
            return ev;
        }
        if (std::regex_match(msg, x, rx(R"(^SRCH\s+base=(.+?)\s+scope=(\d+)\s+deref=(\d+)\s+filter=(.+)$)"))) {
            ev.kind = "SRCH";
            ev.base = x[1];
            ev.scope = std::stoi(x[2]);
            ev.deref = std::stoi(x[3]);
            ev.filter = x[4];
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"(^SRCH\s+attr=(.*)$)"))) {
            ev.kind = "SRCH_ATTR";
            ev.attrs = x[1];
            return ev;
        }

        if (std::regex_match(
                    msg, x,
                    rx(R"(^SEARCH RESULT\s+tag=(\d+)\s+err=(\d+)\s+qtime=([0-9.]+)\s+etime=([0-9.]+)\s+nentries=(\d+)\s+text=(.*)$)"))) {
            ev.kind = "SEARCH_RESULT";
            ev.tag = std::stoi(x[1]);
            ev.err = std::stoi(x[2]);
            ev.qtime = std::stod(x[3]);
            ev.etime = std::stod(x[4]);
            ev.nentries = std::stoi(x[5]);
            ev.text = x[6];
            return ev;
        }

        if (std::regex_match(
                    msg, x,
                    rx(R"(^SEARCH RESULT\s+tag=(\d+)\s+err=(\d+)\s+qtime=([0-9.]+)\s+etime=([0-9.]+)\s+nentries=(\d+)$)"))) {
            ev.kind = "SEARCH_RESULT";
            ev.tag = std::stoi(x[1]);
            ev.err = std::stoi(x[2]);
            ev.qtime = std::stod(x[3]);
            ev.etime = std::stod(x[4]);
            ev.nentries = std::stoi(x[5]);
            ev.text = "";
            return ev;
        }

        if (std::regex_match(
                    msg, x, rx(R"(^RESULT\s+tag=(\d+)\s+err=(\d+)\s+qtime=([0-9.]+)\s+etime=([0-9.]+)\s+text=(.*)$)"))) {
            ev.kind = "RESULT";
            ev.tag = std::stoi(x[1]);
            ev.err = std::stoi(x[2]);
            ev.qtime = std::stod(x[3]);
            ev.etime = std::stod(x[4]);
            ev.text = x[5];
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"(^RESULT\s+tag=(\d+)\s+err=(\d+)\s+qtime=([0-9.]+)\s+etime=([0-9.]+)$)"))) {
            ev.kind = "RESULT";
            ev.tag = std::stoi(x[1]);
            ev.err = std::stoi(x[2]);
            ev.qtime = std::stod(x[3]);
            ev.etime = std::stod(x[4]);
            ev.text = "";
            return ev;
        }

        if (std::regex_match(
                    msg, x, rx(R"(^RESULT\s+oid=(.*)\s+err=(\d+)\s+qtime=([0-9.]+)\s+etime=([0-9.]+)\s+text=(.*)$)"))) {
            ev.kind = "RESULT";
            ev.oid = x[1];
            ev.err = std::stoi(x[2]);
            ev.qtime = std::stod(x[3]);
            ev.etime = std::stod(x[4]);
            ev.text = x[5];
            ev.tag = std::nullopt;
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"(^ADD\s+dn=(.*)$)"))) {
            ev.kind = "ADD";
            ev.dn = x[1];
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"(^DEL\s+dn=(.*)$)"))) {
            ev.kind = "DEL";
            ev.dn = x[1];
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"(^MOD\s+dn=(.*)$)"))) {
            ev.kind = "MOD";
            ev.dn = x[1];
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"(^MOD\s+attr=(.*)$)"))) {
            ev.kind = "MOD";
            ev.attrs = x[1];
            ev.raw = msg;
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"(^MODRDN\s+dn=(.*)$)"))) {
            ev.kind = "MODRDN";
            ev.dn = x[1];
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"(^CMP\s+dn=(.*)$)"))) {
            ev.kind = "CMP";
            ev.dn = x[1];
            return ev;
        }

        if (std::regex_match(msg, x, rx(R"(^ABANDON\s+msgid=(\d+)$)"))) {
            ev.kind = "ABANDON";
            ev.msgid = std::stoi(x[1]);
            return ev;
        }

        if (msg == "UNBIND") {
            ev.kind = "UNBIND";
            return ev;
        }

        if (msg.rfind("EXT oid=", 0) == 0 && std::regex_match(msg, x, rx(R"(^EXT\s+oid=(.*)$)"))) {
            ev.kind = "EXT";
            ev.oid = x[1];
            return ev;
        }

        if (msg.rfind("syncprov_", 0) == 0) {
            ev.kind = "SYNCPROV";
            ev.raw = msg;
            return ev;
        }

        ev.kind = "UNKNOWN_OP";
        ev.raw = msg;
        return ev;
    }

    if (std::regex_match(rest, m,
                rx(R"(^slap_get_csn:\s+conn=(\d+)\s+op=(\d+)\s+generated new csn=(\S+)\s+manage=(\d+).*$)"))) {
        ev.kind = "CSN_GET";
        ev.conn = std::stoi(m[1]);
        ev.op = std::stoi(m[2]);
        ev.csn = m[3];
        ev.manage = std::stoi(m[4]);
        ev.raw = rest;
        return ev;
    }

    if (std::regex_match(rest, m, rx(R"(^slap_queue_csn:\s+queueing\s+\S+\s+(\S+).*$)"))) {
        ev.kind = "CSN_QUEUE";
        ev.csn = m[1];
        ev.raw = rest;
        return ev;
    }

    if (std::regex_match(rest, m, rx(R"(^slap_graduate_commit_csn:\s+removing\s+\S+\s+(\S+).*$)"))) {
        ev.kind = "CSN_GRADUATE";
        ev.csn = m[1];
        ev.raw = rest;
        return ev;
    }

    if (rest.rfind("slap_global_control: unrecognized control: ", 0) == 0) {
        ev.kind = "GLOBAL_CONTROL";
        std::smatch y;
        if (std::regex_search(rest, y, rx(R"(unrecognized control:\s+(\S+))"))) {
            ev.oid = y[1];
        }
        ev.raw = rest;
        return ev;
    }

    if (rest.rfind("syncprov", 0) == 0) {
        ev.kind = "SYNCPROV";
        ev.raw = rest;
        return ev;
    }

    if (rest.find("mdb_") != std::string::npos || rest.find("bdb_") != std::string::npos) {
        std::smatch y;
        if (std::regex_search(rest, y,
                    rx(R"((?:^|<=\s+)(?:mdb|bdb)_[a-z_]+:\s+([^)]+)\s+not indexed)", std::regex::icase))) {
            ev.kind = "NOT_INDEXED";
            ev.attrs = y[1];
            return ev;
        }
    }

    ev.kind = "UNKNOWN_LINE";
    ev.raw = line;
    ev.rest = rest;
    return ev;
}

struct Stats {
    long long lines = 0;
    long long fd_open = 0;
    long long fd_close = 0;
    long long conn_count = 0;
    long long unknown_lines = 0;
    long long replication_logs = 0;
};

struct OpState {
    bool counted = false;
    std::string type;
    std::string base;
    std::string filter;
    std::string attrs;
    std::string who;
    std::string dn;
    std::string oid;
    std::string binddn;
    std::string authcid;
    std::string authzid;
    std::optional<int> method;
    std::optional<int> msgid;
    std::optional<double> etime;
    std::optional<double> qtime;
    std::optional<int> nentries;
    std::optional<int> err;
    std::optional<int> tag;
    std::string text;
};

struct ConnState {
    std::map<int, OpState> ops;
    long long ops_count = 0;
    long long completed_ops = 0;
    double total_etime = 0.0;
    std::string binddn;
    std::string authcid;
    std::string app;
    std::string src;
    std::optional<int> fd;
    std::map<std::string, std::string> track;
};

struct TopOpRow {
    double etime = 0.0;
    int conn = 0;
    int op = 0;
    std::string type;
    std::string who;
    std::string base;
    std::string filter;
    std::optional<int> nentries;
    std::optional<int> err;
};

struct TopConnRow {
    double total_etime = 0.0;
    int conn = 0;
    std::string who;
    std::string src;
    int ops_count = 0;
    std::string binddn;
    std::string reason;
};

struct Aggregator {
    Stats stats;

    std::map<std::string, long long> operation_count = {
        {"BIND", 0},         {"BIND ANONYMOUS", 0}, {"EXT", 0},      {"ADD", 0},     {"DEL", 0},
        {"MOD", 0},          {"MODRDN", 0},         {"CMP", 0},      {"SRCH", 0},    {"SRCH ATTR", 0},
        {"RESULT", 0},       {"SEARCH RESULT", 0},  {"ABANDON", 0},  {"UNBIND", 0},  {"TLS", 0},
        {"SASL", 0},         {"GLOBAL_CONTROL", 0}, {"SYNCPROV", 0}, {"CSN_GET", 0}, {"CSN_QUEUE", 0},
        {"CSN_GRADUATE", 0}, {"NOT_INDEXED", 0}};

    struct {
        long long read = 0;
        long long write = 0;
    } read_write_stats;

    std::map<int, ConnState> conn_state;
    std::map<int, std::string> binddn_by_conn;
    std::map<int, std::string> src_by_conn;

    std::string firsttime;
    std::string lasttime;

    std::optional<double> maxetime;
    std::string maxetimeusr;
    std::string maxopdesc;

    std::optional<double> maxconnetime;
    std::string maxconnetimeusr;
    std::string maxconnopdesc;

    double etime_total = 0.0;
    double qtime_total = 0.0;

    std::map<std::string, long long> app_count;
    std::map<std::string, double> app_etime_total;
    std::map<std::string, long long> base_count;
    std::map<std::string, double> base_etime_total;
    std::map<std::string, long long> filter_count;
    std::map<std::string, double> filter_etime_total;
    std::map<std::string, long long> norm_filter_count;
    std::map<std::string, double> norm_filter_etime_total;
    std::map<std::string, long long> norm_filter_attrs_count;
    std::map<std::string, long long> norm_filter_n1_count;
    std::map<std::string, long long> norm_filter_n0_count;
    std::map<std::string, long long> wildcard_filter_count;
    std::map<std::string, std::map<std::string, long long>> filter_by_app;
    std::map<std::string, long long> attr_count;

    long long qmark_filter_count = 0;
    std::map<std::string, long long> qmark_filter_attr_count;

    std::map<int, long long> error_count;
    std::map<std::string, std::map<int, long long>> error_per_app;

    std::map<std::string, long long> ext_oid_count;
    std::map<std::string, long long> global_control_oid_count;

    struct {
        long long get = 0;
        long long queue = 0;
        long long graduate = 0;
    } csn_event_count;

    long long not_indexed_count = 0;
    std::map<std::string, long long> not_indexed_attr;

    std::vector<TopOpRow> top_ops;
    std::vector<TopConnRow> top_conns;

    long long active_connections = 0;
    long long peak_active_connections = 0;
};

static Aggregator new_aggregator() { return Aggregator{}; }

static void update_time_bounds(Aggregator &agg, const std::string &ts) {
    if (ts.empty())
        return;
    std::string key = ts_sort_key(ts);

    if (agg.firsttime.empty() || key < ts_sort_key(agg.firsttime)) {
        agg.firsttime = ts;
    }
    if (agg.lasttime.empty() || key > ts_sort_key(agg.lasttime)) {
        agg.lasttime = ts;
    }
}

static ConnState &ensure_conn(Aggregator &agg, int cid) { return agg.conn_state[cid]; }

static OpState &ensure_op(Aggregator &agg, int cid, int opid) { return agg.conn_state[cid].ops[opid]; }

static void ensure_total_counted(Aggregator &agg, int cid, int opid) {
    auto &conn = agg.conn_state[cid];
    auto &op = conn.ops[opid];
    if (op.counted)
        return;
    op.counted = true;
    conn.ops_count++;
}

static std::string app_for_conn(const Aggregator &agg, int cid) {
    auto it = agg.conn_state.find(cid);
    if (it == agg.conn_state.end())
        return "unknown";

    const auto &conn = it->second;
    if (!conn.binddn.empty())
        return conn.binddn;
    if (!conn.authcid.empty())
        return conn.authcid;

    auto itu = conn.track.find("USERNAME");
    if (itu != conn.track.end() && !itu->second.empty())
        return itu->second;
    auto itn = conn.track.find("NAME");
    if (itn != conn.track.end() && !itn->second.empty())
        return itn->second;

    return "unknown";
}

static void add_top_row(std::vector<TopConnRow> &rows, size_t limit, const TopConnRow &row) {
    rows.push_back(row);
    std::sort(rows.begin(), rows.end(), [](const TopConnRow &a, const TopConnRow &b) {
            if (a.total_etime != b.total_etime)
            return a.total_etime > b.total_etime;
            return a.conn < b.conn;
            });
    if (rows.size() > limit)
        rows.resize(limit);
}

static void add_top_op(Aggregator &agg, const TopOpRow &row) {
    agg.top_ops.push_back(row);
    std::sort(agg.top_ops.begin(), agg.top_ops.end(), [](const TopOpRow &a, const TopOpRow &b) {
            if (a.etime != b.etime)
            return a.etime > b.etime;
            if (a.conn != b.conn)
            return a.conn < b.conn;
            return a.op < b.op;
            });
    if (agg.top_ops.size() > 25)
        agg.top_ops.resize(25);
}

static void track_qmark_filter(Aggregator &agg, const std::string &filter) {
    if (filter.empty())
        return;
    std::set<std::string> seen;

    static const std::regex re(R"(\?([^=\s)]+)=)");
    auto begin = std::sregex_iterator(filter.begin(), filter.end(), re);
    auto end = std::sregex_iterator();

    for (auto it = begin; it != end; ++it) {
        agg.qmark_filter_count++;
        seen.insert((*it)[1].str());
    }

    for (const auto &a : seen) {
        agg.qmark_filter_attr_count[a]++;
    }
}

static void finalize_connection(Aggregator &agg, int cid, const std::string &reason) {
    auto it = agg.conn_state.find(cid);
    if (it == agg.conn_state.end())
        return;

    ConnState conn = it->second;
    agg.conn_state.erase(it);

    std::string app = conn.app;
    if (app.empty())
        app = conn.binddn;

    if (app.empty()) {
        auto iu = conn.track.find("USERNAME");
        if (iu != conn.track.end() && !iu->second.empty())
            app = iu->second;
    }
    if (app.empty()) {
        auto in = conn.track.find("NAME");
        if (in != conn.track.end() && !in->second.empty())
            app = in->second;
    }
    if (app.empty()) {
        auto ii = conn.track.find("IP");
        if (ii != conn.track.end() && !ii->second.empty())
            app = ii->second;
    }
    if (app.empty())
        app = "unknown";

    double total = conn.total_etime;

    int ops_count = static_cast<int>(conn.ops_count ? conn.ops_count : conn.completed_ops);
    if (!ops_count)
        ops_count = static_cast<int>(conn.ops.size());

    if (!agg.maxconnetime.has_value() || total > *agg.maxconnetime) {
        agg.maxconnetime = total;
        agg.maxconnetimeusr = app;
        std::ostringstream oss;
        oss << "conn=" << cid << " src=" << conn.src << " reason=" << reason;
        agg.maxconnopdesc = oss.str();
    }

    add_top_row(agg.top_conns, 20, TopConnRow{total, cid, app, conn.src, ops_count, conn.binddn, reason});
}

static void process_event(Aggregator &agg, const Event &ev) {
    agg.stats.lines++;

    if (!ev.ts.empty())
        update_time_bounds(agg, ev.ts);

    if (ev.kind == "UNKNOWN_LINE" || ev.kind == "UNKNOWN_OP") {
        agg.stats.unknown_lines++;
        return;
    }

    if (ev.kind == "GLOBAL_CONTROL") {
        agg.operation_count["GLOBAL_CONTROL"]++;
        agg.global_control_oid_count[ev.oid]++;
        return;
    }

    if (ev.kind == "TRACK") {
        if (!ev.conn.has_value())
            return;
        auto &conn = ensure_conn(agg, *ev.conn);
        conn.track = ev.track;

        if (conn.track.count("USERNAME") && !conn.track["USERNAME"].empty()) {
            conn.app = conn.track["USERNAME"];
        } else if (conn.track.count("NAME") && !conn.track["NAME"].empty()) {
            conn.app = conn.track["NAME"];
        }
        return;
    }

    if (ev.kind == "ACCEPT") {
        agg.stats.fd_open++;
        agg.stats.conn_count++;
        agg.active_connections++;
        if (agg.active_connections > agg.peak_active_connections) {
            agg.peak_active_connections = agg.active_connections;
        }

        if (!ev.conn.has_value())
            return;
        auto &conn = ensure_conn(agg, *ev.conn);
        conn.fd = ev.fd;
        conn.src = ev.src;
        agg.src_by_conn[*ev.conn] = ev.src;
        return;
    }

    if (ev.kind == "CLOSED") {
        agg.stats.fd_close++;
        if (agg.active_connections > 0)
            agg.active_connections--;
        if (ev.conn.has_value())
            finalize_connection(agg, *ev.conn, ev.reason);
        return;
    }

    if (ev.kind == "TLS") {
        agg.operation_count["TLS"]++;
        return;
    }

    if (ev.kind == "SASL") {
        agg.operation_count["SASL"]++;
        return;
    }

    if (ev.kind == "NOT_INDEXED") {
        agg.operation_count["NOT_INDEXED"]++;
        agg.not_indexed_count++;
        if (!ev.attrs.empty())
            agg.not_indexed_attr[ev.attrs]++;
        return;
    }

    if (ev.kind == "SYNCPROV") {
        agg.operation_count["SYNCPROV"]++;
        agg.stats.replication_logs++;
        return;
    }

    if (ev.kind == "CSN_GET") {
        agg.operation_count["CSN_GET"]++;
        agg.csn_event_count.get++;
        return;
    }

    if (ev.kind == "CSN_QUEUE") {
        agg.operation_count["CSN_QUEUE"]++;
        agg.csn_event_count.queue++;
        return;
    }

    if (ev.kind == "CSN_GRADUATE") {
        agg.operation_count["CSN_GRADUATE"]++;
        agg.csn_event_count.graduate++;
        return;
    }

    if (!ev.conn.has_value())
        return;

    int cid = *ev.conn;
    auto &conn = ensure_conn(agg, cid);

    OpState *op = nullptr;
    if (ev.op.has_value()) {
        op = &ensure_op(agg, cid, *ev.op);
    }

    if (ev.kind == "BIND") {
        agg.operation_count["BIND"]++;
        agg.read_write_stats.read++;
        if (ev.op.has_value())
            ensure_total_counted(agg, cid, *ev.op);

        std::string dn = dequote(ev.binddn);

        if (op) {
            op->type = "BIND";
            op->who = app_for_conn(agg, cid);
            op->binddn = ev.binddn;
            op->method = ev.method;
            op->authcid = ev.authcid;
            op->authzid = ev.authzid;
        }

        if (!dn.empty()) {
            conn.binddn = dn;
            if (!ev.authcid.empty())
                conn.authcid = ev.authcid;
            agg.binddn_by_conn[cid] = dn;

            if (conn.app.empty() || conn.app == "unknown") {
                conn.app = dn;
            }
        }

        return;
    }
    if (ev.kind == "BIND_DN_INFO") {
        std::string dn = dequote(ev.dn);

        if (op) {
            if (op->type.empty())
                op->type = "BIND";
            if (op->dn.empty())
                op->dn = dn;
            if (op->binddn.empty())
                op->binddn = dn;
            if (op->who.empty())
                op->who = app_for_conn(agg, cid);
        }

        if (!dn.empty()) {
            conn.binddn = dn;
            agg.binddn_by_conn[cid] = dn;
            if (conn.app.empty() || conn.app == "unknown") {
                conn.app = dn;
            }
        }

        return;
    }
    if (ev.kind == "BIND_ANON") {
        agg.operation_count["BIND ANONYMOUS"]++;
        agg.read_write_stats.read++;
        if (ev.op.has_value())
            ensure_total_counted(agg, cid, *ev.op);
        if (op) {
            op->type = "BIND";
            op->method = ev.method;
            op->who = app_for_conn(agg, cid);
        }
        return;
    }

    if (ev.kind == "BIND_AUTH") {
        if (op) {
            if (op->type.empty())
                op->type = "BIND";
            if (!ev.authcid.empty())
                op->authcid = ev.authcid;
            if (!ev.authzid.empty())
                op->authzid = ev.authzid;
            if (op->binddn.empty() && !ev.binddn.empty())
                op->binddn = ev.binddn;
            if (op->who.empty())
                op->who = app_for_conn(agg, cid);
        }

        if (!ev.authcid.empty()) {
            conn.authcid = ev.authcid;
        }

        if (!ev.binddn.empty() && conn.binddn.empty()) {
            std::string dn = dequote(ev.binddn);
            conn.binddn = dn;
            agg.binddn_by_conn[cid] = dn;
            if (conn.app.empty() || conn.app == "unknown") {
                conn.app = dn;
            }
        }

        return;
    }
    if (ev.kind == "SRCH") {
        agg.operation_count["SRCH"]++;
        agg.read_write_stats.read++;
        if (ev.op.has_value())
            ensure_total_counted(agg, cid, *ev.op);

        std::string base = ev.base.empty() ? "" : dequote(ev.base);
        std::string filter = ev.filter.empty() ? "" : dequote(ev.filter);

        if (op) {
            op->type = "SRCH";
            op->base = base;
            op->filter = filter;
            op->who = app_for_conn(agg, cid);
        }

        if (!base.empty())
            agg.base_count[base]++;
        if (!filter.empty())
            agg.filter_count[filter]++;

        if (!filter.empty()) {
            std::string nf = normalize_filter(filter);
            if (!nf.empty())
                agg.norm_filter_count[nf]++;
            if (nf.find('*') != std::string::npos)
                agg.wildcard_filter_count[nf]++;
            track_qmark_filter(agg, filter);
        }
        return;
    }

    if (ev.kind == "SRCH_ATTR") {
        agg.operation_count["SRCH ATTR"]++;
        if (op) {
            op->attrs = ev.attrs;
            std::istringstream iss(ev.attrs);
            std::string a;
            while (iss >> a) {
                agg.attr_count[a]++;
            }

            if (!op->filter.empty()) {
                std::string nf = normalize_filter(op->filter);
                std::string na = normalize_attrs(ev.attrs);
                std::string key = nf + " || " + na;
                if (!nf.empty() || !na.empty())
                    agg.norm_filter_attrs_count[key]++;
            }
        }
        return;
    }

    if (ev.kind == "ADD") {
        agg.operation_count["ADD"]++;
        agg.read_write_stats.write++;
        if (ev.op.has_value())
            ensure_total_counted(agg, cid, *ev.op);
        if (op) {
            op->type = "ADD";
            op->dn = dequote(ev.dn);
            op->who = app_for_conn(agg, cid);
        }
        return;
    }

    if (ev.kind == "DEL") {
        agg.operation_count["DEL"]++;
        agg.read_write_stats.write++;
        if (ev.op.has_value())
            ensure_total_counted(agg, cid, *ev.op);
        if (op) {
            op->type = "DEL";
            op->dn = dequote(ev.dn);
            op->who = app_for_conn(agg, cid);
        }
        return;
    }

    if (ev.kind == "MOD") {
        agg.operation_count["MOD"]++;
        agg.read_write_stats.write++;
        if (ev.op.has_value())
            ensure_total_counted(agg, cid, *ev.op);

        if (op) {
            op->type = "MOD";
            if (!ev.dn.empty())
                op->dn = dequote(ev.dn);
            if (!ev.attrs.empty()) {
                op->attrs = ev.attrs;
                std::istringstream iss(ev.attrs);
                std::string a;
                while (iss >> a) {
                    agg.attr_count[a]++;
                }
            }
            op->who = app_for_conn(agg, cid);
        }
        return;
    }

    if (ev.kind == "MODRDN") {
        agg.operation_count["MODRDN"]++;
        agg.read_write_stats.write++;
        if (ev.op.has_value())
            ensure_total_counted(agg, cid, *ev.op);
        if (op) {
            op->type = "MODRDN";
            op->dn = dequote(ev.dn);
            op->who = app_for_conn(agg, cid);
        }
        return;
    }

    if (ev.kind == "CMP") {
        agg.operation_count["CMP"]++;
        agg.read_write_stats.read++;
        if (ev.op.has_value())
            ensure_total_counted(agg, cid, *ev.op);
        if (op) {
            op->type = "CMP";
            op->dn = dequote(ev.dn);
            op->who = app_for_conn(agg, cid);
        }
        return;
    }

    if (ev.kind == "EXT") {
        agg.operation_count["EXT"]++;
        agg.read_write_stats.read++;
        if (ev.op.has_value())
            ensure_total_counted(agg, cid, *ev.op);
        if (op) {
            op->type = "EXT";
            op->oid = ev.oid;
            op->who = app_for_conn(agg, cid);
        }
        agg.ext_oid_count[ev.oid]++;
        return;
    }

    if (ev.kind == "ABANDON") {
        agg.operation_count["ABANDON"]++;
        agg.read_write_stats.read++;
        if (ev.op.has_value())
            ensure_total_counted(agg, cid, *ev.op);
        if (op) {
            op->type = "ABANDON";
            op->msgid = ev.msgid;
            op->who = app_for_conn(agg, cid);
        }
        return;
    }

    if (ev.kind == "UNBIND") {
        agg.operation_count["UNBIND"]++;
        if (ev.op.has_value())
            ensure_total_counted(agg, cid, *ev.op);
        if (op) {
            op->type = "UNBIND";
            op->who = app_for_conn(agg, cid);
        }
        return;
    }

    if (ev.kind == "RESULT" || ev.kind == "SEARCH_RESULT") {
        bool is_search = (ev.kind == "SEARCH_RESULT");

        if (is_search) {
            agg.operation_count["SEARCH RESULT"]++;
        } else {
            agg.operation_count["RESULT"]++;
        }

        if (op) {
            op->err = ev.err;
            op->tag = ev.tag;
            op->qtime = ev.qtime;
            op->etime = ev.etime;
            op->nentries = ev.nentries;
            op->text = ev.text;

            if (op->who.empty()) {
                op->who = app_for_conn(agg, cid);
            }
        }

        int err = ev.err.value_or(0);
        std::string who = app_for_conn(agg, cid);

        agg.error_count[err]++;
        agg.error_per_app[who][err]++;

        double etime = ev.etime.value_or(0.0);
        double qtime = ev.qtime.value_or(0.0);

        agg.etime_total += etime;
        agg.qtime_total += qtime;

        if (op) {
            conn.total_etime += etime;

            if (!agg.maxetime.has_value() || etime > *agg.maxetime) {
                agg.maxetime = etime;
                agg.maxetimeusr = who;

                std::ostringstream oss;
                oss << "conn=" << cid << " op=" << ev.op.value_or(0) << " type=" << op->type << " base=" << op->base
                    << " filter=" << op->filter << " err=" << err;
                agg.maxopdesc = oss.str();
            }

            if (!who.empty()) {
                agg.app_count[who]++;
                agg.app_etime_total[who] += etime;
            }

            if (!op->base.empty()) {
                agg.base_etime_total[op->base] += etime;
            }

            if (!op->filter.empty()) {
                agg.filter_etime_total[op->filter] += etime;

                std::string nf = normalize_filter(op->filter);
                if (!nf.empty()) {
                    agg.norm_filter_etime_total[nf] += etime;
                }

                if (!op->attrs.empty()) {
                    std::string na = normalize_attrs(op->attrs);
                    std::string key = nf + " || " + na;
                    if (!nf.empty() || !na.empty()) {
                        agg.norm_filter_attrs_count[key]++;
                    }
                }

                if (ev.nentries.has_value()) {
                    if (!nf.empty() && *ev.nentries == 1)
                        agg.norm_filter_n1_count[nf]++;
                    if (!nf.empty() && *ev.nentries == 0)
                        agg.norm_filter_n0_count[nf]++;
                }

                if (!nf.empty() && !who.empty()) {
                    agg.filter_by_app[who][nf]++;
                }
            }

            add_top_op(agg,
                    TopOpRow{etime, cid, ev.op.value_or(0), op->type, who, op->base, op->filter, op->nentries, err});

            conn.completed_ops++;
            if (ev.op.has_value()) {
                conn.ops.erase(*ev.op);
            }
        }

        return;
    }
}

static json finalize_report(Aggregator &agg) {
    std::vector<int> cids;
    cids.reserve(agg.conn_state.size());
    for (const auto &kv : agg.conn_state) {
        cids.push_back(kv.first);
    }

    for (int cid : cids) {
        finalize_connection(agg, cid, "eof");
    }

    json ldap_errors = json::object();
    for (const auto &kv : LDAP_ERRORS) {
        ldap_errors[std::to_string(kv.first)] = kv.second;
    }

    json ext_oid_name = json::object();
    for (const auto &kv : EXT_OID_NAME) {
        ext_oid_name[kv.first] = kv.second;
    }

    json report;
    report["stats"] = {{"lines", agg.stats.lines},
        {"fd_open", agg.stats.fd_open},
        {"fd_close", agg.stats.fd_close},
        {"conn_count", agg.stats.conn_count},
        {"unknown_lines", agg.stats.unknown_lines},
        {"replication_logs", agg.stats.replication_logs}};

    report["operation_count"] = agg.operation_count;
    report["read_write_stats"] = {{"read", agg.read_write_stats.read}, {"write", agg.read_write_stats.write}};
    json error_count_json = json::object();
    for (const auto &kv : agg.error_count) {
        error_count_json[std::to_string(kv.first)] = kv.second;
    }

    json error_per_app_json = json::object();
    for (const auto &app_kv : agg.error_per_app) {
        json per_app = json::object();
        for (const auto &err_kv : app_kv.second) {
            per_app[std::to_string(err_kv.first)] = err_kv.second;
        }
        error_per_app_json[app_kv.first] = per_app;
    }

    report["error_count"] = error_count_json;
    report["error_per_app"] = error_per_app_json;
    report["ldap_errors"] = ldap_errors;
    report["ext_oid_name"] = ext_oid_name;
    report["top_ops"] = json::array();
    report["top_conns"] = json::array();

    report["firsttime"] = agg.firsttime;
    report["lasttime"] = agg.lasttime;
    report["maxetime"] = agg.maxetime.has_value() ? json(*agg.maxetime) : json(nullptr);
    report["maxetimeusr"] = agg.maxetimeusr;
    report["maxopdesc"] = agg.maxopdesc;
    report["maxconnetime"] = agg.maxconnetime.has_value() ? json(*agg.maxconnetime) : json(nullptr);
    report["maxconnetimeusr"] = agg.maxconnetimeusr;
    report["maxconnopdesc"] = agg.maxconnopdesc;
    report["etime_total"] = agg.etime_total;
    report["qtime_total"] = agg.qtime_total;
    report["app_count"] = agg.app_count;
    report["app_etime_total"] = agg.app_etime_total;
    report["base_count"] = agg.base_count;
    report["base_etime_total"] = agg.base_etime_total;
    report["filter_count"] = agg.filter_count;
    report["filter_etime_total"] = agg.filter_etime_total;
    report["norm_filter_count"] = agg.norm_filter_count;
    report["norm_filter_etime_total"] = agg.norm_filter_etime_total;
    report["norm_filter_attrs_count"] = agg.norm_filter_attrs_count;
    report["norm_filter_n1_count"] = agg.norm_filter_n1_count;
    report["norm_filter_n0_count"] = agg.norm_filter_n0_count;
    report["wildcard_filter_count"] = agg.wildcard_filter_count;
    report["filter_by_app"] = agg.filter_by_app;
    report["attr_count"] = agg.attr_count;
    report["qmark_filter_count"] = agg.qmark_filter_count;
    report["qmark_filter_attr_count"] = agg.qmark_filter_attr_count;
    report["ext_oid_count"] = agg.ext_oid_count;
    report["global_control_oid_count"] = agg.global_control_oid_count;
    report["csn_event_count"] = {{"get", agg.csn_event_count.get},
        {"queue", agg.csn_event_count.queue},
        {"graduate", agg.csn_event_count.graduate}};
    report["not_indexed_count"] = agg.not_indexed_count;
    report["not_indexed_attr"] = agg.not_indexed_attr;
    report["peak_active_connections"] = agg.peak_active_connections;

    for (const auto &r : agg.top_ops) {
        report["top_ops"].push_back({{"etime", r.etime},
                {"conn", r.conn},
                {"op", r.op},
                {"type", r.type},
                {"who", r.who},
                {"base", r.base},
                {"filter", r.filter},
                {"nentries", r.nentries.has_value() ? json(*r.nentries) : json(nullptr)},
                {"err", r.err.has_value() ? json(*r.err) : json(nullptr)}});
    }

    for (const auto &r : agg.top_conns) {
        report["top_conns"].push_back({{"total_etime", r.total_etime},
                {"conn", r.conn},
                {"who", r.who},
                {"src", r.src},
                {"ops_count", r.ops_count},
                {"binddn", r.binddn},
                {"reason", r.reason}});
    }

    return report;
}

static std::string sep(const std::vector<size_t> &widths) {
    std::ostringstream oss;
    oss << "+";
    for (auto w : widths) {
        oss << std::string(w + 2, '-') << "+";
    }
    oss << "\n";
    return oss.str();
}

static void print_table(const std::vector<std::string> &headers, const std::vector<std::vector<std::string>> &rows) {
    std::vector<size_t> widths(headers.size(), 0);
    for (size_t i = 0; i < headers.size(); ++i) {
        widths[i] = headers[i].size();
    }

    for (const auto &row : rows) {
        for (size_t i = 0; i < row.size() && i < widths.size(); ++i) {
            widths[i] = std::max(widths[i], row[i].size());
        }
    }

    std::cout << sep(widths);
    std::cout << "| ";
    for (size_t i = 0; i < headers.size(); ++i) {
        std::cout << std::left << std::setw(static_cast<int>(widths[i])) << headers[i] << " | ";
    }
    std::cout << "\n";
    std::cout << sep(widths);

    for (const auto &row : rows) {
        std::cout << "| ";
        for (size_t i = 0; i < headers.size(); ++i) {
            std::string v = i < row.size() ? row[i] : "";
            std::cout << std::left << std::setw(static_cast<int>(widths[i])) << v << " | ";
        }
        std::cout << "\n";
    }
    std::cout << sep(widths);
}

static void print_kv_block(const std::string &title, const std::vector<std::pair<std::string, std::string>> &pairs) {
    std::cout << "\n" << title << "\n";
    std::cout << std::string(title.size(), '=') << "\n";

    std::vector<std::vector<std::string>> rows;
    for (const auto &p : pairs) {
        rows.push_back({p.first, p.second});
    }
    print_table({"Key", "Value"}, rows);
}

static std::vector<std::pair<std::string, long long>> top_rows_from_map(const std::map<std::string, long long> &m,
        size_t limit = 20) {
    std::vector<std::pair<std::string, long long>> rows(m.begin(), m.end());
    std::sort(rows.begin(), rows.end(), [](const auto &a, const auto &b) {
            if (a.second != b.second)
            return a.second > b.second;
            return a.first < b.first;
            });
    if (rows.size() > limit)
        rows.resize(limit);
    return rows;
}

static std::string fmt6(double v) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6) << v;
    return oss.str();
}

static void render_text(const std::string &file, const json &report, double duration) {
    std::cout << "\nLDAP Log Analysis Report\n";
    std::cout << "========================\n";

    print_kv_block(
            "Run summary",
            {{"File", file},
            {"Lines processed", std::to_string(report["stats"]["lines"].get<long long>())},
            {"Elapsed time (s)", ([duration] {
                    std::ostringstream o;
                    o << std::fixed << std::setprecision(3) << duration;
                    return o.str();
                    })()},
            {"Processing speed (l/s)",
            std::to_string(duration > 0 ? static_cast<long long>(report["stats"]["lines"].get<long long>() / duration)
                    : 0)},
            {"Start time", report.value("firsttime", "")},
            {"End time", report.value("lasttime", "")}});

    print_kv_block("Connection summary",
            {{"Connections accepted", std::to_string(report["stats"]["conn_count"].get<long long>())},
            {"File descriptors opened", std::to_string(report["stats"]["fd_open"].get<long long>())},
            {"File descriptors closed", std::to_string(report["stats"]["fd_close"].get<long long>())},
            {"Peak active connections", std::to_string(report.value("peak_active_connections", 0LL))}});

    print_kv_block(
            "Performance summary",
            {{"Total etime", fmt6(report.value("etime_total", 0.0))},
            {"Total qtime", fmt6(report.value("qtime_total", 0.0))},
            {"Max single operation etime", report["maxetime"].is_null() ? "" : fmt6(report["maxetime"].get<double>())},
            {"User/application with max etime", report.value("maxetimeusr", "")},
            {"Operation with max etime", report.value("maxopdesc", "")},
            {"Max cumulative connection etime",
            report["maxconnetime"].is_null() ? "" : fmt6(report["maxconnetime"].get<double>())},
            {"User/application with max cumulative etime", report.value("maxconnetimeusr", "")},
            {"Connection with max cumulative etime", report.value("maxconnopdesc", "")}});

    std::cout << "\nOperation counts\n";
    std::cout << "================\n";
    std::vector<std::vector<std::string>> op_rows;
    std::vector<std::pair<std::string, long long>> ops;
    for (auto it = report["operation_count"].begin(); it != report["operation_count"].end(); ++it) {
        ops.push_back({it.key(), it.value().get<long long>()});
    }
    std::sort(ops.begin(), ops.end(), [](const auto &a, const auto &b) {
            if (a.second != b.second)
            return a.second > b.second;
            return a.first < b.first;
            });
    for (const auto &p : ops)
        op_rows.push_back({p.first, std::to_string(p.second)});
    print_table({"Operation", "Count"}, op_rows);

    print_kv_block("Read/write summary",
            {{"Read operations", std::to_string(report["read_write_stats"]["read"].get<long long>())},
            {"Write operations", std::to_string(report["read_write_stats"]["write"].get<long long>())},
            {"Unknown log lines", std::to_string(report["stats"]["unknown_lines"].get<long long>())}});

    if (!report["error_count"].empty()) {
        std::cout << "\nLDAP errors\n";
        std::cout << "===========\n";
        std::vector<std::vector<std::string>> rows;
        std::vector<std::pair<int, long long>> errs;
        for (auto it = report["error_count"].begin(); it != report["error_count"].end(); ++it) {
            errs.push_back({std::stoi(it.key()), it.value().get<long long>()});
        }
        std::sort(errs.begin(), errs.end(), [](const auto &a, const auto &b) {
                if (a.second != b.second)
                return a.second > b.second;
                return a.first < b.first;
                });
        for (const auto &e : errs) {
            std::string code = std::to_string(e.first);
            rows.push_back({code, report["ldap_errors"].value(code, "unknown"), std::to_string(e.second)});
        }
        print_table({"Code", "Name", "Count"}, rows);
    }

    auto print_string_count_map = [&](const std::string &title, const std::string &col1, const json &obj,
            size_t limit) {
        if (obj.empty())
            return;
        std::cout << "\n" << title << "\n";
        std::cout << std::string(title.size(), '=') << "\n";
        std::map<std::string, long long> m;
        for (auto it = obj.begin(); it != obj.end(); ++it)
            m[it.key()] = it.value().get<long long>();
        auto top = top_rows_from_map(m, limit);
        std::vector<std::vector<std::string>> rows;
        for (const auto &p : top)
            rows.push_back({p.first, std::to_string(p.second)});
        print_table({col1, "Count"}, rows);
    };

    if (!report["app_count"].empty()) {
        std::cout << "\nTop applications\n";
        std::cout << "================\n";
        std::map<std::string, long long> m;
        for (auto it = report["app_count"].begin(); it != report["app_count"].end(); ++it) {
            m[it.key()] = it.value().get<long long>();
        }
        auto top = top_rows_from_map(m, 20);
        std::vector<std::vector<std::string>> rows;
        for (const auto &p : top)
            rows.push_back({p.first, std::to_string(p.second)});
        print_table({"Application", "Count"}, rows);
    }

    if (!report["app_etime_total"].empty()) {
        std::cout << "\nApplications by cumulative etime\n";
        std::cout << "================================\n";
        std::vector<std::pair<std::string, double>> rows0;
        for (auto it = report["app_etime_total"].begin(); it != report["app_etime_total"].end(); ++it) {
            rows0.push_back({it.key(), it.value().get<double>()});
        }
        std::sort(rows0.begin(), rows0.end(), [](const auto &a, const auto &b) {
                if (a.second != b.second)
                return a.second > b.second;
                return a.first < b.first;
                });
        if (rows0.size() > 20)
            rows0.resize(20);

        std::vector<std::vector<std::string>> rows;
        for (const auto &p : rows0)
            rows.push_back({p.first, fmt6(p.second)});
        print_table({"Application", "Cumulative etime"}, rows);
    }

    print_string_count_map("Top requested attributes", "Attribute", report["attr_count"], 25);
    print_string_count_map("Top normalized search filters", "Normalized filter", report["norm_filter_count"], 25);

    if (!report["norm_filter_etime_total"].empty()) {
        std::cout << "\nTop normalized filters by cumulative etime\n";
        std::cout << "==========================================\n";
        std::vector<std::pair<std::string, double>> rows0;
        for (auto it = report["norm_filter_etime_total"].begin(); it != report["norm_filter_etime_total"].end(); ++it) {
            rows0.push_back({it.key(), it.value().get<double>()});
        }
        std::sort(rows0.begin(), rows0.end(), [](const auto &a, const auto &b) {
                if (a.second != b.second)
                return a.second > b.second;
                return a.first < b.first;
                });
        if (rows0.size() > 25)
            rows0.resize(25);

        std::vector<std::vector<std::string>> rows;
        for (const auto &p : rows0)
            rows.push_back({p.first, fmt6(p.second)});
        print_table({"Normalized filter", "Cumulative etime"}, rows);
    }

    print_string_count_map("Top normalized filter + normalized requested attrs", "Normalized filter || attrs",
            report["norm_filter_attrs_count"], 25);

    print_string_count_map("Top normalized filters where nentries = 1", "Normalized filter",
            report["norm_filter_n1_count"], 25);

    print_string_count_map("Top normalized filters where nentries = 0", "Normalized filter",
            report["norm_filter_n0_count"], 25);

    print_string_count_map("Top wildcard filters", "Filter", report["wildcard_filter_count"], 25);

    if (!report["filter_by_app"].empty()) {
        std::cout << "\nTop filters by application\n";
        std::cout << "==========================\n";
        std::vector<std::vector<std::string>> rows;
        for (auto it = report["filter_by_app"].begin(); it != report["filter_by_app"].end(); ++it) {
            std::map<std::string, long long> sub;
            for (auto it2 = it.value().begin(); it2 != it.value().end(); ++it2) {
                sub[it2.key()] = it2.value().get<long long>();
            }
            auto top = top_rows_from_map(sub, 5);
            for (const auto &p : top) {
                rows.push_back({it.key(), p.first, std::to_string(p.second)});
            }
        }
        if (!rows.empty())
            print_table({"Application", "Filter", "Count"}, rows);
    }

    print_string_count_map("Top search bases", "Base", report["base_count"], 20);

    if (!report["base_etime_total"].empty()) {
        std::cout << "\nTop search bases by cumulative etime\n";
        std::cout << "===================================\n";
        std::vector<std::pair<std::string, double>> rows0;
        for (auto it = report["base_etime_total"].begin(); it != report["base_etime_total"].end(); ++it) {
            rows0.push_back({it.key(), it.value().get<double>()});
        }
        std::sort(rows0.begin(), rows0.end(), [](const auto &a, const auto &b) {
                if (a.second != b.second)
                return a.second > b.second;
                return a.first < b.first;
                });
        if (rows0.size() > 20)
            rows0.resize(20);

        std::vector<std::vector<std::string>> rows;
        for (const auto &p : rows0)
            rows.push_back({p.first, fmt6(p.second)});
        print_table({"Base", "Cumulative etime"}, rows);
    }

    print_string_count_map("Top raw search filters", "Filter", report["filter_count"], 20);

    if (!report["filter_etime_total"].empty()) {
        std::cout << "\nTop raw search filters by cumulative etime\n";
        std::cout << "==========================================\n";
        std::vector<std::pair<std::string, double>> rows0;
        for (auto it = report["filter_etime_total"].begin(); it != report["filter_etime_total"].end(); ++it) {
            rows0.push_back({it.key(), it.value().get<double>()});
        }
        std::sort(rows0.begin(), rows0.end(), [](const auto &a, const auto &b) {
                if (a.second != b.second)
                return a.second > b.second;
                return a.first < b.first;
                });
        if (rows0.size() > 20)
            rows0.resize(20);

        std::vector<std::vector<std::string>> rows;
        for (const auto &p : rows0)
            rows.push_back({p.first, fmt6(p.second)});
        print_table({"Filter", "Cumulative etime"}, rows);
    }

    if (!report["ext_oid_count"].empty()) {
        std::cout << "\nExtended operations by OID\n";
        std::cout << "==========================\n";
        std::vector<std::vector<std::string>> rows;
        std::vector<std::pair<std::string, long long>> tmp;
        for (auto it = report["ext_oid_count"].begin(); it != report["ext_oid_count"].end(); ++it) {
            tmp.push_back({it.key(), it.value().get<long long>()});
        }
        std::sort(tmp.begin(), tmp.end(), [](const auto &a, const auto &b) {
                if (a.second != b.second)
                return a.second > b.second;
                return a.first < b.first;
                });
        for (const auto &p : tmp) {
            rows.push_back({p.first, report["ext_oid_name"].value(p.first, ""), std::to_string(p.second)});
        }
        print_table({"OID", "Name", "Count"}, rows);
    }

    if (!report["global_control_oid_count"].empty()) {
        std::cout << "\nGlobal control warnings by OID\n";
        std::cout << "==============================\n";
        std::map<std::string, long long> m;
        for (auto it = report["global_control_oid_count"].begin(); it != report["global_control_oid_count"].end();
                ++it) {
            m[it.key()] = it.value().get<long long>();
        }
        auto top = top_rows_from_map(m, 1000);
        std::vector<std::vector<std::string>> rows;
        for (const auto &p : top)
            rows.push_back({p.first, std::to_string(p.second)});
        print_table({"OID", "Count"}, rows);
    }

    print_kv_block("Search filters with question-mark attributes",
            {{"Filters containing (?attr=", std::to_string(report.value("qmark_filter_count", 0LL))}});

    print_string_count_map("Question-mark filter attributes", "Attribute", report["qmark_filter_attr_count"], 20);

    print_kv_block("CSN internal events",
            {{"CSN get", std::to_string(report["csn_event_count"]["get"].get<long long>())},
            {"CSN queue", std::to_string(report["csn_event_count"]["queue"].get<long long>())},
            {"CSN graduate", std::to_string(report["csn_event_count"]["graduate"].get<long long>())}});

    print_kv_block("Indexing diagnostics",
            {{"Not indexed occurrences", std::to_string(report.value("not_indexed_count", 0LL))}});

    print_string_count_map("Not indexed attributes", "Attribute", report["not_indexed_attr"], 20);

    if (!report["top_ops"].empty()) {
        std::cout << "\nTop long operations\n";
        std::cout << "===================\n";
        std::vector<std::vector<std::string>> rows;
        for (const auto &r : report["top_ops"]) {
            rows.push_back({fmt6(r.value("etime", 0.0)), std::to_string(r.value("conn", 0)),
                    std::to_string(r.value("op", 0)), r.value("type", ""), r.value("who", ""),
                    r["nentries"].is_null() ? "" : std::to_string(r["nentries"].get<int>()),
                    r["err"].is_null() ? "" : std::to_string(r["err"].get<int>()), r.value("base", ""),
                    r.value("filter", "")});
        }
        print_table({"etime", "conn", "op", "type", "who", "nentries", "err", "base", "filter"}, rows);
    }

    if (!report["top_conns"].empty()) {
        std::cout << "\nTop connections by cumulative etime\n";
        std::cout << "==================================\n";
        std::vector<std::vector<std::string>> rows;
        for (const auto &r : report["top_conns"]) {
            rows.push_back({fmt6(r.value("total_etime", 0.0)), std::to_string(r.value("conn", 0)), r.value("who", ""),
                    r.value("src", ""), std::to_string(r.value("ops_count", 0)), r.value("binddn", "")});
        }
        print_table({"total etime", "conn", "who", "src", "ops", "binddn"}, rows);
    }
}

static std::string build_dynatrace_payload(const std::string &file, const json &report) {
    json records = json::array();

    records.push_back({{"content", "ldap_log_summary"},
            {"slaplog",
            {{"file", file},
            {"lines", report["stats"]["lines"]},
            {"fd_open", report["stats"]["fd_open"]},
            {"fd_close", report["stats"]["fd_close"]},
            {"conn_count", report["stats"]["conn_count"]},
            {"unknown_lines", report["stats"]["unknown_lines"]},
            {"replication_logs", report["stats"]["replication_logs"]},
            {"firsttime", report["firsttime"]},
            {"lasttime", report["lasttime"]},
            {"etime_total", report["etime_total"]},
            {"qtime_total", report["qtime_total"]},
            {"maxetime", report["maxetime"]},
            {"maxetimeusr", report["maxetimeusr"]},
            {"maxconnetime", report["maxconnetime"]},
            {"maxconnetimeusr", report["maxconnetimeusr"]},
            {"peak_active_connections", report["peak_active_connections"]},
            {"qmark_filter_count", report.value("qmark_filter_count", 0LL)},
            {"not_indexed_count", report.value("not_indexed_count", 0LL)}}}});

    for (auto it = report["operation_count"].begin(); it != report["operation_count"].end(); ++it) {
        records.push_back(
                {{"content", "ldap_operation_count"}, {"slaplog", {{"operation", it.key()}, {"count", it.value()}}}});
    }

    for (auto it = report["error_count"].begin(); it != report["error_count"].end(); ++it) {
        records.push_back({{"content", "ldap_error_count"},
                {"slaplog",
                {{"code", it.key()},
                {"name", report["ldap_errors"].value(it.key(), "unknown")},
                {"count", it.value()}}}});
    }

    for (auto it = report["ext_oid_count"].begin(); it != report["ext_oid_count"].end(); ++it) {
        records.push_back(
                {{"content", "ldap_extended_operation"},
                {"slaplog",
                {{"oid", it.key()}, {"name", report["ext_oid_name"].value(it.key(), "")}, {"count", it.value()}}}});
    }

    for (auto it = report["global_control_oid_count"].begin(); it != report["global_control_oid_count"].end(); ++it) {
        records.push_back(
                {{"content", "ldap_global_control_warning"}, {"slaplog", {{"oid", it.key()}, {"count", it.value()}}}});
    }

    for (auto it = report["attr_count"].begin(); it != report["attr_count"].end(); ++it) {
        records.push_back(
                {{"content", "ldap_requested_attribute"}, {"slaplog", {{"attribute", it.key()}, {"count", it.value()}}}});
    }

    for (auto it = report["norm_filter_count"].begin(); it != report["norm_filter_count"].end(); ++it) {
        records.push_back(
                {{"content", "ldap_normalized_filter"}, {"slaplog", {{"filter", it.key()}, {"count", it.value()}}}});
    }

    for (auto it = report["norm_filter_n1_count"].begin(); it != report["norm_filter_n1_count"].end(); ++it) {
        records.push_back({{"content", "ldap_normalized_filter_nentries_1"},
                {"slaplog", {{"filter", it.key()}, {"count", it.value()}}}});
    }

    for (auto it = report["norm_filter_n0_count"].begin(); it != report["norm_filter_n0_count"].end(); ++it) {
        records.push_back({{"content", "ldap_normalized_filter_nentries_0"},
                {"slaplog", {{"filter", it.key()}, {"count", it.value()}}}});
    }

    for (auto it = report["wildcard_filter_count"].begin(); it != report["wildcard_filter_count"].end(); ++it) {
        records.push_back(
                {{"content", "ldap_wildcard_filter"}, {"slaplog", {{"filter", it.key()}, {"count", it.value()}}}});
    }

    for (auto it = report["base_count"].begin(); it != report["base_count"].end(); ++it) {
        records.push_back(
                {{"content", "ldap_search_base_count"}, {"slaplog", {{"base", it.key()}, {"count", it.value()}}}});
    }

    for (auto it = report["base_etime_total"].begin(); it != report["base_etime_total"].end(); ++it) {
        records.push_back(
                {{"content", "ldap_search_base_etime"}, {"slaplog", {{"base", it.key()}, {"etime_total", it.value()}}}});
    }

    for (auto it = report["filter_count"].begin(); it != report["filter_count"].end(); ++it) {
        records.push_back(
                {{"content", "ldap_raw_filter_count"}, {"slaplog", {{"filter", it.key()}, {"count", it.value()}}}});
    }

    for (auto it = report["filter_etime_total"].begin(); it != report["filter_etime_total"].end(); ++it) {
        records.push_back(
                {{"content", "ldap_raw_filter_etime"}, {"slaplog", {{"filter", it.key()}, {"etime_total", it.value()}}}});
    }

    for (auto it = report["qmark_filter_attr_count"].begin(); it != report["qmark_filter_attr_count"].end(); ++it) {
        records.push_back({{"content", "ldap_qmark_filter_attribute"},
                {"slaplog", {{"attribute", it.key()}, {"count", it.value()}}}});
    }

    for (auto it = report["not_indexed_attr"].begin(); it != report["not_indexed_attr"].end(); ++it) {
        records.push_back(
                {{"content", "ldap_not_indexed_attribute"}, {"slaplog", {{"attribute", it.key()}, {"count", it.value()}}}});
    }

    for (const auto &op : report["top_ops"]) {
        records.push_back({{"content", "ldap_top_operation"},
                {"slaplog",
                {{"etime", op.value("etime", 0.0)},
                {"conn", op.value("conn", 0)},
                {"op", op.value("op", 0)},
                {"type", op.value("type", "")},
                {"who", op.value("who", "")},
                {"base", op.value("base", "")},
                {"filter", op.value("filter", "")},
                {"nentries", op["nentries"]},
                {"err", op["err"]}}}});
    }

    for (const auto &conn : report["top_conns"]) {
        records.push_back({{"content", "ldap_top_connection"},
                {"slaplog",
                {{"total_etime", conn.value("total_etime", 0.0)},
                {"conn", conn.value("conn", 0)},
                {"who", conn.value("who", "")},
                {"src", conn.value("src", "")},
                {"ops_count", conn.value("ops_count", 0)},
                {"binddn", conn.value("binddn", "")}}}});
    }

    return records.dump();
}

struct Options {
    bool debug = false;
    std::string outputformat = "text";
    bool recursive = false;
    bool per_file = false;
    bool per_file_summary_only = false;
    std::string unknown_lines_file;
    bool unknown_only = false;
    bool help = false;
    bool show_version = false;
    std::vector<std::string> inputs;
};

static bool parse_args(int argc, char **argv, Options &opt) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];

        if (a == "-d" || a == "--debug") {
            opt.debug = true;
        } else if ((a == "-o" || a == "--output") && i + 1 < argc) {
            opt.outputformat = argv[++i];
        } else if (a == "-r" || a == "--recursive") {
            opt.recursive = true;
        } else if (a == "--per-file") {
            opt.per_file = true;
        } else if (a == "--per-file-summary-only") {
            opt.per_file_summary_only = true;
        } else if (a == "--unknown-lines" && i + 1 < argc) {
            opt.unknown_lines_file = argv[++i];
        } else if (a == "--unknown-only") {
            opt.unknown_only = true;
        } else if (a == "-h" || a == "--help") {
            opt.help = true;
        } else if (a == "-V" || a == "--version") {
            opt.show_version = true;
        } else if (!a.empty() && a[0] == '-') {
            return false;
        } else {
            opt.inputs.push_back(a);
        }
    }
    return true;
}

int main(int argc, char **argv) {
    // Estimate total lines (you'd do this in a pre-analysis step)
    size_t estimated_total_lines = 100000; // From file size or header scan
                                           // Callback to update UI (e.g., stdout, Qt, etc.)
    auto print_progress = [](float percent) {
        std::cout << "\rProgress: [" << std::string(static_cast<int>(percent), '=')
            << std::string(100 - static_cast<int>(percent), ' ') << "] "
            << std::fixed << std::setprecision(1) << percent << "%";
        std::cout.flush();
    };
    // Create manager
    // ProgressBarManager pb_manager(estimated_total_lines, print_progress);

    Options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return 1;
    }

    if (opt.help) {
        usage(argv[0]);
        return 0;
    }

    if (opt.show_version) {
        std::cout << VERSION << "\n";
        return 0;
    }

    opt.outputformat = normalize_output(opt.outputformat);

    if (opt.inputs.empty()) {
        usage(argv[0]);
        return 1;
    }

    std::vector<std::string> files = collect_input_files(opt.inputs, opt.recursive);
    if (files.empty()) {
        std::cerr << "No input files found\n";
        return 1;
    }

    std::string input_label = files.size() == 1 ? files[0] : std::to_string(files.size()) + " files";

    Aggregator agg = new_aggregator();
    std::map<std::string, Aggregator> file_aggs;
    json file_meta = json::object();

    std::unique_ptr<std::ofstream> unknown_ofs;
    std::ostream *unknown_out = nullptr;
    if (!opt.unknown_lines_file.empty()) {
        unknown_ofs = std::make_unique<std::ofstream>(opt.unknown_lines_file);
        if (!*unknown_ofs) {
            std::cerr << "Cannot open " << opt.unknown_lines_file << "\n";
            return 1;
        }
        unknown_out = unknown_ofs.get();
    }

    auto t0 = std::chrono::steady_clock::now();
    const long long progress_every = 1000000;
    size_t file_index = 0;

    for (const auto &file : files) {
        ++file_index;
        CompressionType ctype = detect_compression_type(file);
        std::cerr << "Processing file " << file_index << "/" << files.size() << ": " << file
            << " [type=" << compression_to_string(ctype) << "]\n";

        auto file_t0 = std::chrono::steady_clock::now();
        long long file_lines = 0;

        if (opt.per_file || opt.per_file_summary_only) {
            file_aggs[file] = new_aggregator();
        }

        try {
            LineReader reader(file, ctype);
            std::string line;

            while (reader.getline(line)) {
                ++file_lines;

                Event ev = parse_line(line);

                if (unknown_out && (ev.kind == "UNKNOWN_LINE" || ev.kind == "UNKNOWN_OP")) {
                    std::string raw = !ev.raw.empty() ? ev.raw : line;
                    *unknown_out << file << "\t" << ev.kind << "\t" << raw << "\n";
                }

                // Progress bar
                pb_manager.update_line();

                process_event(agg, ev);

                if (opt.per_file || opt.per_file_summary_only) {
                    process_event(file_aggs[file], ev);
                }

                if ((agg.stats.lines % progress_every) == 0) {
                    std::cerr << "Done so far: " << agg.stats.lines << " lines total | current file: " << file_lines
                        << " | " << file << "\n";
                }
            }
        } catch (const std::exception &e) {
            std::cerr << "Error processing " << file << ": " << e.what() << "\n";
            return 1;
        }

        auto file_t1 = std::chrono::steady_clock::now();
        double file_duration = std::chrono::duration<double>(file_t1 - file_t0).count();

        file_meta[file] = {{"lines", file_lines}, {"duration", file_duration}, {"type", compression_to_string(ctype)}};

        std::cerr << "Completed file: " << file << " [type=" << compression_to_string(ctype)
            << "] | lines read: " << file_lines << "\n";
    }

    auto t1 = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double>(t1 - t0).count();

    if (opt.unknown_only) {
        std::cerr << "Unknown-only scan completed in " << duration << " s\n";
        return 0;
    }

    json report = finalize_report(agg);

    if (opt.per_file || opt.per_file_summary_only) {
        json per_file_reports = json::object();

        for (const auto &file : files) {
            auto r = finalize_report(file_aggs[file]);
            per_file_reports[file] = r;
        }

        report["per_file_reports"] = per_file_reports;
        report["per_file_meta"] = file_meta;
        report["per_file_summary_only"] = opt.per_file_summary_only ? 1 : 0;
    }

    if (opt.outputformat == "text" || opt.outputformat == "textdynatrace") {
        render_text(input_label, report, duration);
    }

    if (opt.outputformat == "dynatrace" || opt.outputformat == "textdynatrace") {
        std::cout << build_dynatrace_payload(input_label, report) << "\n";
    }

    return 0;
}
