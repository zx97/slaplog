// dialect_opendj.cpp
//
// OpenDJ / ForgeRock DS / PingDS / Oracle Unified Directory access log (the
// OpenDS family).  Default text format, one message per line:
//
//   [dd/MMM/yyyy:HH:mm:ss[.SSS] +HHMM] CONNECT conn=N from=ip:port to=ip:port protocol=LDAP
//   [..] BIND REQ conn=N op=M msgID=K version=3 type=SIMPLE dn="..."
//   [..] BIND RES conn=N op=M msgID=K result=0 authDN="..." etime=<ms>
//   [..] SEARCH REQ conn=N op=M msgID=K base="..." scope=wholeSubtree filter="..." attrs="ALL"
//   [..] SEARCH RES conn=N op=M msgID=K result=0 nentries=1 etime=<ms>
//   [..] DISCONNECT conn=N reason="Client Unbind"
//
// `etime` is in milliseconds (the server's elapsedTimeUnits is MILLISECONDS);
// Event keeps seconds, like every other format.  Values are key=value pairs,
// quoted when they can contain spaces, and their order is not relied upon.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "dialect.hpp"
#include "log_parser.hpp"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {


bool space(std::string_view& s) {
    size_t i = 0;
    while (i < s.size() && s[i] == ' ') ++i;
    s.remove_prefix(i);
    return i > 0;
}


bool quoted(std::string_view& s, std::string& out) {
    if (s.empty() || s[0] != '"') return false;
    const size_t end = s.find('"', 1);
    if (end == std::string_view::npos) return false;
    out.assign(s.data() + 1, end - 1);
    s.remove_prefix(end + 1);
    return true;
}

// One space-delimited token, quotes not special.
std::string_view token(std::string_view& s) {
    const size_t sp = s.find(' ');
    std::string_view v = (sp == std::string_view::npos) ? s : s.substr(0, sp);
    s.remove_prefix(sp == std::string_view::npos ? s.size() : sp);
    return v;
}

int int_of(std::string_view v) {
    long r = 0;
    bool neg = false;
    size_t i = 0;
    if (i < v.size() && v[i] == '-') { neg = true; ++i; }
    for (; i < v.size() && v[i] >= '0' && v[i] <= '9'; ++i) {
        r = r * 10 + (v[i] - '0');
        if (r > 2147483647L) return 0;
    }
    return static_cast<int>(neg ? -r : r);
}

// Howard Hinnant's civil-date arithmetic (same as the core file).
long long days_from_civil(long long y, long long m, long long d) {
    y -= (m <= 2);
    const long long era = (y >= 0 ? y : y - 399) / 400;
    const long long yoe = y - era * 400;
    const long long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const long long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

// "[20/Apr/2012:13:31:05 +0200]" or with milliseconds -> RFC3339 UTC.
bool parse_opendj_time(std::string_view ts, std::string& out) {
    const std::string text(ts);
    int day = 0, year = 0, hh = 0, mi = 0, ss = 0, used = 0;
    char mon[4] = {};
    if (std::sscanf(text.c_str(), "%2d/%3[A-Za-z]/%4d:%2d:%2d:%2d%n",
                    &day, mon, &year, &hh, &mi, &ss, &used) != 6)
        return false;
    size_t p = static_cast<size_t>(used);
    long long frac = 0;
    if (p < ts.size() && ts[p] == '.') {
        ++p;
        int digits = 0;
        while (p < ts.size() && ts[p] >= '0' && ts[p] <= '9') {
            if (digits < 9) { frac = frac * 10 + (ts[p] - '0'); ++digits; }
            ++p;
        }
        if (digits == 0) return false;
        while (digits++ < 9) frac *= 10;
    }
    while (p < ts.size() && std::isspace(static_cast<unsigned char>(ts[p]))) ++p;
    if (p >= ts.size() || (ts[p] != '+' && ts[p] != '-')) return false;
    const int sign = ts[p] == '-' ? -1 : 1;
    ++p;
    if (p + 4 > ts.size()) return false;
    for (int i = 0; i < 4; ++i)
        if (ts[p + static_cast<size_t>(i)] < '0' || ts[p + static_cast<size_t>(i)] > '9')
            return false;
    const int oh = (ts[p] - '0') * 10 + (ts[p + 1] - '0');
    const int om = (ts[p + 2] - '0') * 10 + (ts[p + 3] - '0');
    p += 4;
    while (p < ts.size() && std::isspace(static_cast<unsigned char>(ts[p]))) ++p;
    if (p != ts.size() || oh > 23 || om > 59) return false;

    static const char* kMonths[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    int mo = 0;
    for (int i = 0; i < 12; ++i)
        if (std::strncmp(mon, kMonths[i], 3) == 0) { mo = i + 1; break; }
    if (mo == 0 || day < 1 || day > 31 || hh > 23 || mi > 59 || ss > 60)
        return false;

    const long long epoch = days_from_civil(year, mo, day) * 86400LL +
                            hh * 3600LL + mi * 60LL + ss -
                            sign * (oh * 3600LL + om * 60LL);
    const std::time_t t = static_cast<std::time_t>(epoch);
    std::tm tm{};
    if (gmtime_r(&t, &tm) == nullptr) return false;
    char buf[64];
    const int n = std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    if (n <= 0) return false;
    out.assign(buf, static_cast<size_t>(n));
    if (frac > 0) {
        char f[32];
        std::snprintf(f, sizeof(f), ".%09lld", frac);
        out += f;
    }
    out += 'Z';
    return true;
}

int scope_value(const std::string& v) {
    if (v == "baseObject") return 0;
    if (v == "singleLevel" || v == "oneLevel") return 1;
    if (v == "wholeSubtree" || v == "subtree") return 2;
    if (v == "subordinateSubtree") return 3;
    return int_of(v);   // numeric scopes are tolerated
}

struct Fields {
    std::optional<int> conn, op, msgid, err, nentries, scope;
    std::optional<double> etime;
    int method = -1;
    std::string dn, authdn, authzid, base, filter, attrs, text, reason, oid, name,
                from, protocol, category, severity;
};

// key=value pairs; quoted values may contain spaces.  A leading space is
// optional so a record whose payload starts directly with its first key (the
// OpenDJ errors log does) is read the same way.
void parse_fields(std::string_view s, Fields& f) {
    for (;;) {
        space(s);
        if (s.empty()) break;
        const size_t eq = s.find('=');
        if (eq == std::string_view::npos) break;
        const std::string_view key = s.substr(0, eq);
        s.remove_prefix(eq + 1);
        if (key == "msg") {          // free text to end of line
            f.text.assign(s.data(), s.size());
            break;
        }
        std::string val;
        if (!s.empty() && s[0] == '"') {
            if (!quoted(s, val)) val.assign(token(s));
        } else {
            val.assign(token(s));
        }
        if (key == "conn") f.conn = int_of(val);
        else if (key == "op") f.op = int_of(val);
        else if (key == "msgID") f.msgid = int_of(val);
        else if (key == "result") f.err = int_of(val);
        else if (key == "nentries") f.nentries = int_of(val);
        else if (key == "etime") f.etime = std::strtod(val.c_str(), nullptr) / 1000.0;
        else if (key == "dn") f.dn = val;
        else if (key == "authDN") f.authdn = val;
        else if (key == "authzDN") f.authzid = val;
        else if (key == "base") f.base = val;
        else if (key == "filter") f.filter = val;
        else if (key == "attrs") f.attrs = val;
        else if (key == "attr") f.attrs = val;     // COMPARE REQ names one attribute
        else if (key == "scope") f.scope = scope_value(val);
        else if (key == "type" && val == "SIMPLE") f.method = 128;
        else if (key == "type" && val == "SASL") f.method = 163;
        else if (key == "message") f.text = val;
        else if (key == "severity") f.severity = val;
        else if (key == "category") f.category = val;
        else if (key == "reason") f.reason = val;
        else if (key == "oid") f.oid = val;
        else if (key == "name") f.name = val;
        else if (key == "from") f.from = val;
        else if (key == "protocol") f.protocol = val;
    }
}

}  // namespace

Event parse_opendj_line(std::string_view line) {
    Event ev;
    ev.raw.assign(line.data(), line.size());
    ev.format = LogFormat::OPEN_DJ;

    if (line.empty() || line[0] != '[') {
        ev.kind = "UNKNOWN_LINE";
        return ev;
    }
    const size_t close = line.find("] ");
    if (close == std::string_view::npos) {
        ev.kind = "UNKNOWN_LINE";
        return ev;
    }
    std::string rfc;
    if (parse_opendj_time(line.substr(1, close - 1), rfc)) ev.ts = rfc;

    std::string_view s = line.substr(close + 2);
    const std::string_view verb = token(s);

    if (verb == "CONNECT") {
        Fields f;
        parse_fields(s, f);
        ev.kind = "ACCEPT";
        ev.conn = f.conn;
        ev.src = f.from;
        ev.text = f.protocol;   // LDAP or LDAPS: the bind table reports it
        return ev;
    }
    if (verb == "DISCONNECT") {
        Fields f;
        parse_fields(s, f);
        ev.kind = "CLOSED";
        ev.conn = f.conn;
        ev.reason = f.reason;
        return ev;
    }
    if (verb == "TLS") { ev.kind = "TLS"; return ev; }

    // "<VERB> REQ|RES conn=N op=M msgID=K ..."
    space(s);
    const std::string_view phase = token(s);
    const bool req = (phase == "REQ");
    const bool res = (phase == "RES");
    if (!req && !res) {
        ev.kind = "UNKNOWN_OP";
        return ev;
    }
    Fields f;
    parse_fields(s, f);
    ev.conn = f.conn;
    ev.op = f.op;
    ev.msgid = f.msgid;
    ev.authzid = f.authzid;

    if (req) {
        if (verb == "BIND") {
            ev.kind = "BIND";
            ev.binddn = f.dn;
            ev.dn = f.dn;
            if (f.method >= 0) ev.method = f.method;
        } else if (verb == "SEARCH") {
            ev.kind = "SRCH";
            ev.base = f.base;
            ev.filter = f.filter;
            ev.attrs = f.attrs;
            ev.scope = f.scope;
        } else if (verb == "ADD") {
            ev.kind = "ADD";
            ev.dn = f.dn;
        } else if (verb == "DELETE") {
            ev.kind = "DEL";
            ev.dn = f.dn;
        } else if (verb == "MODIFY") {
            ev.kind = "MOD";
            ev.dn = f.dn;
        } else if (verb == "MODDN" || verb == "MODIFYDN") {
            ev.kind = "MODRDN";
            ev.dn = f.dn;
        } else if (verb == "COMPARE") {
            ev.kind = "CMP";
            ev.dn = f.dn;
            ev.attrs = f.attrs;
        } else if (verb == "EXTENDED") {
            ev.kind = "EXT";
            ev.oid = f.oid.empty() ? f.name : f.oid;
        } else if (verb == "ABANDON") {
            ev.kind = "ABANDON";
        } else if (verb == "UNBIND") {
            ev.kind = "UNBIND";
        } else {
            ev.kind = "UNKNOWN_OP";
        }
        return ev;
    }

    // Responses: a search result is the operation completion, the others are
    // plain results (the aggregator finishes the operation started by the REQ).
    ev.kind = (verb == "SEARCH") ? "SEARCH_RESULT" : "RESULT";
    ev.err = f.err;
    ev.nentries = f.nentries;
    ev.etime = f.etime;
    ev.text = f.text;
    if (verb == "BIND" && !f.authdn.empty()) ev.binddn = f.authdn;
    // A successful StartTLS extended result turns the connection into a TLS
    // one, so a bind that follows is reported as "ldap + StartTLS".
    if (verb == "EXTENDED" && f.name == "StartTLS" && f.err.value_or(-1) == 0)
        ev.tls_started = true;
    return ev;
}

// OpenDJ / PingDS errors log: "[dd/MMM/yyyy:HH:mm:ss ±HHMM] category=…
// severity=… msgID=… msg=…".  A line without a timestamp continues the
// previous message (a Java stack trace): counted, not parsed.
Event parse_opendj_errors_line(std::string_view line) {
    Event ev;
    ev.raw.assign(line.data(), line.size());
    ev.format = LogFormat::OPEN_DJ_ERRORS;
    if (line.empty() || line[0] != '[') {
        ev.kind = "SERVER_LOG_CONT";
        return ev;
    }
    const size_t close = line.find("] ");
    if (close == std::string_view::npos) {
        ev.kind = "UNKNOWN_LINE";
        return ev;
    }
    std::string rfc;
    if (parse_opendj_time(line.substr(1, close - 1), rfc)) ev.ts = rfc;

    std::string_view s = line.substr(close + 2);
    Fields f;
    parse_fields(s, f);
    if (f.severity.empty()) {      // not a diagnostic record
        ev.kind = "UNKNOWN_LINE";
        return ev;
    }
    ev.kind = "SERVER_LOG";
    ev.reason = f.severity;        // counted per severity
    ev.attrs = f.category;         // counted per category (the subsystem)
    ev.text = f.text;
    return ev;
}

bool classify_opendj(const std::vector<std::string>& head) {
    for (const std::string& raw : head) {
        std::string_view line(raw);
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.remove_suffix(1);
        if (line.empty()) continue;
        if (line[0] != '[') return false;
        const size_t close = line.find("] ");
        if (close == std::string_view::npos) return false;
        std::string_view s = line.substr(close + 2);
        const std::string_view verb = token(s);
        if (verb == "CONNECT" || verb == "DISCONNECT" || verb == "TLS") return true;
        if (verb == "BIND" || verb == "SEARCH" || verb == "ADD" || verb == "DELETE" ||
            verb == "MODIFY" || verb == "MODDN" || verb == "MODIFYDN" ||
            verb == "COMPARE" || verb == "ABANDON" || verb == "UNBIND" ||
            verb == "EXTENDED") {
            space(s);
            const std::string_view phase = token(s);
            return phase == "REQ" || phase == "RES";
        }
        return false;
    }
    return false;
}

bool classify_opendj_errors(const std::vector<std::string>& head) {
    for (const std::string& raw : head) {
        std::string_view line(raw);
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.remove_suffix(1);
        if (line.empty()) continue;
        if (line[0] != '[') continue;          // stack-trace continuation
        const size_t close = line.find("] ");
        if (close == std::string_view::npos) continue;
        const std::string_view s = line.substr(close + 2);
        if (s.rfind("category=", 0) != 0) continue;
        if (s.find(" severity=") == std::string_view::npos) continue;
        return true;
    }
    return false;
}

// OpenDJ common-audit records (Json File-Based Access Logger): nested
// request/response objects, "eventName":"DJ-LDAP", timestamp in RFC 3339.
// This is not an access log; recognising it lets the run refuse the file with
// a clear reason instead of taking it for the 389-ds JSON stream, whose
// records also contain the word "operation".
bool classify_opendj_audit(const std::vector<std::string>& head) {
    for (const std::string& raw : head) {
        std::string_view line(raw);
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.remove_suffix(1);
        if (line.empty()) continue;
        if (line[0] != '{') return false;
        return line.find("\"eventName\"") != std::string_view::npos;
    }
    return false;
}
