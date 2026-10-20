// state_io.cpp — the --save-state / --resume file.
//
// The file is a clear magic followed by one xz stream (liblzma is already
// linked for .xz logs) whose payload is the Aggregator in a fixed, versioned
// order:
//
//   "SLAPSTAT" (clear) | xz( schema(u32) | tool version | ... fields ... )
//
// The magic is deliberately outside the compressed stream: the CLI, the WASM
// session and the browser page all tell a state file from a log by its first
// eight bytes, without decompressing anything.  Every value is little-endian
// and strings are length-prefixed, so the file is portable across the machines
// slaplog runs on.  Maps are written in their (sorted) iteration order, so the
// same state always yields the same file.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "state_io.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>

#include <lzma.h>

#include "version.hpp"

namespace {

constexpr char MAGIC[8] = {'S', 'L', 'A', 'P', 'S', 'T', 'A', 'T'};
constexpr uint32_t SCHEMA = 2;   // 2: the timeline is varint-encoded

// ------------------------------------------------------------------ writer --
struct Writer {
    FILE* f = nullptr;
    lzma_stream strm = LZMA_STREAM_INIT;
    unsigned char buf[1 << 16];
    bool ok = false;

    bool open(const std::string& path) {
        f = std::fopen(path.c_str(), "wb");
        if (!f) return false;
        // The magic goes in the clear, before the compressed stream, so a reader
        // (or a browser page) can tell a state file from a log — and from any
        // other xz stream — by its first bytes, without decompressing anything.
        if (std::fwrite(MAGIC, 1, sizeof MAGIC, f) != sizeof MAGIC) {
            std::fclose(f);
            f = nullptr;
            return false;
        }
        if (lzma_easy_encoder(&strm, 6, LZMA_CHECK_CRC64) != LZMA_OK) {
            std::fclose(f);
            f = nullptr;
            return false;
        }
        ok = true;
        return true;
    }

    void put(const void* p, size_t n) {
        if (!ok || n == 0) return;
        strm.next_in = static_cast<const uint8_t*>(p);
        strm.avail_in = n;
        while (strm.avail_in) {
            strm.next_out = buf;
            strm.avail_out = sizeof(buf);
            if (lzma_code(&strm, LZMA_RUN) != LZMA_OK) { ok = false; return; }
            const size_t made = sizeof(buf) - strm.avail_out;
            if (made && std::fwrite(buf, 1, made, f) != made) { ok = false; return; }
        }
    }

    bool close() {
        bool good = ok;
        if (f) {
            strm.next_in = nullptr;
            strm.avail_in = 0;
            lzma_ret r;
            do {
                strm.next_out = buf;
                strm.avail_out = sizeof(buf);
                r = lzma_code(&strm, LZMA_FINISH);
                const size_t made = sizeof(buf) - strm.avail_out;
                if (made && std::fwrite(buf, 1, made, f) != made) good = false;
            } while (r == LZMA_OK);
            if (r != LZMA_STREAM_END) good = false;
            lzma_end(&strm);
            if (std::fclose(f) != 0) good = false;
            f = nullptr;
        }
        return good;
    }
};

// ------------------------------------------------------------------ reader --
struct Reader {
    FILE* f = nullptr;
    lzma_stream strm = LZMA_STREAM_INIT;
    unsigned char buf[1 << 16];
    bool ok = false;
    bool eof = false;

    // Returns false and fills `err`: "cannot open" and "not a state file" are
    // different mistakes and deserve different messages.
    bool open(const std::string& path, std::string& err) {
        f = std::fopen(path.c_str(), "rb");
        if (!f) {
            err = "cannot open " + path;
            return false;
        }
        char magic[8] = {};
        if (std::fread(magic, 1, sizeof magic, f) != sizeof magic ||
            std::memcmp(magic, MAGIC, sizeof magic) != 0) {
            err = path +
                  " is not a slaplog state file (no 'SLAPSTAT' header): analyse it "
                  "as a log instead of giving it to --resume";
            std::fclose(f);
            f = nullptr;
            return false;
        }
        if (lzma_stream_decoder(&strm, UINT64_MAX, 0) != LZMA_OK) {
            err = "cannot initialise the xz decoder for " + path;
            std::fclose(f);
            f = nullptr;
            return false;
        }
        ok = true;
        return true;
    }

    void get(void* dst, size_t n) {
        auto* d = static_cast<uint8_t*>(dst);
        while (ok && n) {
            if (strm.avail_in == 0 && !eof) {
                const size_t got = std::fread(buf, 1, sizeof(buf), f);
                strm.next_in = buf;
                strm.avail_in = got;
                if (got == 0) eof = true;
            }
            strm.next_out = d;
            strm.avail_out = n;
            const lzma_ret r =
                lzma_code(&strm, (eof && strm.avail_in == 0) ? LZMA_FINISH : LZMA_RUN);
            const size_t made = n - strm.avail_out;
            d += made;
            n -= made;
            if (r == LZMA_STREAM_END) {
                if (n) ok = false;
                break;
            }
            if (r != LZMA_OK) { ok = false; break; }
            if (made == 0 && eof && strm.avail_in == 0) { ok = false; break; }
        }
    }

    bool close() {
        const bool good = ok;
        if (f) std::fclose(f);
        f = nullptr;
        lzma_end(&strm);
        return good;
    }
};

// -------------------------------------------------------------- primitives --
void w_bytes(Writer& w, const void* p, size_t n) { w.put(p, n); }

void w_u8(Writer& w, uint8_t v) { w_bytes(w, &v, 1); }

void w_u32(Writer& w, uint32_t v) {
    uint8_t b[4];
    for (int i = 0; i < 4; ++i) b[i] = static_cast<uint8_t>(v >> (8 * i));
    w_bytes(w, b, 4);
}

void w_i32(Writer& w, int32_t v) { w_u32(w, static_cast<uint32_t>(v)); }

void w_u64(Writer& w, uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; ++i) b[i] = static_cast<uint8_t>(v >> (8 * i));
    w_bytes(w, b, 8);
}

void w_i64(Writer& w, int64_t v) { w_u64(w, static_cast<uint64_t>(v)); }

void w_f64(Writer& w, double v) {
    uint64_t u = 0;
    std::memcpy(&u, &v, sizeof u);
    w_u64(w, u);
}

void w_str(Writer& w, const std::string& s) {
    w_u32(w, static_cast<uint32_t>(s.size()));
    w_bytes(w, s.data(), s.size());
}

void w_strv(Writer& w, std::string_view s) {
    w_u32(w, static_cast<uint32_t>(s.size()));
    w_bytes(w, s.data(), s.size());
}

void w_opt_i32(Writer& w, const std::optional<int>& o) {
    w_u8(w, o ? 1 : 0);
    if (o) w_i32(w, *o);
}

void w_opt_f64(Writer& w, const std::optional<double>& o) {
    w_u8(w, o ? 1 : 0);
    if (o) w_f64(w, *o);
}

void r_bytes(Reader& r, void* p, size_t n) { r.get(p, n); }

uint8_t r_u8(Reader& r) {
    uint8_t v = 0;
    r_bytes(r, &v, 1);
    return v;
}

uint32_t r_u32(Reader& r) {
    uint8_t b[4] = {0, 0, 0, 0};
    r_bytes(r, b, 4);
    return uint32_t(b[0]) | (uint32_t(b[1]) << 8) | (uint32_t(b[2]) << 16) |
           (uint32_t(b[3]) << 24);
}

int32_t r_i32(Reader& r) { return static_cast<int32_t>(r_u32(r)); }

uint64_t r_u64(Reader& r) {
    uint8_t b[8] = {0};
    r_bytes(r, b, 8);
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | b[i];
    return v;
}

int64_t r_i64(Reader& r) { return static_cast<int64_t>(r_u64(r)); }

double r_f64(Reader& r) {
    const uint64_t u = r_u64(r);
    double v = 0.0;
    std::memcpy(&v, &u, sizeof v);
    return v;
}

std::string r_str(Reader& r) {
    const uint32_t n = r_u32(r);
    if (!r.ok || n > (1u << 30)) { r.ok = false; return {}; }
    std::string s(n, '\0');
    if (n) r_bytes(r, &s[0], n);
    return s;
}

std::optional<int> r_opt_i32(Reader& r) {
    if (r_u8(r) == 0) return std::nullopt;
    return r_i32(r);
}

std::optional<double> r_opt_f64(Reader& r) {
    if (r_u8(r) == 0) return std::nullopt;
    return r_f64(r);
}

// LEB128 + zigzag.  The timeline holds millions of events whose timestamps are
// seconds apart, so a fixed 8 + 4 bytes per event was mostly zero bytes.
void w_varint(Writer& w, uint64_t v) {
    uint8_t b;
    do {
        b = static_cast<uint8_t>(v & 0x7f);
        v >>= 7;
        if (v) b |= 0x80;
        w_bytes(w, &b, 1);
    } while (v);
}

uint64_t r_varint(Reader& r) {
    uint64_t v = 0;
    unsigned shift = 0;
    for (;;) {
        uint8_t b = 0;
        r_bytes(r, &b, 1);
        if (!r.ok) return 0;
        v |= static_cast<uint64_t>(b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift >= 64) { r.ok = false; return 0; }
    }
    return v;
}

uint64_t zigzag(int64_t v) {
    return (static_cast<uint64_t>(v) << 1) ^ static_cast<uint64_t>(v >> 63);
}

int64_t unzigzag(uint64_t v) {
    return static_cast<int64_t>(v >> 1) ^ -static_cast<int64_t>(v & 1);
}

// ------------------------------------------------------------- collections --
void w_map_size(Writer& w, size_t n) { w_u32(w, static_cast<uint32_t>(n)); }

void w_map_i64(Writer& w, const std::map<std::string, long long>& m) {
    w_map_size(w, m.size());
    for (const auto& [k, v] : m) { w_str(w, k); w_i64(w, v); }
}

void r_map_i64(Reader& r, std::map<std::string, long long>& m) {
    m.clear();
    const uint32_t n = r_u32(r);
    for (uint32_t i = 0; i < n && r.ok; ++i) {
        std::string k = r_str(r);
        m[k] = r_i64(r);
    }
}

void w_map_int_i64(Writer& w, const std::map<int, long long>& m) {
    w_map_size(w, m.size());
    for (const auto& [k, v] : m) { w_i32(w, k); w_i64(w, v); }
}

void r_map_int_i64(Reader& r, std::map<int, long long>& m) {
    m.clear();
    const uint32_t n = r_u32(r);
    for (uint32_t i = 0; i < n && r.ok; ++i) {
        const int k = r_i32(r);
        m[k] = r_i64(r);
    }
}

// { count, etime_total } maps (AppInfo, BaseInfo, FilterInfo, UserInfo)
template <typename T>
void w_map_info(Writer& w, const std::map<std::string, T>& m) {
    w_map_size(w, m.size());
    for (const auto& [k, v] : m) { w_str(w, k); w_i64(w, v.count); w_f64(w, v.etime_total); }
}

// The interned maps use the same wire layout, keyed by a borrowed view.
template <typename Map>
void write_interned_i64(Writer& w, const Map& m) {
    const auto items = m.sorted_by_key();
    w_map_size(w, items.size());
    for (const auto& it : items) { w_strv(w, it.key); w_i64(w, *it.value); }
}

template <typename Map>
void read_map_i64(Reader& r, Map& m) {
    m.clear();
    const uint32_t n = r_u32(r);
    for (uint32_t i = 0; i < n && r.ok; ++i) {
        std::string k = r_str(r);
        m[k] = r_i64(r);
    }
}

template <typename Map>
void read_map_info(Reader& r, Map& m) {
    m.clear();
    const uint32_t n = r_u32(r);
    for (uint32_t i = 0; i < n && r.ok; ++i) {
        std::string k = r_str(r);
        typename Map::mapped_type v;
        v.count = r_i64(r);
        v.etime_total = r_f64(r);
        m[k] = v;
    }
}

template <typename T>
void r_map_info(Reader& r, std::map<std::string, T>& m) {
    m.clear();
    const uint32_t n = r_u32(r);
    for (uint32_t i = 0; i < n && r.ok; ++i) {
        std::string k = r_str(r);
        T v;
        v.count = r_i64(r);
        v.etime_total = r_f64(r);
        m[k] = v;
    }
}

}  // namespace

// --------------------------------------------------------------- save/load --
namespace {

void write_payload(Writer& w, const Aggregator& a) {
    w_u32(w, SCHEMA);
    w_str(w, SLAPLOG_VERSION);

    // -- counters
    w_i64(w, a.stats.lines);
    w_i64(w, a.stats.fd_open);
    w_i64(w, a.stats.fd_close);
    w_i64(w, a.stats.conn_count);
    w_i64(w, a.stats.unknown_lines);
    w_i64(w, a.stats.replication_logs);
    w_map_i64(w, a.operation_count);
    w_i64(w, a.read_write_stats.read);
    w_i64(w, a.read_write_stats.write);

    // -- time range and extremes
    w_str(w, a.firsttime);
    w_str(w, a.lasttime);
    w_opt_f64(w, a.maxetime);
    w_str(w, a.maxetimeusr);
    w_str(w, a.maxopdesc);
    w_opt_f64(w, a.maxconnetime);
    w_str(w, a.maxconnetimeusr);
    w_str(w, a.maxconnopdesc);
    w_f64(w, a.etime_total);
    w_f64(w, a.qtime_total);

    // -- per-app / base / filter
    w_map_info(w, a.app_stats);
    w_map_info(w, a.base_stats);
    // Written in key order: the hash layout must not leak into the file.
    {
        const auto items = a.filter_stats.sorted_by_key();
        w_map_size(w, items.size());
        for (const auto& it : items) {
            w_strv(w, it.key);
            w_i64(w, it.value->count);
            w_f64(w, it.value->etime_total);
        }
    }
    // Deprecated: this map was filled, serialised and never read by a report.
    // The field stays in the layout (empty) so schema-1 states keep parsing.
    w_map_size(w, 0);
    write_interned_i64(w, a.norm_filter_n1_count);
    write_interned_i64(w, a.norm_filter_n0_count);
    write_interned_i64(w, a.wildcard_filter_count);
    {
        const auto items = a.filter_by_app.sorted_by_key();
        w_map_size(w, items.size());
        for (const auto& it : items) {
            w_strv(w, it.key1);
            w_strv(w, it.key2);
            w_i64(w, *it.value);
        }
    }
    w_map_i64(w, a.attr_count);

    // -- question-mark filters
    w_i64(w, a.qmark_filter_count);
    w_map_i64(w, a.qmark_filter_attr_count);

    // -- errors
    w_map_int_i64(w, a.error_count);
    w_map_size(w, a.error_per_app.size());
    for (const auto& [app, codes] : a.error_per_app) {
        w_str(w, app);
        w_map_size(w, codes.size());
        for (const auto& [code, n] : codes) { w_i32(w, code); w_i64(w, n); }
    }
    w_map_size(w, a.error_texts.size());
    for (const auto& [app, by_code] : a.error_texts) {
        w_str(w, app);
        w_map_size(w, by_code.size());
        for (const auto& [code, texts] : by_code) {
            w_i32(w, code);
            w_map_size(w, texts.size());
            for (const auto& [msg, n] : texts) { w_str(w, msg); w_i64(w, n); }
        }
    }

    // -- extended operations, global controls, CSN, indexing
    w_map_i64(w, a.ext_oid_count);
    w_map_i64(w, a.global_control_oid_count);
    w_i64(w, a.csn_event_count.get);
    w_i64(w, a.csn_event_count.queue);
    w_i64(w, a.csn_event_count.graduate);
    w_i64(w, a.not_indexed_count);
    w_map_i64(w, a.not_indexed_attr);

    // -- top-N
    w_map_size(w, a.top_ops.size());
    for (const TopOpRow& r : a.top_ops) {
        w_f64(w, r.etime);
        w_str(w, r.server);
        w_i32(w, r.conn);
        w_i32(w, r.op);
        w_str(w, r.type);
        w_str(w, r.who);
        w_str(w, r.base);
        w_str(w, r.filter);
        w_str(w, r.attrs);
        w_opt_i32(w, r.scope);
        w_opt_i32(w, r.deref);
        w_str(w, r.binddn);
        w_str(w, r.authcid);
        w_str(w, r.authzid);
        w_opt_i32(w, r.nentries);
        w_opt_i32(w, r.err);
        w_opt_f64(w, r.qtime);
        w_str(w, r.text);
        w_str(w, r.timestamp);
    }
    w_map_size(w, a.top_conns.size());
    for (const TopConnRow& r : a.top_conns) {
        w_f64(w, r.total_etime);
        w_str(w, r.server);
        w_i32(w, r.conn);
        w_str(w, r.who);
        w_str(w, r.src);
        w_i64(w, r.ops_count);
        w_str(w, r.binddn);
        w_str(w, r.reason);
    }

    // -- connections / sessions
    w_i64(w, a.active_connections);
    w_i64(w, a.peak_active_connections);
    w_map_size(w, a.unknown_lines.size());
    for (const std::string& s : a.unknown_lines) w_str(w, s);
    w_i32(w, a.restart_count);
    w_map_size(w, a.session_correlations.size());
    for (const auto& [key, c] : a.session_correlations) {
        w_str(w, std::get<0>(key));
        w_i32(w, std::get<1>(key));
        w_i32(w, std::get<2>(key));
        w_str(w, c.server);
        w_i32(w, c.restart);
        w_i32(w, c.conn);
        w_str(w, c.ts);
        w_str(w, c.accept_ip);
        w_str(w, c.real_ip);
        w_str(w, c.name);
        w_str(w, c.username);
        w_str(w, c.binddn);
    }

    // -- misc counters and server events
    w_i64(w, a.control_not_supported_count);
    w_i64(w, a.invalid_dn_count);
    w_i64(w, a.rebind_failed_count);
    w_i64(w, a.retry_count);
    w_i64(w, a.defer_count);
    w_i64(w, a.server_events.start_count);
    w_i64(w, a.server_events.stop_count);
    w_i64(w, a.server_events.shutdown_count);
    w_i64(w, a.server_events.daemon_shutdown_count);
    w_map_size(w, a.server_event_list.size());
    for (const auto& [ts, what] : a.server_event_list) { w_str(w, ts); w_str(w, what); }
    w_str(w, a.openldap_version);
    w_map_size(w, a.servers.size());
    for (const std::string& s : a.servers) w_str(w, s);

    // -- per server
    w_map_i64(w, a.ops_by_server);
    w_map_size(w, a.etime_by_server.size());
    for (const auto& [k, v] : a.etime_by_server) { w_str(w, k); w_f64(w, v); }
    w_map_i64(w, a.conn_by_server);
    w_map_i64(w, a.results_by_server);
    w_map_size(w, a.time_by_server.size());
    for (const auto& [host, win] : a.time_by_server) {
        w_str(w, host);
        w_str(w, win.first);
        w_str(w, win.last);
        w_str(w, win.first_key);
        w_str(w, win.last_key);
    }

    // -- bind usage, paged searches, resource consumers
    w_map_i64(w, a.bind_method_count);
    w_map_i64(w, a.bind_transport_count);
    w_map_i64(w, a.bind_mech_count);
    w_i64(w, a.bind_total);
    w_i64(w, a.bind_session_control);
    w_i64(w, a.paged_search_count);
    w_map_i64(w, a.paged_search_by_app);
    w_i64(w, a.pending_paged);
    w_map_info(w, a.user_stats);

    // -- chart data
    w_map_size(w, a.conn_timeline.size());
    {
        int64_t prev = 0;
        for (const ConnEvent& e : a.conn_timeline) {
            w_varint(w, zigzag(e.t - prev));
            prev = e.t;
            w_u8(w, e.delta > 0 ? 1 : 0);
        }
    }
    for (int i = 0; i < OP_ETIME_BUCKETS; ++i) w_i64(w, a.op_etime_hist[i]);
    for (int i = 0; i < ETIME_LOG_BINS; ++i) w_i64(w, a.op_etime_log_hist[i]);
    w_map_size(w, a.error_times_by_code.size());
    for (const auto& [code, times] : a.error_times_by_code) {
        w_i32(w, code);
        w_map_size(w, times.size());
        for (long long t : times) w_i64(w, t);
    }
}

bool read_payload(Reader& r, Aggregator& a, std::string& err) {
    const uint32_t schema = r_u32(r);
    if (!r.ok) {   // a header cut short reads as zeros: say what happened
        err = "state file is truncated or corrupt";
        return false;
    }
    if (schema != 1 && schema != SCHEMA) {
        err = "state written by schema " + std::to_string(schema) +
              ", this build reads 1 and " + std::to_string(SCHEMA);
        return false;
    }
    const std::string tool = r_str(r);

    Aggregator n;   // build into a fresh aggregate, swap on success

    n.stats.lines = r_i64(r);
    n.stats.fd_open = r_i64(r);
    n.stats.fd_close = r_i64(r);
    n.stats.conn_count = r_i64(r);
    n.stats.unknown_lines = r_i64(r);
    n.stats.replication_logs = r_i64(r);
    r_map_i64(r, n.operation_count);
    n.read_write_stats.read = r_i64(r);
    n.read_write_stats.write = r_i64(r);

    n.firsttime = r_str(r);
    n.lasttime = r_str(r);
    n.maxetime = r_opt_f64(r);
    n.maxetimeusr = r_str(r);
    n.maxopdesc = r_str(r);
    n.maxconnetime = r_opt_f64(r);
    n.maxconnetimeusr = r_str(r);
    n.maxconnopdesc = r_str(r);
    n.etime_total = r_f64(r);
    n.qtime_total = r_f64(r);

    r_map_info(r, n.app_stats);
    r_map_info(r, n.base_stats);
    read_map_info(r, n.filter_stats);
    // Deprecated and ignored: read it and drop it, without allocating what a
    // schema-1 state may carry (17 % of one real export).
    {
        const uint32_t c = r_u32(r);
        for (uint32_t i = 0; i < c && r.ok; ++i) { (void)r_str(r); (void)r_i64(r); }
    }
    read_map_i64(r, n.norm_filter_n1_count);
    read_map_i64(r, n.norm_filter_n0_count);
    read_map_i64(r, n.wildcard_filter_count);
    {
        const uint32_t c = r_u32(r);
        for (uint32_t i = 0; i < c && r.ok; ++i) {
            std::string a1 = r_str(r), a2 = r_str(r);
            n.filter_by_app(a1, a2) = r_i64(r);
        }
    }
    r_map_i64(r, n.attr_count);

    n.qmark_filter_count = r_i64(r);
    r_map_i64(r, n.qmark_filter_attr_count);

    r_map_int_i64(r, n.error_count);
    {
        const uint32_t apps = r_u32(r);
        for (uint32_t i = 0; i < apps && r.ok; ++i) {
            std::string app = r_str(r);
            const uint32_t codes = r_u32(r);
            for (uint32_t j = 0; j < codes && r.ok; ++j) {
                const int code = r_i32(r);
                n.error_per_app[app][code] = r_i64(r);
            }
        }
    }
    {
        const uint32_t apps = r_u32(r);
        for (uint32_t i = 0; i < apps && r.ok; ++i) {
            std::string app = r_str(r);
            const uint32_t codes = r_u32(r);
            for (uint32_t j = 0; j < codes && r.ok; ++j) {
                const int code = r_i32(r);
                const uint32_t texts = r_u32(r);
                for (uint32_t k = 0; k < texts && r.ok; ++k) {
                    std::string msg = r_str(r);
                    n.error_texts[app][code][msg] = r_i64(r);
                }
            }
        }
    }

    // A state written before "Errors per Application" meant failures only may
    // carry informational codes (success, compareFalse/True, referral,
    // saslBindInProgress).  Drop them here, so replaying an older state shows a
    // failure table too — and re-saving it writes a clean one.
    for (auto it = n.error_per_app.begin(); it != n.error_per_app.end(); ) {
        auto& codes = it->second;
        for (auto c = codes.begin(); c != codes.end(); ) {
            if (ldap_code_is_error(c->first)) ++c;
            else c = codes.erase(c);
        }
        if (codes.empty()) it = n.error_per_app.erase(it);
        else ++it;
    }

    r_map_i64(r, n.ext_oid_count);
    r_map_i64(r, n.global_control_oid_count);
    n.csn_event_count.get = r_i64(r);
    n.csn_event_count.queue = r_i64(r);
    n.csn_event_count.graduate = r_i64(r);
    n.not_indexed_count = r_i64(r);
    r_map_i64(r, n.not_indexed_attr);

    {
        const uint32_t c = r_u32(r);
        n.top_ops.reserve(c);
        for (uint32_t i = 0; i < c && r.ok; ++i) {
            TopOpRow row;
            row.etime = r_f64(r);
            row.server = r_str(r);
            row.conn = r_i32(r);
            row.op = r_i32(r);
            row.type = r_str(r);
            row.who = r_str(r);
            row.base = r_str(r);
            row.filter = r_str(r);
            row.attrs = r_str(r);
            row.scope = r_opt_i32(r);
            row.deref = r_opt_i32(r);
            row.binddn = r_str(r);
            row.authcid = r_str(r);
            row.authzid = r_str(r);
            row.nentries = r_opt_i32(r);
            row.err = r_opt_i32(r);
            row.qtime = r_opt_f64(r);
            row.text = r_str(r);
            row.timestamp = r_str(r);
            n.top_ops.push_back(std::move(row));
        }
    }
    {
        const uint32_t c = r_u32(r);
        n.top_conns.reserve(c);
        for (uint32_t i = 0; i < c && r.ok; ++i) {
            TopConnRow row;
            row.total_etime = r_f64(r);
            row.server = r_str(r);
            row.conn = r_i32(r);
            row.who = r_str(r);
            row.src = r_str(r);
            row.ops_count = r_i64(r);
            row.binddn = r_str(r);
            row.reason = r_str(r);
            n.top_conns.push_back(std::move(row));
        }
    }

    n.active_connections = r_i64(r);
    n.peak_active_connections = r_i64(r);
    {
        const uint32_t c = r_u32(r);
        // They are only useful to --unknown-lines FILE: skip their bytes when
        // this run will not write them (the count stays in stats).
        const bool keep = collect_unknown_lines_enabled();
        if (keep) n.unknown_lines.reserve(c);
        for (uint32_t i = 0; i < c && r.ok; ++i) {
            std::string line = r_str(r);
            if (keep) n.unknown_lines.push_back(std::move(line));
        }
    }
    n.restart_count = r_i32(r);
    {
        const uint32_t c = r_u32(r);
        for (uint32_t i = 0; i < c && r.ok; ++i) {
            std::string server = r_str(r);
            const int restart = r_i32(r);
            const int conn = r_i32(r);
            Aggregator::SessionCorrelation sc;
            sc.server = r_str(r);
            sc.restart = r_i32(r);
            sc.conn = r_i32(r);
            sc.ts = r_str(r);
            sc.accept_ip = r_str(r);
            sc.real_ip = r_str(r);
            sc.name = r_str(r);
            sc.username = r_str(r);
            sc.binddn = r_str(r);
            n.session_correlations[{server, restart, conn}] = std::move(sc);
        }
    }

    n.control_not_supported_count = r_i64(r);
    n.invalid_dn_count = r_i64(r);
    n.rebind_failed_count = r_i64(r);
    n.retry_count = r_i64(r);
    n.defer_count = r_i64(r);
    n.server_events.start_count = r_i64(r);
    n.server_events.stop_count = r_i64(r);
    n.server_events.shutdown_count = r_i64(r);
    n.server_events.daemon_shutdown_count = r_i64(r);
    {
        const uint32_t c = r_u32(r);
        n.server_event_list.reserve(c);
        for (uint32_t i = 0; i < c && r.ok; ++i) {
            std::string ts = r_str(r);
            n.server_event_list.emplace_back(ts, r_str(r));
        }
    }
    n.openldap_version = r_str(r);
    {
        const uint32_t c = r_u32(r);
        for (uint32_t i = 0; i < c && r.ok; ++i) n.servers.insert(r_str(r));
    }

    r_map_i64(r, n.ops_by_server);
    {
        const uint32_t c = r_u32(r);
        for (uint32_t i = 0; i < c && r.ok; ++i) {
            std::string k = r_str(r);
            n.etime_by_server[k] = r_f64(r);
        }
    }
    r_map_i64(r, n.conn_by_server);
    r_map_i64(r, n.results_by_server);
    {
        const uint32_t c = r_u32(r);
        for (uint32_t i = 0; i < c && r.ok; ++i) {
            const std::string host = r_str(r);
            Aggregator::ServerWindow win;
            win.first = r_str(r);
            win.last = r_str(r);
            win.first_key = r_str(r);
            win.last_key = r_str(r);
            n.time_by_server[host] = std::move(win);
        }
    }

    r_map_i64(r, n.bind_method_count);
    r_map_i64(r, n.bind_transport_count);
    r_map_i64(r, n.bind_mech_count);
    n.bind_total = r_i64(r);
    n.bind_session_control = r_i64(r);
    n.paged_search_count = r_i64(r);
    r_map_i64(r, n.paged_search_by_app);
    n.pending_paged = r_i64(r);
    r_map_info(r, n.user_stats);

    {
        const uint32_t c = r_u32(r);
        n.conn_timeline.reserve(c);
        if (schema >= 2) {
            int64_t prev = 0;
            for (uint32_t i = 0; i < c && r.ok; ++i) {
                prev += unzigzag(r_varint(r));
                const uint8_t d = r_u8(r);
                n.conn_timeline.push_back({prev, static_cast<signed char>(d ? 1 : -1)});
            }
        } else {
            // Schema 1 wrote a fixed 8 + 4 bytes per event.
            for (uint32_t i = 0; i < c && r.ok; ++i) {
                const long long t = r_i64(r);
                const int32_t d = r_i32(r);
                n.conn_timeline.push_back({t, static_cast<signed char>(d > 0 ? 1 : -1)});
            }
        }
    }
    for (int i = 0; i < OP_ETIME_BUCKETS; ++i) n.op_etime_hist[i] = r_i64(r);
    for (int i = 0; i < ETIME_LOG_BINS; ++i) n.op_etime_log_hist[i] = r_i64(r);
    {
        const uint32_t c = r_u32(r);
        for (uint32_t i = 0; i < c && r.ok; ++i) {
            const int code = r_i32(r);
            const uint32_t n_t = r_u32(r);
            auto& v = n.error_times_by_code[code];
            v.reserve(n_t);
            for (uint32_t j = 0; j < n_t && r.ok; ++j) v.push_back(r_i64(r));
            n.error_time_total += n_t;
        }
    }

    if (!r.ok) {
        err = "state file is truncated or corrupt";
        return false;
    }
    if (!tool.empty() && tool != SLAPLOG_VERSION) {
        // Not fatal: the schema is what makes the file readable.  Say it, so a
        // figure that moved between versions is not mistaken for a bug.
        std::fprintf(stderr,
                     "note: state written by slaplog v%s, this build is v%s\n",
                     tool.c_str(), SLAPLOG_VERSION);
    }
    // Fold the loaded state in: one --resume loads it, a second one adds to it.
    merge_aggregators(a, n);
    return true;
}

}  // namespace

bool save_state(const Aggregator& agg, const std::string& path, std::string& err) {
    Writer w;
    if (!w.open(path)) {
        err = "cannot open " + path + " for writing";
        return false;
    }
    write_payload(w, agg);
    if (!w.close()) {
        err = "failed to write " + path;
        return false;
    }
    return true;
}

bool load_state(Aggregator& agg, const std::string& path, std::string& err) {
    Reader r;
    if (!r.open(path, err)) return false;
    const bool ok = read_payload(r, agg, err);
    if (!r.close() && ok) {
        err = path + " is truncated";
        return false;
    }
    return ok;
}
