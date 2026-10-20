#!/usr/bin/env python3
#!/usr/bin/env python3
"""state_profile.py — bytes and entries per section of a .slapstate file.

Mirrors the read order of state_io.cpp's read_payload() (schemas 1 and 2) and
prints the payload size of each field group, so memory work is driven by
measurement rather than by guesswork.

    python3 tools/state_profile.py report.slapstate

SPDX-License-Identifier: AGPL-3.0-or-later
"""
import lzma
import struct
import sys
from collections import OrderedDict

data = open(sys.argv[1], "rb").read()
assert data[:8] == b"SLAPSTAT", "not a state file"
payload = lzma.decompress(data[8:])
pos = 0


def need(n):
    global pos
    if pos + n > len(payload):
        raise EOFError(f"truncated at {pos} (+{n})")
    pos += n
    return n


def u32():
    global pos
    v = struct.unpack_from("<I", payload, pos)[0]
    need(4)
    return v


def i32():
    global pos
    v = struct.unpack_from("<i", payload, pos)[0]
    need(4)
    return v


def i64():
    global pos
    v = struct.unpack_from("<q", payload, pos)[0]
    need(8)
    return v


def f64():
    global pos
    v = struct.unpack_from("<d", payload, pos)[0]
    need(8)
    return v


def s():
    n = u32()
    global pos
    pos += n
    need(0)


def opt(fn):
    flag = payload[pos]
    need(1)
    if flag:
        fn()


def r_map_i64():
    n = u32()
    for _ in range(n):
        s()
        i64()
    return n


def r_map_info():
    n = u32()
    for _ in range(n):
        s(); i64(); f64()
    return n


def r_map_int_i64():
    n = u32()
    for _ in range(n):
        i32(); i64()
    return n


sections = OrderedDict()


def mark(name, fn, *a):
    start = pos
    n = fn(*a) if fn else 0
    if isinstance(n, list):
        n = n[-1] if n else 0
    sections[name] = (pos - start, n)


SCHEMA = 0


def header():
    global SCHEMA
    SCHEMA = u32(); s()
    return 0


mark("header (schema + tool version)", header)

# -- counters
mark("stats + operation_count + read/write",
     lambda: [i64() for _ in range(6)] + [r_map_i64(), i64(), i64()])

# -- time range / extremes
def time_extremes():
    s(); s()
    opt(f64); s(); s()
    opt(f64); s(); s()
    f64(); f64()
    return 0

mark("time range + max fields + totals", time_extremes)

mark("app_stats", r_map_info)
mark("base_stats", r_map_info)
mark("filter_stats", r_map_info)
mark("norm_filter_@@attrs_count", r_map_i64)
mark("norm_filter_@@nentries=1", r_map_i64)
mark("norm_filter_@@nentries=0", r_map_i64)
mark("wildcard_filter_count", r_map_i64)

def filter_by_app():
    n = u32()
    for _ in range(n):
        s(); s(); i64()
    return n

mark("filter_by_app", filter_by_app)
mark("attr_count", r_map_i64)
mark("qmark (count + attrs)", lambda: [i64(), r_map_i64()])
mark("error_count", r_map_int_i64)

def error_per_app():
    apps = u32(); rows = 0
    for _ in range(apps):
        s()
        codes = u32()
        for _ in range(codes):
            i32(); i64(); rows += 1
    return rows

mark("error_per_app", error_per_app)

def error_texts():
    apps = u32(); rows = 0
    for _ in range(apps):
        s()
        codes = u32()
        for _ in range(codes):
            i32()
            texts = u32()
            for _ in range(texts):
                s(); i64(); rows += 1
    return rows

mark("error_texts", error_texts)
mark("ext_oid + global_control", lambda: [r_map_i64(), r_map_i64()])
mark("csn + not_indexed", lambda: [i64() for _ in range(4)] + [r_map_i64()])

def top_ops():
    n = u32()
    for _ in range(n):
        f64(); s(); i32(); i32(); s(); s(); s(); s(); s()
        opt(i32); opt(i32)
        s(); s(); s()
        opt(i32); opt(i32); opt(f64)
        s(); s()
    return n

mark("top_ops (max 100)", top_ops)

def top_conns():
    n = u32()
    for _ in range(n):
        f64(); s(); i32(); s(); s(); i64(); s(); s()
    return n

mark("top_conns (max 100)", top_conns)

def unknown_lines():
    n = u32()
    for _ in range(n):
        s()
    return n

mark("active/peak + unknown_lines", lambda: [i64(), i64(), unknown_lines()])

def sessions():
    i32()
    n = u32()
    for _ in range(n):
        s(); i32(); i32()
        s(); i32(); i32()
        s(); s(); s(); s(); s(); s()
    return n

mark("session_correlations", sessions)

def misc():
    for _ in range(5): i64()
    for _ in range(4): i64()
    n = u32()
    for _ in range(n):
        s(); s()
    s()
    m = u32()
    for _ in range(m):
        s()
    return n + m

mark("misc + server events + version + servers", misc)
mark("ops_by_server", r_map_i64)

def etime_by_server():
    n = u32()
    for _ in range(n):
        s(); f64()
    return n

mark("etime_by_server", etime_by_server)
mark("conn_by_server + results_by_server", lambda: [r_map_i64(), r_map_i64()])

def time_by_server():
    n = u32()
    for _ in range(n):
        s(); s(); s(); s(); s()
    return n

mark("time_by_server", time_by_server)
mark("bind maps (3)", lambda: [r_map_i64(), r_map_i64(), r_map_i64()])
mark("bind_total + bind_session_control + paged_count", lambda: [i64() for _ in range(3)])
mark("paged_search_by_app", r_map_i64)
mark("i64 pending_paged", lambda: i64())
mark("user_stats", r_map_info)

def varint():
    global pos
    v = 0; shift = 0
    while True:
        b = payload[pos]; need(1)
        v |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return v


def unzigzag(v):
    return (v >> 1) ^ -(v & 1)


def conn_timeline():
    n = u32()
    if SCHEMA >= 2:
        prev = 0
        for _ in range(n):
            prev += unzigzag(varint())
            need(1)                      # signed delta, one byte
    else:
        for _ in range(n):
            i64(); i32()
    return n

mark("conn_timeline", conn_timeline)
mark("op_etime_hist (11) + log hist (35)",
     lambda: [i64() for _ in range(46)])

def error_times():
    n = u32(); total = 0
    for _ in range(n):
        i32()
        k = u32()
        for _ in range(k):
            i64()
        total += k
    return total

mark("error_times_by_code", error_times)

print(f"payload: {len(payload):,} bytes ({len(payload)/1048576:.1f} MiB)")
print(f"parsed:  {pos:,} bytes\n")
print(f"{'section':48s} {'bytes':>12s} {'%':>6s} {'entries':>10s}")
print("-" * 80)
for name, (nb, n) in sorted(sections.items(), key=lambda kv: -kv[1][0]):
    print(f"{name:48s} {nb:12,d} {100*nb/len(payload):5.1f}% {n:10,d}")
