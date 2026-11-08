// dialect.hpp
//
// A dialect describes one input format: how to recognise a file from its head,
// and how to parse one line.  The table (dialect.cpp) is ordered from the most
// specific format to the most general one, and is consulted once per file — the
// per-line loop only follows the pointer it selected, so adding a format never
// puts a test on the hot path of another.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "log_parser.hpp"

struct LogDialect {
    const char* name;     // shown in "different log format for this run (…)"
    FileKind    kind;
    ParseMode   mode;
    bool        json_pretty;  // reader must assemble multi-line JSON records
    bool (*classify)(const std::vector<std::string>& head);
    Event (*parse_line)(std::string_view line);
};

// Ordered table, most specific first.
const LogDialect* log_dialects(size_t& count);
const LogDialect* classify_dialect(const std::vector<std::string>& head);
const LogDialect* dialect_by_mode(ParseMode mode);
const LogDialect* dialect_by_kind(FileKind kind);

// Implemented by each format file.
bool classify_openldap(const std::vector<std::string>& head);
bool classify_ds389_text(const std::vector<std::string>& head);
bool classify_ds389_json(const std::vector<std::string>& head);
bool classify_ds389_json_pretty(const std::vector<std::string>& head);
bool classify_ds389_errors_text(const std::vector<std::string>& head);
bool classify_ds389_errors_json(const std::vector<std::string>& head);
bool classify_ds389_other(const std::vector<std::string>& head);
bool classify_opendj(const std::vector<std::string>& head);

Event parse_opendj_line(std::string_view line);

// 389-ds parsers (log_parser.cpp).
Event parse_ds389_line(std::string_view line);
Event parse_ds389_json_line(std::string_view line);
Event parse_ds389_errors_line(std::string_view line);
Event parse_ds389_errors_json_line(std::string_view line);
