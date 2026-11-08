// dialect.cpp — the ordered registry of input dialects.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "dialect.hpp"
#include "log_parser.hpp"

namespace {

const LogDialect kDialects[] = {
    // 389-ds: the payload decides between access and errors, and the JSON
    // records are told apart by their keys.
    {"389-ds text access", FileKind::DS389Text, ParseMode::DS389Text, false,
     classify_ds389_text, parse_ds389_line},
    {"389-ds JSON access", FileKind::DS389Json, ParseMode::DS389Json, false,
     classify_ds389_json, parse_ds389_json_line},
    {"389-ds json-pretty access", FileKind::DS389JsonPretty,
     ParseMode::DS389JsonPretty, true, classify_ds389_json_pretty,
     parse_ds389_json_line},
    {"389-ds text errors", FileKind::DS389ErrorsText, ParseMode::DS389ErrorsText,
     false, classify_ds389_errors_text, parse_ds389_errors_line},
    {"389-ds JSON errors", FileKind::DS389ErrorsJson, ParseMode::DS389ErrorsJson,
     false, classify_ds389_errors_json, parse_ds389_errors_json_line},
    // A 389-ds stream that is not an access or errors log (audit LDIF,
    // security JSON, rotation info): recognised, then skipped with a reason.
    {"389-ds non-access stream", FileKind::DS389Other, ParseMode::OpenLDAP,
     false, classify_ds389_other, nullptr},

    // OpenDJ / ForgeRock DS / PingDS / Oracle Unified Directory (OpenDS family).
    {"OpenDJ access", FileKind::OpenDJ, ParseMode::OpenDJ, false,
     classify_opendj, parse_opendj_line},

    // OpenLDAP last: its auto-detection also accepts the timestamp shapes of
    // the formats above, so it must only see what they rejected.
    {"OpenLDAP access", FileKind::OpenLDAP, ParseMode::OpenLDAP, false,
     classify_openldap, nullptr},   // nullptr: the core parse_line()
};

}  // namespace

const LogDialect* log_dialects(size_t& count) {
    count = sizeof(kDialects) / sizeof(kDialects[0]);
    return kDialects;
}

const LogDialect* classify_dialect(const std::vector<std::string>& head) {
    size_t n = 0;
    const LogDialect* table = log_dialects(n);
    for (size_t i = 0; i < n; ++i)
        if (table[i].classify && table[i].classify(head)) return &table[i];
    return nullptr;
}

const LogDialect* dialect_by_mode(ParseMode mode) {
    size_t n = 0;
    const LogDialect* table = log_dialects(n);
    for (size_t i = 0; i < n; ++i)
        if (table[i].mode == mode) return &table[i];
    return nullptr;
}

const LogDialect* dialect_by_kind(FileKind kind) {
    size_t n = 0;
    const LogDialect* table = log_dialects(n);
    for (size_t i = 0; i < n; ++i)
        if (table[i].kind == kind) return &table[i];
    return nullptr;
}
