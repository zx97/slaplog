#pragma once
//
// state_io.hpp — the --save-state / --resume file.
//
// A state file holds the mergeable part of an Aggregator, so that a later run
// can fold new logs into it: `A -> save -> resume + B` produces the same report
// as `A + B`.  The per-file working maps (conn_state, binddn_by_conn,
// src_by_conn) are not stored: only parsing uses them.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <string>

#include "log_parser.hpp"

// Write `agg` to `path` (xz-compressed, versioned).  Returns false and fills
// `err` on failure.
bool save_state(const Aggregator& agg, const std::string& path, std::string& err);

// Read `path` and fold it into `agg`.  On an empty aggregate this simply loads
// the state; on one that already holds a state (or a first run), the two are
// merged, which is what makes --resume repeatable and lets two state files be
// combined.  Returns false and fills `err` when the file is not a state file,
// was written by an incompatible schema, or is truncated — in which case `agg`
// is left untouched.
bool load_state(Aggregator& agg, const std::string& path, std::string& err);
