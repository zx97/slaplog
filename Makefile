# Makefile
CXX := g++
# Directory containing this Makefile — resolves correctly even under
# "make -C /path" or "make -f /path/to/Makefile".
ROOT_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

# Compiler flags - using system PCRE2
CXXFLAGS := -std=c++17 -O3 -Wall -Wextra -pedantic -pthread -MMD -MP -I$(ROOT_DIR)
LDFLAGS := -lz -lbz2 -llzma -lpcre2-8

# -------------------------------------------------------------------
# std::filesystem linkage
# -------------------------------------------------------------------
# GCC < 9 ships <filesystem> in a separate static archive (-lstdc++fs)
# while GCC >= 9 provides it directly in libstdc++.so.  On very new
# toolchains (e.g. GCC 14+ / Arch / Fedora 42+) the separate archive
# may not exist at all, so linking it unconditionally fails.
#
# We check the GCC major version to decide.
# -------------------------------------------------------------------
GCC_MAJOR := $(shell $(CXX) -dumpversion | cut -d. -f1)
LDFLAGS := -lz -lbz2 -llzma -lpcre2-8
ifneq ($(shell [ "$(GCC_MAJOR)" -lt 9 ] && echo old),)
  LDFLAGS += -lstdc++fs
endif

# Source files
SRCS := main.cpp log_parser.cpp report.cpp html_chart.cpp
OBJS := $(SRCS:.cpp=.o)
TARGET := slaplog

all: $(TARGET)

# Auto-incrementing build number — always bumps on 'make'
BUILD_FILE := build_number.txt

# Force rebuild of build_number.txt on every invocation
FORCE:
.PHONY: FORCE

$(BUILD_FILE): FORCE
	@expr $$(cat $@ 2>/dev/null || echo 0) + 1 > $@

# main.cpp always recompiles (depends on changing build number)
main.o: main.cpp $(BUILD_FILE)
	$(CXX) $(CXXFLAGS) -DBUILD_NUMBER=$$(cat $(BUILD_FILE)) -c $< -o $@

%.o: %.cpp Makefile
	$(CXX) $(CXXFLAGS) -DBUILD_NUMBER=$$(cat $(BUILD_FILE)) -c $< -o $@

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

-include $(OBJS:.o=.d)

clean:
	rm -f $(TARGET) $(OBJS) $(OBJS:.o=.d)

.PHONY: all clean FORCE

# ===================================================================
# Embedded documentation  --  `make embedded` / `make check-doc`
# ===================================================================
# embedded.hpp holds LICENSE and doc/slaplog.md as raw string literals,
# printed by `slaplog -l` and `slaplog -D`.  Those two copies used to be
# kept in step by hand and drifted apart (131 differing lines at v3.8.0,
# each side carrying changes the other lacked), so embedded.hpp is now a
# GENERATED file: doc/slaplog.md is the source, the .hpp the artefact.
#
# `make` regenerates it as soon as a source or the template changes (the
# -MMD dependency files then rebuild whoever includes it); `make check-doc`
# fails when it is stale, which is the guard to run before a release.
# ===================================================================
$(ROOT_DIR)embedded.hpp: $(ROOT_DIR)doc/slaplog.md $(ROOT_DIR)LICENSE \
                         $(ROOT_DIR)tools/embedded.hpp.in \
                         $(ROOT_DIR)tools/gen_embedded.py
	@$(ROOT_DIR)tools/gen_embedded.py

.PHONY: embedded check-doc
embedded:
	@$(ROOT_DIR)tools/gen_embedded.py
check-doc:
	@$(ROOT_DIR)tools/gen_embedded.py --check

# ===================================================================
# WebAssembly build (Emscripten)  --  `make wasm`
# ===================================================================
# This section is purely additive: it defines new variables and new
# targets, and does not alter any rule or variable of the native build
# above.  Plain `make` still builds the native binary exactly as before.
#
# The WASM build compiles wasm/wasm_main.cpp instead of main.cpp (which
# uses std::thread and /proc/meminfo), and reuses log_parser.cpp and
# report.cpp unmodified.  It never passes -pthread, so the produced
# module runs in a normal browser tab without SharedArrayBuffer / COOP
# /COEP headers.
#
# Prerequisites:
#   - emsdk activated (em++ on PATH)
#   - wasm/prebuilt/liblzma.a + headers (built once by build_liblzma.sh;
#     zlib and bzip2 come from Emscripten's own ports)
#
# Output: wasm/web/slaplog.js (+ slaplog.wasm), loaded by wasm/web/index.html
# ===================================================================
EMXX      ?= em++
WASM_DIR  := $(ROOT_DIR)wasm
WASM_PRE  := $(WASM_DIR)/prebuilt
WASM_INC  := $(WASM_PRE)/include
WASM_OUT  := $(WASM_DIR)/web/slaplog.js

WASM_SRCS := $(WASM_DIR)/wasm_main.cpp \
             $(ROOT_DIR)log_parser.cpp \
             $(ROOT_DIR)report.cpp \
             $(ROOT_DIR)html_chart.cpp

WASM_FLAGS := -std=c++17 -O2 -Wall -Wextra \
              -I$(ROOT_DIR) -I$(WASM_INC) \
              -sUSE_ZLIB=1 -sUSE_BZIP2=1 \
              -sMODULARIZE=1 -sEXPORT_NAME=createSlaplog \
              -sINVOKE_RUN=0 -sEXIT_RUNTIME=0 \
              -sALLOW_MEMORY_GROWTH=1 \
              -sSTACK_SIZE=5242880 \
              -sFORCE_FILESYSTEM=1 \
              -sEXPORTED_FUNCTIONS='["_main","_slaplog_run","_slaplog_begin","_slaplog_input_begin","_slaplog_input_end","_slaplog_add_file","_slaplog_add_text","_slaplog_end","_slaplog_version","_malloc","_free"]' \
              -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap","FS","HEAPU8"]'

.PHONY: wasm wasm-clean

wasm: $(WASM_OUT)

$(WASM_OUT): $(WASM_SRCS) $(WASM_PRE)/liblzma.a $(WASM_INC)/nlohmann/json.hpp $(BUILD_FILE)
	$(EMXX) $(WASM_FLAGS) -DBUILD_NUMBER=$$(cat $(BUILD_FILE)) \
	        $(WASM_SRCS) $(WASM_PRE)/liblzma.a -o $@

# liblzma (xz) has no Emscripten port: cross-build it once.
$(WASM_PRE)/liblzma.a $(WASM_INC)/lzma.h: $(WASM_DIR)/build_liblzma.sh
	$(WASM_DIR)/build_liblzma.sh

# Stage nlohmann/json (header-only) locally.  Copying it into our own
# include dir avoids putting the host /usr/include on the compiler search
# path, which would shadow Emscripten's own sysroot headers.
$(WASM_INC)/nlohmann/json.hpp:
	@mkdir -p $(WASM_INC)
	@src="$$(for d in /usr/include/nlohmann /usr/local/include/nlohmann \
	                    $(HOME)/.local/include/nlohmann \
	                    /home/linuxbrew/.linuxbrew/include/nlohmann; do \
	           [ -f "$$d/json.hpp" ] && { echo "$$d"; break; }; done)"; \
	if [ -z "$$src" ]; then \
	    echo "ERROR: nlohmann/json.hpp not found on host (install e.g. nlohmann-json3-dev)"; \
	    exit 1; \
	fi; \
	rm -rf $(WASM_INC)/nlohmann; \
	cp -r "$$src" $(WASM_INC)/nlohmann; \
	echo "staged nlohmann/json from $$src"

wasm-clean:
	rm -f $(WASM_OUT) $(WASM_DIR)/web/slaplog.wasm
