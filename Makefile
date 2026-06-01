# Makefile
CXX := g++
# Directory containing this Makefile — resolves correctly even under
# "make -C /path" or "make -f /path/to/Makefile".
ROOT_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
# Compiler flags
CXXFLAGS := -std=c++17 -O3 -Wall -Wextra -pedantic -pthread -MMD -MP -I$(ROOT_DIR)

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
LDFLAGS := -lz -lbz2 -llzma
ifneq ($(shell [ "$(GCC_MAJOR)" -lt 9 ] && echo old),)
  LDFLAGS += -lstdc++fs
endif

# Source files
SRCS := main.cpp log_parser.cpp report.cpp
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
