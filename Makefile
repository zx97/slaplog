# Makefile
CXX := g++
CXXFLAGS := -std=c++17 -O3 -Wall -Wextra -pedantic -pthread -MMD -MP
LDFLAGS := -lz -lbz2 -llzma -lstdc++fs

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
