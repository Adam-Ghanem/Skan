CXX := g++
CC := gcc
CPPFLAGS ?= -Iinclude
CXXFLAGS ?= -std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -O2
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -O2
LDFLAGS ?=

PROJECT := skan
TARGET := bin/$(PROJECT)
BUILD_DIR := build

CPP_SOURCES := \
	src/core/types.cpp \
	src/core/status.cpp \
	src/core/log.cpp \
	src/main.cpp
C_SOURCES := src/c_api/status.c
CPP_OBJECTS := $(CPP_SOURCES:src/%.cpp=$(BUILD_DIR)/%.o)
C_OBJECTS := $(C_SOURCES:src/%.c=$(BUILD_DIR)/%.o)

TEST_SOURCES := \
	tests/unit/core/test_types.cpp \
	tests/unit/core/test_status.cpp \
	tests/unit/core/test_constants.cpp
TEST_BINARIES := \
	$(BUILD_DIR)/test_types \
	$(BUILD_DIR)/test_status \
	$(BUILD_DIR)/test_constants
TEST_OBJECTS := $(TEST_SOURCES:%.cpp=$(BUILD_DIR)/%.o)

.PHONY: all debug test clean

all: $(TARGET)

$(TARGET): $(CPP_OBJECTS) $(C_OBJECTS) | bin
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_types: $(BUILD_DIR)/tests/unit/core/test_types.o $(BUILD_DIR)/core/types.o $(BUILD_DIR)/core/status.o $(BUILD_DIR)/c_api/status.o | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_status: $(BUILD_DIR)/tests/unit/core/test_status.o $(BUILD_DIR)/core/status.o $(BUILD_DIR)/c_api/status.o | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_constants: $(BUILD_DIR)/tests/unit/core/test_constants.o | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/tests/%.o: tests/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

bin:
	mkdir -p $@

$(BUILD_DIR):
	mkdir -p $@

debug: CXXFLAGS += -g -O0

debug: CFLAGS += -g -O0

debug: clean all

test: $(TEST_BINARIES)
	./$(BUILD_DIR)/test_types
	./$(BUILD_DIR)/test_status
	./$(BUILD_DIR)/test_constants

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

-include $(CPP_OBJECTS:.o=.d) $(C_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)
