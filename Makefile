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
	src/io/event.cpp \
	src/io/io_engine.cpp \
	src/io/timer.cpp \
	src/main.cpp
C_SOURCES := src/c_api/status.c
CPP_OBJECTS := $(CPP_SOURCES:src/%.cpp=$(BUILD_DIR)/%.o)
C_OBJECTS := $(C_SOURCES:src/%.c=$(BUILD_DIR)/%.o)
CORE_OBJECTS := $(BUILD_DIR)/core/types.o $(BUILD_DIR)/core/status.o
C_API_OBJECTS := $(BUILD_DIR)/c_api/status.o
IO_OBJECTS := $(BUILD_DIR)/io/event.o $(BUILD_DIR)/io/io_engine.o $(BUILD_DIR)/io/timer.o

TEST_SOURCES := \
	tests/unit/core/test_types.cpp \
	tests/unit/core/test_status.cpp \
	tests/unit/core/test_constants.cpp \
	tests/unit/io/test_event.cpp \
	tests/unit/io/test_io_engine.cpp \
	tests/unit/io/test_timer.cpp
TEST_OBJECTS := $(TEST_SOURCES:%.cpp=$(BUILD_DIR)/%.o)
TEST_BINARIES := \
	$(BUILD_DIR)/test_types \
	$(BUILD_DIR)/test_status \
	$(BUILD_DIR)/test_constants \
	$(BUILD_DIR)/test_event \
	$(BUILD_DIR)/test_io_engine \
	$(BUILD_DIR)/test_timer

.PHONY: all debug test clean

all: $(TARGET)

$(TARGET): $(CPP_OBJECTS) $(C_OBJECTS) | bin
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_types: $(BUILD_DIR)/tests/unit/core/test_types.o $(CORE_OBJECTS) $(C_API_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_status: $(BUILD_DIR)/tests/unit/core/test_status.o $(BUILD_DIR)/core/status.o $(C_API_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_constants: $(BUILD_DIR)/tests/unit/core/test_constants.o | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_event: $(BUILD_DIR)/tests/unit/io/test_event.o $(IO_OBJECTS) $(CORE_OBJECTS) $(BUILD_DIR)/core/log.o | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_io_engine: $(BUILD_DIR)/tests/unit/io/test_io_engine.o $(IO_OBJECTS) $(CORE_OBJECTS) $(BUILD_DIR)/core/log.o | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_timer: $(BUILD_DIR)/tests/unit/io/test_timer.o $(IO_OBJECTS) $(CORE_OBJECTS) $(BUILD_DIR)/core/log.o | $(BUILD_DIR)
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
	./$(BUILD_DIR)/test_event
	./$(BUILD_DIR)/test_io_engine
	./$(BUILD_DIR)/test_timer

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

-include $(CPP_OBJECTS:.o=.d) $(C_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)
