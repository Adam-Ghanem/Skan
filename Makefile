CC := gcc
CPPFLAGS ?= -Iinclude
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2
LDFLAGS ?=

PROJECT := skan
VERSION := 0.1.0
TARGET := bin/$(PROJECT)
BUILD_DIR := build

CORE_SOURCES := \
	src/core/types.c \
	src/core/errors.c \
	src/core/log.c
CORE_OBJECTS := $(CORE_SOURCES:src/%.c=$(BUILD_DIR)/%.o)
MAIN_OBJECT := $(BUILD_DIR)/main.o

TEST_SOURCES := tests/unit/core/test_core.c
TEST_OBJECTS := $(TEST_SOURCES:%.c=$(BUILD_DIR)/%.o)
TEST_BINARY := $(BUILD_DIR)/test_core

.PHONY: all debug test clean

all: $(TARGET)

$(TARGET): $(CORE_OBJECTS) $(MAIN_OBJECT) | bin
	$(CC) $(LDFLAGS) $^ -o $@

$(TEST_BINARY): $(CORE_OBJECTS) $(TEST_OBJECTS) | $(BUILD_DIR)
	$(CC) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/tests/%.o: tests/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

bin:
	mkdir -p $@

$(BUILD_DIR):
	mkdir -p $@

debug: CFLAGS += -g3 -O0

debug: clean all

test: $(TEST_BINARY)
	./$(TEST_BINARY)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

-include $(CORE_OBJECTS:.o=.d) $(MAIN_OBJECT:.o=.d) $(TEST_OBJECTS:.o=.d)
