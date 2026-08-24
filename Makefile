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
	src/packet/packet_element.cpp \
	src/packet/packet.cpp \
	src/packet/ethernet.cpp \
	src/packet/ipv4.cpp \
	src/packet/tcp.cpp \
	src/packet/udp.cpp \
	src/packet/icmp.cpp \
	src/packet/checksum.cpp \
	src/discovery/discovery.cpp \
	src/discovery/discovery_types.cpp \
	src/discovery/discovery_probe.cpp \
	src/discovery/discovery_scheduler.cpp \
	src/discovery/icmp_discovery.cpp \
	src/discovery/tcp_discovery.cpp \
			src/discovery/arp_discovery.cpp \
		src/portscan/port_types.cpp \
		src/portscan/port_result.cpp \
		src/portscan/port_probe.cpp \
		src/portscan/tcp_connect.cpp \
		src/portscan/tcp_syn.cpp \
		src/portscan/port_scheduler.cpp \
		src/main.cpp

C_SOURCES := src/c_api/status.c
CPP_OBJECTS := $(CPP_SOURCES:src/%.cpp=$(BUILD_DIR)/%.o)
C_OBJECTS := $(C_SOURCES:src/%.c=$(BUILD_DIR)/%.o)
CORE_OBJECTS := $(BUILD_DIR)/core/types.o $(BUILD_DIR)/core/status.o
CORE_LOG_OBJECT := $(BUILD_DIR)/core/log.o
C_API_OBJECTS := $(BUILD_DIR)/c_api/status.o
IO_OBJECTS := $(BUILD_DIR)/io/event.o $(BUILD_DIR)/io/io_engine.o $(BUILD_DIR)/io/timer.o
PACKET_OBJECTS := $(BUILD_DIR)/packet/packet_element.o $(BUILD_DIR)/packet/packet.o \
	$(BUILD_DIR)/packet/ethernet.o $(BUILD_DIR)/packet/ipv4.o $(BUILD_DIR)/packet/tcp.o \
	$(BUILD_DIR)/packet/udp.o $(BUILD_DIR)/packet/icmp.o $(BUILD_DIR)/packet/checksum.o
PORTSCAN_OBJECTS := $(BUILD_DIR)/portscan/port_types.o $(BUILD_DIR)/portscan/port_result.o \
	$(BUILD_DIR)/portscan/port_probe.o $(BUILD_DIR)/portscan/tcp_connect.o \
	$(BUILD_DIR)/portscan/tcp_syn.o $(BUILD_DIR)/portscan/port_scheduler.o

TEST_SOURCES := \
	tests/unit/core/test_types.cpp \
	tests/unit/core/test_status.cpp \
	tests/unit/core/test_constants.cpp \
	tests/unit/io/test_event.cpp \
	tests/unit/io/test_io_engine.cpp \
	tests/unit/io/test_timer.cpp \
	tests/unit/packet/test_packet_element.cpp \
	tests/unit/packet/test_packet.cpp \
	tests/unit/packet/test_ethernet.cpp \
	tests/unit/packet/test_ipv4.cpp \
	tests/unit/packet/test_tcp.cpp \
	tests/unit/packet/test_udp.cpp \
	tests/unit/packet/test_icmp.cpp \
	tests/unit/packet/test_checksum.cpp \
	tests/unit/discovery/test_discovery_types.cpp \
	tests/unit/discovery/test_discovery_probe.cpp \
	tests/unit/discovery/test_discovery_scheduler.cpp \
	tests/integration/discovery/test_discovery_local.cpp \
	tests/unit/portscan/test_port_types.cpp \
	tests/unit/portscan/test_port_probe.cpp \
	tests/unit/portscan/test_port_scheduler.cpp \
	tests/integration/portscan/test_portscan_local.cpp
TEST_OBJECTS := $(TEST_SOURCES:%.cpp=$(BUILD_DIR)/%.o)
TEST_BINARIES := \
	$(BUILD_DIR)/test_types \
	$(BUILD_DIR)/test_status \
	$(BUILD_DIR)/test_constants \
	$(BUILD_DIR)/test_event \
	$(BUILD_DIR)/test_io_engine \
	$(BUILD_DIR)/test_timer \
	$(BUILD_DIR)/test_packet_element \
	$(BUILD_DIR)/test_packet \
	$(BUILD_DIR)/test_ethernet \
	$(BUILD_DIR)/test_ipv4 \
	$(BUILD_DIR)/test_tcp \
	$(BUILD_DIR)/test_udp \
	$(BUILD_DIR)/test_icmp \
	$(BUILD_DIR)/test_checksum \
	$(BUILD_DIR)/test_discovery_types \
	$(BUILD_DIR)/test_discovery_probe \
	$(BUILD_DIR)/test_discovery_scheduler \
		$(BUILD_DIR)/test_discovery_local \
		$(BUILD_DIR)/test_port_types \
		$(BUILD_DIR)/test_port_probe \
		$(BUILD_DIR)/test_port_scheduler \
		$(BUILD_DIR)/test_portscan_local

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

$(BUILD_DIR)/test_event: $(BUILD_DIR)/tests/unit/io/test_event.o $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_io_engine: $(BUILD_DIR)/tests/unit/io/test_io_engine.o $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_timer: $(BUILD_DIR)/tests/unit/io/test_timer.o $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_packet_element: $(BUILD_DIR)/tests/unit/packet/test_packet_element.o $(BUILD_DIR)/packet/packet_element.o $(BUILD_DIR)/packet/ethernet.o $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_packet: $(BUILD_DIR)/tests/unit/packet/test_packet.o $(PACKET_OBJECTS) $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_ethernet: $(BUILD_DIR)/tests/unit/packet/test_ethernet.o $(BUILD_DIR)/packet/packet_element.o $(BUILD_DIR)/packet/ethernet.o $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_ipv4: $(BUILD_DIR)/tests/unit/packet/test_ipv4.o $(BUILD_DIR)/packet/packet_element.o $(BUILD_DIR)/packet/ipv4.o $(BUILD_DIR)/packet/checksum.o $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_tcp: $(BUILD_DIR)/tests/unit/packet/test_tcp.o $(BUILD_DIR)/packet/packet_element.o $(BUILD_DIR)/packet/tcp.o $(BUILD_DIR)/packet/checksum.o $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_udp: $(BUILD_DIR)/tests/unit/packet/test_udp.o $(BUILD_DIR)/packet/packet_element.o $(BUILD_DIR)/packet/udp.o $(BUILD_DIR)/packet/checksum.o $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_icmp: $(BUILD_DIR)/tests/unit/packet/test_icmp.o $(BUILD_DIR)/packet/packet_element.o $(BUILD_DIR)/packet/icmp.o $(BUILD_DIR)/packet/checksum.o $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_checksum: $(BUILD_DIR)/tests/unit/packet/test_checksum.o $(BUILD_DIR)/packet/checksum.o | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

DISCOVERY_OBJECTS := $(BUILD_DIR)/discovery/discovery.o $(BUILD_DIR)/discovery/discovery_types.o \
	$(BUILD_DIR)/discovery/discovery_probe.o $(BUILD_DIR)/discovery/discovery_scheduler.o \
	$(BUILD_DIR)/discovery/icmp_discovery.o $(BUILD_DIR)/discovery/tcp_discovery.o $(BUILD_DIR)/discovery/arp_discovery.o

$(BUILD_DIR)/test_discovery_types: $(BUILD_DIR)/tests/unit/discovery/test_discovery_types.o $(BUILD_DIR)/discovery/discovery_types.o $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_discovery_probe: $(BUILD_DIR)/tests/unit/discovery/test_discovery_probe.o $(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_discovery_scheduler: $(BUILD_DIR)/tests/unit/discovery/test_discovery_scheduler.o $(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_discovery_local: $(BUILD_DIR)/tests/integration/discovery/test_discovery_local.o $(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_port_types: $(BUILD_DIR)/tests/unit/portscan/test_port_types.o $(BUILD_DIR)/portscan/port_types.o $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_port_probe: $(BUILD_DIR)/tests/unit/portscan/test_port_probe.o $(BUILD_DIR)/portscan/port_types.o $(BUILD_DIR)/portscan/port_result.o $(BUILD_DIR)/portscan/port_probe.o $(BUILD_DIR)/portscan/tcp_connect.o $(BUILD_DIR)/portscan/tcp_syn.o $(PACKET_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_port_scheduler: $(BUILD_DIR)/tests/unit/portscan/test_port_scheduler.o $(PORTSCAN_OBJECTS) $(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_portscan_local: $(BUILD_DIR)/tests/integration/portscan/test_portscan_local.o $(PORTSCAN_OBJECTS) $(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
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
	./$(BUILD_DIR)/test_packet_element
	./$(BUILD_DIR)/test_packet
	./$(BUILD_DIR)/test_ethernet
	./$(BUILD_DIR)/test_ipv4
	./$(BUILD_DIR)/test_tcp
	./$(BUILD_DIR)/test_udp
	./$(BUILD_DIR)/test_icmp
	./$(BUILD_DIR)/test_checksum
	./$(BUILD_DIR)/test_discovery_types
	./$(BUILD_DIR)/test_discovery_probe
	./$(BUILD_DIR)/test_discovery_scheduler
	./$(BUILD_DIR)/test_discovery_local
	./$(BUILD_DIR)/test_port_types
	./$(BUILD_DIR)/test_port_probe
	./$(BUILD_DIR)/test_port_scheduler
	./$(BUILD_DIR)/test_portscan_local

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

-include $(CPP_OBJECTS:.o=.d) $(C_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)
