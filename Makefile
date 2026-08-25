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
		src/scanengine/timing_profile.cpp \
		src/scanengine/rtt_estimator.cpp \
		src/scanengine/congestion.cpp \
		src/scanengine/scan_metrics.cpp \
		src/scanengine/scan_group.cpp \
		src/scanengine/adaptive_scheduler.cpp \
				src/scanengine/scan_engine.cpp \
		src/output/result_model.cpp \
		src/output/output_writer.cpp \
		src/output/output_context.cpp \
		src/output/output_normal.cpp \
		src/output/output_json.cpp \
		src/output/output_xml.cpp \
		src/output/output_grepable.cpp \
					src/output/output_manager.cpp \
		 src/net/interface.cpp \
		 src/net/interface_types.cpp \
		 src/net/transport.cpp \
		 src/net/transport_types.cpp \
		 src/net/capture.cpp \
		 src/net/capture_types.cpp \
		 src/net/packet_receiver.cpp \
		 src/net/packet_filter.cpp \
		 src/net/linux_transport.cpp \
		 src/net/linux_capture.cpp \
	src/net/unique_fd.cpp \
	src/net/network_scan_transport.cpp \
			 src/net/linux_discovery_transport.cpp \
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
		src/detect/service_types.cpp \
		src/detect/service_db.cpp \
		src/detect/service_matcher.cpp \
		src/detect/service_probe.cpp \
		src/detect/service_scheduler.cpp \
			src/detect/service_detector.cpp \
			src/db/db_types.cpp \
			src/db/os_db.cpp \
			src/db/os_db_loader.cpp \
			src/osdetect/os_probe_types.cpp \
			src/osdetect/os_types.cpp \
			src/osdetect/os_fingerprint.cpp \
			src/osdetect/os_probe.cpp \
			src/osdetect/os_matcher.cpp \
			src/osdetect/os_scheduler.cpp \
				src/osdetect/os_detector.cpp \
				src/orchestrator/scan_config.cpp \
				src/orchestrator/scan_events.cpp \
				src/orchestrator/scan_session.cpp \
				src/orchestrator/scan_stage.cpp \
				src/orchestrator/scan_report_builder.cpp \
				src/orchestrator/scan_pipeline.cpp \
				src/orchestrator/scan_orchestrator.cpp \
				src/main.cpp

C_SOURCES := src/c_api/status.c
CPP_OBJECTS := $(CPP_SOURCES:src/%.cpp=$(BUILD_DIR)/%.o)
C_OBJECTS := $(C_SOURCES:src/%.c=$(BUILD_DIR)/%.o)
CORE_OBJECTS := $(BUILD_DIR)/core/types.o $(BUILD_DIR)/core/status.o
CORE_LOG_OBJECT := $(BUILD_DIR)/core/log.o
C_API_OBJECTS := $(BUILD_DIR)/c_api/status.o
IO_OBJECTS := $(BUILD_DIR)/io/event.o $(BUILD_DIR)/io/io_engine.o $(BUILD_DIR)/io/timer.o
SCANENGINE_OBJECTS := $(BUILD_DIR)/scanengine/timing_profile.o $(BUILD_DIR)/scanengine/rtt_estimator.o \
	$(BUILD_DIR)/scanengine/congestion.o $(BUILD_DIR)/scanengine/scan_metrics.o \
	$(BUILD_DIR)/scanengine/scan_group.o $(BUILD_DIR)/scanengine/adaptive_scheduler.o \
			$(BUILD_DIR)/scanengine/scan_engine.o
OUTPUT_OBJECTS := $(BUILD_DIR)/output/result_model.o $(BUILD_DIR)/output/output_writer.o \
	$(BUILD_DIR)/output/output_context.o \
	$(BUILD_DIR)/output/output_normal.o $(BUILD_DIR)/output/output_json.o \
	$(BUILD_DIR)/output/output_xml.o $(BUILD_DIR)/output/output_grepable.o \
	$(BUILD_DIR)/output/output_manager.o
NET_OBJECTS := $(BUILD_DIR)/net/interface.o $(BUILD_DIR)/net/interface_types.o \
	$(BUILD_DIR)/net/transport.o $(BUILD_DIR)/net/transport_types.o \
	$(BUILD_DIR)/net/capture.o $(BUILD_DIR)/net/capture_types.o \
	$(BUILD_DIR)/net/packet_receiver.o $(BUILD_DIR)/net/packet_filter.o \
	$(BUILD_DIR)/net/linux_transport.o $(BUILD_DIR)/net/linux_capture.o \
	$(BUILD_DIR)/net/unique_fd.o $(BUILD_DIR)/net/network_scan_transport.o \
		$(BUILD_DIR)/net/linux_discovery_transport.o

PACKET_OBJECTS := $(BUILD_DIR)/packet/packet_element.o $(BUILD_DIR)/packet/packet.o \
	$(BUILD_DIR)/packet/ethernet.o $(BUILD_DIR)/packet/ipv4.o $(BUILD_DIR)/packet/tcp.o \
	$(BUILD_DIR)/packet/udp.o $(BUILD_DIR)/packet/icmp.o $(BUILD_DIR)/packet/checksum.o
PORTSCAN_OBJECTS := $(BUILD_DIR)/portscan/port_types.o $(BUILD_DIR)/portscan/port_result.o \
	$(BUILD_DIR)/portscan/port_probe.o $(BUILD_DIR)/portscan/tcp_connect.o \
	$(BUILD_DIR)/portscan/tcp_syn.o $(BUILD_DIR)/portscan/port_scheduler.o
DETECT_OBJECTS := $(BUILD_DIR)/detect/service_types.o $(BUILD_DIR)/detect/service_db.o \
	$(BUILD_DIR)/detect/service_matcher.o $(BUILD_DIR)/detect/service_probe.o \
		$(BUILD_DIR)/detect/service_scheduler.o $(BUILD_DIR)/detect/service_detector.o
DB_OBJECTS := $(BUILD_DIR)/db/db_types.o $(BUILD_DIR)/db/os_db.o $(BUILD_DIR)/db/os_db_loader.o
OSDETECT_OBJECTS := $(BUILD_DIR)/osdetect/os_probe_types.o $(BUILD_DIR)/osdetect/os_types.o \
		$(BUILD_DIR)/osdetect/os_fingerprint.o $(BUILD_DIR)/osdetect/os_probe.o \
		$(BUILD_DIR)/osdetect/os_matcher.o $(BUILD_DIR)/osdetect/os_scheduler.o \
		$(BUILD_DIR)/osdetect/os_detector.o
ORCHESTRATOR_OBJECTS := $(BUILD_DIR)/orchestrator/scan_config.o \
	$(BUILD_DIR)/orchestrator/scan_events.o $(BUILD_DIR)/orchestrator/scan_session.o \
	$(BUILD_DIR)/orchestrator/scan_stage.o $(BUILD_DIR)/orchestrator/scan_report_builder.o \
	$(BUILD_DIR)/orchestrator/scan_pipeline.o $(BUILD_DIR)/orchestrator/scan_orchestrator.o

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
	tests/integration/portscan/test_portscan_local.cpp \
	tests/unit/detect/test_service_types.cpp \
	tests/unit/detect/test_service_db.cpp \
	tests/unit/detect/test_service_probe.cpp \
	tests/unit/detect/test_service_matcher.cpp \
	tests/unit/detect/test_service_scheduler.cpp \
	tests/unit/detect/test_service_detector.cpp \
			tests/integration/detect/test_service_detection_local.cpp \
		tests/unit/db/test_os_db.cpp \
		tests/unit/osdetect/test_os_matcher.cpp \
		tests/unit/osdetect/test_os_probe.cpp \
		tests/unit/osdetect/test_os_scheduler.cpp \
			tests/integration/osdetect/test_os_detection_injected.cpp \
		tests/unit/scanengine/test_timing_profile.cpp \
		tests/unit/scanengine/test_rtt_estimator.cpp \
		tests/unit/scanengine/test_congestion.cpp \
		tests/unit/scanengine/test_scan_metrics.cpp \
		tests/unit/scanengine/test_scan_group.cpp \
		tests/unit/scanengine/test_adaptive_scheduler.cpp \
		tests/unit/scanengine/test_scan_engine.cpp \
		tests/integration/scanengine/test_scan_engine_io.cpp \
		tests/unit/output/test_result_model.cpp \
		tests/unit/output/test_output_context.cpp \
		tests/unit/output/test_output_normal.cpp \
		tests/unit/output/test_output_json.cpp \
		tests/unit/output/test_output_xml.cpp \
		tests/unit/output/test_output_grepable.cpp \
		tests/unit/output/test_output_manager.cpp \
			tests/integration/output/test_output_integration.cpp \
			tests/unit/net/test_interface_types.cpp \
			tests/unit/net/test_transport.cpp \
			tests/unit/net/test_capture.cpp \
			tests/unit/net/test_packet_receiver.cpp \
			tests/unit/net/test_packet_filter.cpp \
			tests/unit/net/test_linux_transport.cpp \
		tests/unit/net/test_network_scan_transport.cpp \
		tests/unit/net/test_linux_discovery_transport.cpp \
				 tests/integration/net/test_linux_loopback.cpp \
			tests/unit/orchestrator/test_scan_config.cpp \
			tests/unit/orchestrator/test_scan_state.cpp \
			tests/unit/orchestrator/test_scan_session.cpp \
			tests/unit/orchestrator/test_scan_events.cpp \
			tests/unit/orchestrator/test_scan_report_builder.cpp \
			tests/unit/orchestrator/test_scan_stage.cpp \
			tests/unit/orchestrator/test_pipeline.cpp \
			tests/integration/orchestrator/test_pipeline_cancellation.cpp \
			tests/integration/orchestrator/test_pipeline_discovery.cpp \
			tests/integration/orchestrator/test_pipeline_stages.cpp \
			tests/integration/orchestrator/test_pipeline_stress.cpp

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
		$(BUILD_DIR)/test_portscan_local \
		$(BUILD_DIR)/test_service_types \
		$(BUILD_DIR)/test_service_db \
		$(BUILD_DIR)/test_service_probe \
		$(BUILD_DIR)/test_service_matcher \
		$(BUILD_DIR)/test_service_scheduler \
		$(BUILD_DIR)/test_service_detector \
			$(BUILD_DIR)/test_service_detection_local \
			$(BUILD_DIR)/test_os_db \
			$(BUILD_DIR)/test_os_matcher \
			$(BUILD_DIR)/test_os_probe \
			$(BUILD_DIR)/test_os_scheduler \
				$(BUILD_DIR)/test_os_detection_injected \
				$(BUILD_DIR)/test_timing_profile \
				$(BUILD_DIR)/test_rtt_estimator \
				$(BUILD_DIR)/test_congestion \
				$(BUILD_DIR)/test_scan_metrics \
				$(BUILD_DIR)/test_scan_group \
				$(BUILD_DIR)/test_adaptive_scheduler \
				$(BUILD_DIR)/test_scan_engine \
				$(BUILD_DIR)/test_scan_engine_io \
		$(BUILD_DIR)/test_result_model \
		$(BUILD_DIR)/test_output_context \
		$(BUILD_DIR)/test_output_normal \
		$(BUILD_DIR)/test_output_json \
		$(BUILD_DIR)/test_output_xml \
		$(BUILD_DIR)/test_output_grepable \
		$(BUILD_DIR)/test_output_manager \
			$(BUILD_DIR)/test_output_integration \
			$(BUILD_DIR)/test_interface_types \
			$(BUILD_DIR)/test_transport \
			$(BUILD_DIR)/test_capture \
			$(BUILD_DIR)/test_packet_receiver \
			$(BUILD_DIR)/test_packet_filter \
			$(BUILD_DIR)/test_linux_transport \
			$(BUILD_DIR)/test_network_scan_transport \
			$(BUILD_DIR)/test_linux_discovery_transport \
				$(BUILD_DIR)/test_linux_loopback \
			$(BUILD_DIR)/test_scan_config \
			$(BUILD_DIR)/test_scan_state \
			$(BUILD_DIR)/test_scan_session \
			$(BUILD_DIR)/test_scan_events \
			$(BUILD_DIR)/test_scan_report_builder \
			$(BUILD_DIR)/test_scan_stage \
			$(BUILD_DIR)/test_pipeline \
			$(BUILD_DIR)/test_pipeline_cancellation \
			$(BUILD_DIR)/test_pipeline_discovery \
			$(BUILD_DIR)/test_pipeline_stages \
			$(BUILD_DIR)/test_pipeline_stress

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

$(BUILD_DIR)/test_port_scheduler: $(BUILD_DIR)/tests/unit/portscan/test_port_scheduler.o $(PORTSCAN_OBJECTS) $(SCANENGINE_OBJECTS) $(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_portscan_local: $(BUILD_DIR)/tests/integration/portscan/test_portscan_local.o $(PORTSCAN_OBJECTS) $(SCANENGINE_OBJECTS) $(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_service_types: $(BUILD_DIR)/tests/unit/detect/test_service_types.o $(BUILD_DIR)/detect/service_types.o $(BUILD_DIR)/portscan/port_types.o $(BUILD_DIR)/portscan/port_result.o $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_service_db: $(BUILD_DIR)/tests/unit/detect/test_service_db.o $(BUILD_DIR)/detect/service_db.o $(BUILD_DIR)/detect/service_types.o $(BUILD_DIR)/portscan/port_types.o $(BUILD_DIR)/portscan/port_result.o $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_service_probe: $(BUILD_DIR)/tests/unit/detect/test_service_probe.o $(BUILD_DIR)/detect/service_probe.o $(BUILD_DIR)/detect/service_db.o $(BUILD_DIR)/detect/service_types.o $(BUILD_DIR)/portscan/port_types.o $(BUILD_DIR)/portscan/port_result.o $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_service_matcher: $(BUILD_DIR)/tests/unit/detect/test_service_matcher.o $(BUILD_DIR)/detect/service_matcher.o $(BUILD_DIR)/detect/service_db.o $(BUILD_DIR)/detect/service_types.o $(BUILD_DIR)/portscan/port_types.o $(BUILD_DIR)/portscan/port_result.o $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_service_scheduler: $(BUILD_DIR)/tests/unit/detect/test_service_scheduler.o $(DETECT_OBJECTS) $(PORTSCAN_OBJECTS) $(SCANENGINE_OBJECTS) $(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_service_detector: $(BUILD_DIR)/tests/unit/detect/test_service_detector.o $(DETECT_OBJECTS) $(PORTSCAN_OBJECTS) $(SCANENGINE_OBJECTS) $(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_service_detection_local: $(BUILD_DIR)/tests/integration/detect/test_service_detection_local.o $(DETECT_OBJECTS) $(PORTSCAN_OBJECTS) $(SCANENGINE_OBJECTS) $(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

OS_TEST_OBJECTS := $(DB_OBJECTS) $(OSDETECT_OBJECTS) $(PORTSCAN_OBJECTS) $(SCANENGINE_OBJECTS) $(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT)

$(BUILD_DIR)/test_os_db: $(BUILD_DIR)/tests/unit/db/test_os_db.o $(DB_OBJECTS) $(CORE_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_os_matcher: $(BUILD_DIR)/tests/unit/osdetect/test_os_matcher.o $(OS_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_os_probe: $(BUILD_DIR)/tests/unit/osdetect/test_os_probe.o $(OS_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_os_scheduler: $(BUILD_DIR)/tests/unit/osdetect/test_os_scheduler.o $(OS_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_os_detection_injected: $(BUILD_DIR)/tests/integration/osdetect/test_os_detection_injected.o $(OS_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

SCANENGINE_TEST_OBJECTS := $(SCANENGINE_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT)
OUTPUT_TEST_OBJECTS := $(OUTPUT_OBJECTS) $(DB_OBJECTS) $(OSDETECT_OBJECTS) $(DETECT_OBJECTS) \
	$(PORTSCAN_OBJECTS) $(DISCOVERY_OBJECTS) $(PACKET_OBJECTS) $(SCANENGINE_OBJECTS) \
	$(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT)

$(BUILD_DIR)/test_timing_profile: $(BUILD_DIR)/tests/unit/scanengine/test_timing_profile.o $(SCANENGINE_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_rtt_estimator: $(BUILD_DIR)/tests/unit/scanengine/test_rtt_estimator.o $(SCANENGINE_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_congestion: $(BUILD_DIR)/tests/unit/scanengine/test_congestion.o $(SCANENGINE_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_scan_metrics: $(BUILD_DIR)/tests/unit/scanengine/test_scan_metrics.o $(SCANENGINE_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_scan_group: $(BUILD_DIR)/tests/unit/scanengine/test_scan_group.o $(SCANENGINE_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_adaptive_scheduler: $(BUILD_DIR)/tests/unit/scanengine/test_adaptive_scheduler.o $(SCANENGINE_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_scan_engine: $(BUILD_DIR)/tests/unit/scanengine/test_scan_engine.o $(SCANENGINE_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_scan_engine_io: $(BUILD_DIR)/tests/integration/scanengine/test_scan_engine_io.o $(SCANENGINE_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_result_model: $(BUILD_DIR)/tests/unit/output/test_result_model.o $(OUTPUT_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_output_context: $(BUILD_DIR)/tests/unit/output/test_output_context.o $(OUTPUT_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_output_normal: $(BUILD_DIR)/tests/unit/output/test_output_normal.o $(OUTPUT_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_output_json: $(BUILD_DIR)/tests/unit/output/test_output_json.o $(OUTPUT_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_output_xml: $(BUILD_DIR)/tests/unit/output/test_output_xml.o $(OUTPUT_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_output_grepable: $(BUILD_DIR)/tests/unit/output/test_output_grepable.o $(OUTPUT_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_output_manager: $(BUILD_DIR)/tests/unit/output/test_output_manager.o $(OUTPUT_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_output_integration: $(BUILD_DIR)/tests/integration/output/test_output_integration.o $(OUTPUT_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

NET_TEST_OBJECTS := $(NET_OBJECTS) $(PACKET_OBJECTS) $(DISCOVERY_OBJECTS) $(IO_OBJECTS) $(CORE_OBJECTS) $(CORE_LOG_OBJECT)
$(BUILD_DIR)/test_interface_types: $(BUILD_DIR)/tests/unit/net/test_interface_types.o $(NET_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_transport: $(BUILD_DIR)/tests/unit/net/test_transport.o $(NET_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_capture: $(BUILD_DIR)/tests/unit/net/test_capture.o $(NET_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_packet_receiver: $(BUILD_DIR)/tests/unit/net/test_packet_receiver.o $(NET_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_packet_filter: $(BUILD_DIR)/tests/unit/net/test_packet_filter.o $(NET_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_linux_transport: $(BUILD_DIR)/tests/unit/net/test_linux_transport.o $(NET_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_network_scan_transport: $(BUILD_DIR)/tests/unit/net/test_network_scan_transport.o $(NET_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_linux_discovery_transport: $(BUILD_DIR)/tests/unit/net/test_linux_discovery_transport.o $(NET_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_linux_loopback: $(BUILD_DIR)/tests/integration/net/test_linux_loopback.o $(NET_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

ORCHESTRATOR_TEST_OBJECTS := $(OUTPUT_TEST_OBJECTS) $(NET_OBJECTS) $(ORCHESTRATOR_OBJECTS)
$(BUILD_DIR)/test_scan_config: $(BUILD_DIR)/tests/unit/orchestrator/test_scan_config.o $(ORCHESTRATOR_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_scan_state: $(BUILD_DIR)/tests/unit/orchestrator/test_scan_state.o $(ORCHESTRATOR_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_scan_session: $(BUILD_DIR)/tests/unit/orchestrator/test_scan_session.o $(ORCHESTRATOR_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_scan_events: $(BUILD_DIR)/tests/unit/orchestrator/test_scan_events.o $(ORCHESTRATOR_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_scan_report_builder: $(BUILD_DIR)/tests/unit/orchestrator/test_scan_report_builder.o $(ORCHESTRATOR_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_scan_stage: $(BUILD_DIR)/tests/unit/orchestrator/test_scan_stage.o $(ORCHESTRATOR_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_pipeline: $(BUILD_DIR)/tests/unit/orchestrator/test_pipeline.o $(ORCHESTRATOR_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_pipeline_cancellation: $(BUILD_DIR)/tests/integration/orchestrator/test_pipeline_cancellation.o $(ORCHESTRATOR_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_pipeline_discovery: $(BUILD_DIR)/tests/integration/orchestrator/test_pipeline_discovery.o $(ORCHESTRATOR_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_pipeline_stages: $(BUILD_DIR)/tests/integration/orchestrator/test_pipeline_stages.o $(ORCHESTRATOR_TEST_OBJECTS) | $(BUILD_DIR)
	$(CXX) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_pipeline_stress: $(BUILD_DIR)/tests/integration/orchestrator/test_pipeline_stress.o $(ORCHESTRATOR_TEST_OBJECTS) | $(BUILD_DIR)
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
	./$(BUILD_DIR)/test_service_types
	./$(BUILD_DIR)/test_service_db
	./$(BUILD_DIR)/test_service_probe
	./$(BUILD_DIR)/test_service_matcher
	./$(BUILD_DIR)/test_service_scheduler
	./$(BUILD_DIR)/test_service_detector
		./$(BUILD_DIR)/test_service_detection_local
		./$(BUILD_DIR)/test_os_db
		./$(BUILD_DIR)/test_os_matcher
		./$(BUILD_DIR)/test_os_probe
		./$(BUILD_DIR)/test_os_scheduler
			./$(BUILD_DIR)/test_os_detection_injected
			./$(BUILD_DIR)/test_timing_profile
			./$(BUILD_DIR)/test_rtt_estimator
			./$(BUILD_DIR)/test_congestion
			./$(BUILD_DIR)/test_scan_metrics
			./$(BUILD_DIR)/test_scan_group
			./$(BUILD_DIR)/test_adaptive_scheduler
			./$(BUILD_DIR)/test_scan_engine
			./$(BUILD_DIR)/test_scan_engine_io
		./$(BUILD_DIR)/test_result_model
		./$(BUILD_DIR)/test_output_context
		./$(BUILD_DIR)/test_output_normal
		./$(BUILD_DIR)/test_output_json
		./$(BUILD_DIR)/test_output_xml
		./$(BUILD_DIR)/test_output_grepable
		./$(BUILD_DIR)/test_output_manager
			./$(BUILD_DIR)/test_output_integration
			./$(BUILD_DIR)/test_interface_types
			./$(BUILD_DIR)/test_transport
			./$(BUILD_DIR)/test_capture
			./$(BUILD_DIR)/test_packet_receiver
			./$(BUILD_DIR)/test_packet_filter
			./$(BUILD_DIR)/test_linux_transport
			./$(BUILD_DIR)/test_network_scan_transport
			./$(BUILD_DIR)/test_linux_discovery_transport
							./$(BUILD_DIR)/test_linux_loopback
			./$(BUILD_DIR)/test_scan_config
			./$(BUILD_DIR)/test_scan_state
			./$(BUILD_DIR)/test_scan_session
			./$(BUILD_DIR)/test_scan_events
			./$(BUILD_DIR)/test_scan_report_builder
			./$(BUILD_DIR)/test_scan_stage
			./$(BUILD_DIR)/test_pipeline
			./$(BUILD_DIR)/test_pipeline_cancellation
			./$(BUILD_DIR)/test_pipeline_discovery
			./$(BUILD_DIR)/test_pipeline_stages
			./$(BUILD_DIR)/test_pipeline_stress



clean:
	rm -rf $(BUILD_DIR) $(TARGET)

-include $(CPP_OBJECTS:.o=.d) $(C_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)
