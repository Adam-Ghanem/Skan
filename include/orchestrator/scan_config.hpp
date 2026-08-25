#ifndef SKAN_ORCHESTRATOR_SCAN_CONFIG_HPP
#define SKAN_ORCHESTRATOR_SCAN_CONFIG_HPP

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "core/status.hpp"
#include "core/types.hpp"
#include "output/result_model.hpp"
#include "portscan/port_types.hpp"
#include "scanengine/timing_profile.hpp"

namespace skan::orchestrator {

enum class ScanTransport {
    Offline = 0,
    Linux,
    Connect
};

enum class StageKind {
    Discovery = 0,
    PortScan,
    ServiceDetection,
    OSDetection,
    Output
};

struct ScanConfig final {
    std::vector<core::Target> targets;
    ScanTransport transport{ScanTransport::Connect};
    std::optional<std::string> interface_name;

    bool discovery_enabled{false};
    bool port_scan_enabled{true};
    bool service_detection_enabled{false};
    bool os_detection_enabled{false};

    portscan::ScanProbeType port_method{portscan::ScanProbeType::TcpConnect};
    std::vector<std::uint16_t> ports;
    scanengine::TimingProfile timing_profile{};
    std::chrono::milliseconds timeout{portscan::kDefaultPortTimeout};
    bool adaptive_timing{false};
    std::size_t min_parallelism{1U};
    std::size_t max_parallelism{portscan::kDefaultMaxOutstanding};
    std::size_t retries{0U};

    std::string service_db_path;
    std::size_t max_response_bytes{8192U};
    std::size_t max_probes_per_port{2U};
    std::string os_db_path;
    output::OutputFormat output_format{output::OutputFormat::Normal};
    std::optional<std::string> output_file;

    core::StatusCode validate() const noexcept;
};

const char *scan_transport_name(ScanTransport transport) noexcept;
const char *stage_kind_name(StageKind stage) noexcept;

} // namespace skan::orchestrator

#endif // SKAN_ORCHESTRATOR_SCAN_CONFIG_HPP
