#ifndef SKAN_OUTPUT_RESULT_MODEL_HPP
#define SKAN_OUTPUT_RESULT_MODEL_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/constants.hpp"
#include "core/types.hpp"
#include "detect/service_types.hpp"
#include "discovery/discovery_types.hpp"
#include "osdetect/os_matcher.hpp"
#include "portscan/port_result.hpp"
#include "scanengine/scan_metrics.hpp"
#include "scanengine/timing_profile.hpp"

namespace skan::output {

enum class OutputFormat : std::uint8_t {
    Normal = 0,
    Json,
    Xml,
    Grepable
};

enum class OutputStatus : std::uint8_t {
    Ok = 0,
    InvalidFormat,
    InvalidReport,
    IoError,
    SerializationError
};

const char *output_format_name(OutputFormat format) noexcept;
const char *output_status_name(OutputStatus status) noexcept;
OutputStatus parse_output_format(std::string_view text, OutputFormat &format) noexcept;

struct HostResult final {
    std::string address;
    std::optional<std::string> hostname;
    discovery::HostState state{discovery::HostState::Unknown};
    std::optional<double> rtt_ms;
    std::vector<portscan::PortResult> ports;
    std::vector<detect::ServiceResult> services;
    std::vector<osdetect::OSMatchResult> os_matches;
    std::optional<osdetect::OSDetectionResult> os_detection;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    core::AddressFamily family{core::AddressFamily::Unknown};
};

struct ScanSummary final {
    std::size_t hosts{0U};
    std::size_t hosts_up{0U};
    std::size_t hosts_down{0U};
    std::size_t hosts_unknown{0U};
    std::size_t ports_scanned{0U};
    std::size_t open_ports{0U};
    std::size_t closed_ports{0U};
    std::size_t filtered_ports{0U};
    std::size_t open_or_filtered_ports{0U};
    std::size_t unfiltered_ports{0U};
    std::size_t error_ports{0U};
    std::size_t unreachable_ports{0U};
    std::size_t unknown_ports{0U};
    std::size_t services_detected{0U};
    std::size_t os_matches{0U};
};

struct ScanReport final {
    std::string scanner_name{"Skan"};
    std::string scanner_version{core::constants::SKAN_VERSION_STRING};
    std::optional<std::string> started_at;
    std::optional<std::string> finished_at;
    std::optional<double> duration_ms;
    std::optional<std::string> target_spec;
    std::optional<scanengine::TimingProfileId> timing_profile;
    std::optional<scanengine::ScanMetrics> timing_metrics;
    std::vector<HostResult> hosts;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
};

ScanSummary calculate_summary(const ScanReport &report) noexcept;
OutputStatus validate_report(const ScanReport &report) noexcept;

} // namespace skan::output

#endif // SKAN_OUTPUT_RESULT_MODEL_HPP
