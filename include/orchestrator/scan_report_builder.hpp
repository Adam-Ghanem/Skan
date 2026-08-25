#ifndef SKAN_ORCHESTRATOR_SCAN_REPORT_BUILDER_HPP
#define SKAN_ORCHESTRATOR_SCAN_REPORT_BUILDER_HPP

#include <chrono>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "core/types.hpp"
#include "detect/service_types.hpp"
#include "discovery/discovery_types.hpp"
#include "orchestrator/scan_config.hpp"
#include "osdetect/os_matcher.hpp"
#include "output/result_model.hpp"
#include "portscan/port_result.hpp"
#include "scanengine/scan_metrics.hpp"

namespace skan::orchestrator {

struct OSReportEvidence final {
    std::string target;
    std::vector<osdetect::OSMatchResult> matches;
    std::optional<osdetect::OSDetectionResult> result;
};

class ScanReportBuilder final {
public:
    static output::ScanReport build(
        const ScanConfig &config,
        const core::Target &target,
        std::span<const discovery::DiscoveryResult> discovery_results,
        std::span<const portscan::PortResult> port_results,
        std::span<const detect::ServiceResult> service_results,
        std::span<const OSReportEvidence> os_results,
        const std::optional<scanengine::ScanMetrics> &timing_metrics,
        std::chrono::steady_clock::time_point started_at,
        std::chrono::steady_clock::time_point finished_at,
        std::span<const std::string> warnings = {},
        std::span<const std::string> errors = {});
};

} // namespace skan::orchestrator

#endif // SKAN_ORCHESTRATOR_SCAN_REPORT_BUILDER_HPP
