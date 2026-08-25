#ifndef SKAN_TEST_OUTPUT_TEST_FIXTURE_HPP
#define SKAN_TEST_OUTPUT_TEST_FIXTURE_HPP

#include <chrono>
#include <string>

#include "output/result_model.hpp"
#include "osdetect/os_matcher.hpp"

namespace skan::output::test {

inline ScanReport make_report()
{
    ScanReport report;
    report.scanner_name = "Skan";
    report.scanner_version = "0.1.0";
    report.started_at = "2026-08-25T12:00:00Z";
    report.finished_at = "2026-08-25T12:00:00.042Z";
    report.duration_ms = 42.0;
    report.target_spec = "127.0.0.1\n*";
    report.timing_profile = scanengine::TimingProfileId::T3;
    scanengine::ScanMetrics metrics;
    metrics.total_queued = 3U;
    metrics.total_submitted = 3U;
    metrics.completed = 3U;
    metrics.current_parallelism = 2U;
    metrics.maximum_observed_parallelism = 3U;
    metrics.record_rtt(std::chrono::milliseconds{4});
    metrics.record_rtt(std::chrono::milliseconds{8});
    metrics.retry_count = 1U;
    metrics.timeout_count = 1U;
    metrics.estimated_drop_rate = 0.125;
    report.timing_metrics = metrics;
    report.warnings.push_back("banner warning: <unsafe>\nnext");
    report.errors.push_back("error \\\"quoted\\\" & tab\t");

    HostResult second;
    second.address = "192.0.2.20";
    second.state = discovery::HostState::Up;
    second.hostname = "host \"two\"";
    second.rtt_ms = 1.25;
    second.ports.push_back(portscan::PortResult{
        second.address,
        portscan::Port{80U, portscan::Protocol::Tcp},
        portscan::PortState::Open,
        portscan::ScanProbeType::TcpConnect,
        portscan::ScanReason::ImmediateSuccess,
        1.25,
        {},
        0U,
        std::nullopt});
    second.ports.push_back(portscan::PortResult{
        second.address,
        portscan::Port{22U, portscan::Protocol::Tcp},
        portscan::PortState::Closed,
        portscan::ScanProbeType::TcpConnect,
        portscan::ScanReason::ConnectionRefused,
        std::nullopt,
        {},
        0U,
        std::nullopt});
    second.ports.push_back(portscan::PortResult{
        second.address,
        portscan::Port{443U, portscan::Protocol::Tcp},
        portscan::PortState::Filtered,
        portscan::ScanProbeType::TcpConnect,
        portscan::ScanReason::Timeout,
        std::nullopt,
        {},
        0U,
        std::nullopt});
    second.services.push_back(detect::ServiceResult{
        second.address,
        portscan::Port{80U, portscan::Protocol::Tcp},
        portscan::Protocol::Tcp,
        portscan::PortState::Open,
        detect::DetectionState::Detected,
        "http\"\\\n\t",
        "nginx<&\"'",
        "1.2✓",
        "C:\\Windows",
        1.0,
        detect::DetectionMethod::Banner,
        "banner",
        1.25,
        detect::DetectionError::None,
        {}});
    second.os_matches.push_back(osdetect::OSMatchResult{
        "SkanWindowsGeneric", "Skan", "Windows", "generic", "desktop", 0.91,
        db::MatchCategory::StrongMatch, {"ttl"}, {}, {}});
    second.os_matches.push_back(osdetect::OSMatchResult{
        "SkanLinuxGeneric", "Skan", "Linux", "generic", "server", 0.91,
        db::MatchCategory::StrongMatch, {"ttl"}, {}, {}});
    osdetect::OSDetectionResult os_detection;
    os_detection.target = second.address;
    os_detection.state = osdetect::OSDetectionState::Complete;
    os_detection.vendor = "Skan";
    os_detection.family = "Linux";
    os_detection.generation = "generic";
    os_detection.device_type = "server";
    os_detection.confidence = 0.91;
    os_detection.category = db::MatchCategory::StrongMatch;
    os_detection.matches = second.os_matches;
    os_detection.probes_generated = 12U;
    os_detection.probes_sent = 12U;
    os_detection.responses_received = 7U;
    os_detection.probes_timed_out = 5U;
    os_detection.probes_unsupported = 0U;
    os_detection.probes_malformed = 0U;
    os_detection.rtt_ms = 4.5;
    os_detection.error = osdetect::OSDetectionError::None;
    os_detection.observed.target = second.address;
    os_detection.observed.probes_generated = 12U;
    os_detection.observed.probes_sent = 12U;
    os_detection.observed.responses_received = 7U;
    os_detection.observed.probes_timed_out = 5U;
    second.os_detection = std::move(os_detection);
    second.warnings.push_back("host warning > & <");
    second.errors.push_back("host error");

    HostResult first;
    first.address = "192.0.2.10";
    first.state = discovery::HostState::Unknown;
    report.hosts.push_back(std::move(second));
    report.hosts.push_back(std::move(first));
    return report;
}

} // namespace skan::output::test

#endif // SKAN_TEST_OUTPUT_TEST_FIXTURE_HPP
