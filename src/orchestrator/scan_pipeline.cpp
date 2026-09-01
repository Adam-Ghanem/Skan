#include "orchestrator/scan_pipeline.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

#include "net/interface.hpp"
#include "output/output_manager.hpp"

namespace skan::orchestrator {
namespace {

core::IpAddress host_ip(const core::Host &host) noexcept
{
    if (host.ip_address.valid()) {
        return host.ip_address;
    }
    return core::parse_ip_address(host.address).value_or(core::IpAddress{});
}

core::Target aggregate_targets(const std::vector<core::Target> &targets)
{
    core::Target aggregate;
    std::size_t host_count = 0U;
    std::size_t specification_bytes = 0U;
    for (const core::Target &target : targets) {
        host_count += target.resolved_hosts.size();
        specification_bytes += target.original_specification.size();
    }
    if (targets.size() > 1U) {
        specification_bytes += targets.size() - 1U;
    }
    aggregate.original_specification.reserve(specification_bytes);
    aggregate.resolved_hosts.reserve(host_count);
    std::unordered_set<std::string_view> seen_addresses;
    seen_addresses.reserve(host_count);
    for (const core::Target &target : targets) {
        if (!aggregate.original_specification.empty()) {
            aggregate.original_specification.push_back(';');
        }
        aggregate.original_specification += target.original_specification;
        for (const core::Host &host : target.resolved_hosts) {
            if (seen_addresses.emplace(host.address).second) {
                aggregate.resolved_hosts.push_back(host);
            }
        }
    }
    std::sort(aggregate.resolved_hosts.begin(), aggregate.resolved_hosts.end(),
              [](const core::Host &left, const core::Host &right) {
                  const core::IpAddress left_address = host_ip(left);
                  const core::IpAddress right_address = host_ip(right);
                  if (left_address.valid() && right_address.valid()) {
                      return left_address < right_address;
                  }
                  if (left_address.valid() != right_address.valid()) {
                      return left_address.valid();
                  }
                  return left.address < right.address;
              });
    return aggregate;
}

bool replace_output_file(const std::string &path, const std::string &contents)
{
    const std::string temporary_template = path + ".skan.tmp.XXXXXX";
    std::vector<char> mutable_template(temporary_template.begin(), temporary_template.end());
    mutable_template.push_back('\0');
    const int temporary_descriptor = ::mkstemp(mutable_template.data());
    if (temporary_descriptor < 0) {
        return false;
    }
    const std::string temporary_path(mutable_template.data());
    std::size_t offset = 0U;
    bool write_succeeded = true;
    while (offset < contents.size()) {
        const ssize_t written = ::write(temporary_descriptor, contents.data() + offset, contents.size() - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            write_succeeded = false;
            break;
        }
        if (written == 0) {
            write_succeeded = false;
            break;
        }
        offset += static_cast<std::size_t>(written);
    }
    if (write_succeeded && ::fsync(temporary_descriptor) < 0) {
        write_succeeded = false;
    }
    if (::close(temporary_descriptor) < 0) {
        write_succeeded = false;
    }
    if (!write_succeeded) {
        (void)std::remove(temporary_path.c_str());
        return false;
    }

    std::error_code error;
    std::filesystem::rename(temporary_path, path, error);
    if (error) {
        (void)std::remove(temporary_path.c_str());
        return false;
    }
    return true;
}

core::Target only_up_hosts(const core::Target &target, const DiscoveryStage &stage)
{
    core::Target filtered;
    filtered.original_specification = target.original_specification;
    for (const core::Host &host : target.resolved_hosts) {
        if (stage.host_state(host.address) == discovery::HostState::Up) {
            filtered.resolved_hosts.push_back(host);
        }
    }
    return filtered;
}

} // namespace

ScanPipeline::ScanPipeline(ScanConfig config, ScanEventSink sink, ScanStageDependencies dependencies)
    : config_(std::move(config)),
      dependencies_(std::move(dependencies)),
      session_("scan-1", std::move(sink))
{
    session_.set_cancel_callback([this]() { cancel_active(); });
}

ScanPipeline::~ScanPipeline()
{
    session_.set_cancel_callback({});
}

const ScanConfig &ScanPipeline::config() const noexcept { return config_; }
const ScanSession &ScanPipeline::session() const noexcept { return session_; }
ScanSession &ScanPipeline::session() noexcept { return session_; }
PipelineState ScanPipeline::state() const noexcept { return session_.state(); }
const std::optional<output::ScanReport> &ScanPipeline::report() const noexcept { return session_.report(); }
bool ScanPipeline::cancelled() const noexcept { return session_.cancelled(); }

core::Target ScanPipeline::aggregate_target() const
{
    return aggregate_targets(config_.targets);
}

void ScanPipeline::emit_stage(ScanEventType type, StageKind stage, std::string message)
{
    session_.emit(ScanEvent{type, {}, stage, active_target_, std::nullopt, std::move(message), {}});
}

void ScanPipeline::fail(std::string message, core::StatusCode status)
{
    final_status_ = status;
    session_.set_error(message);
    (void)session_.transition(PipelineState::Failed);
    session_.emit(ScanEvent{ScanEventType::ScanFailed, {}, std::nullopt, active_target_, std::nullopt,
                            std::move(message), {}});
    session_.finish_clock();
}

bool ScanPipeline::execute_discovery(const core::Target &target, std::vector<discovery::DiscoveryResult> &results)
{
    if (cancelled()) {
        return false;
    }
    (void)session_.transition(PipelineState::Discovering);
    emit_stage(ScanEventType::StageStarted, StageKind::Discovery, "discovery started");
    if (cancelled()) {
        return false;
    }
    discovery_stage_ = std::make_unique<DiscoveryStage>(session_.io_engine(), config_, target, &dependencies_);
    const StageResult stage_result = discovery_stage_->start();
    if (stage_result.cancelled || cancelled()) {
        return false;
    }
    if (!stage_result.success()) {
        fail(stage_result.message, stage_result.status);
        return false;
    }
    results = discovery_stage_->results();
    for (const core::Host &host : target.resolved_hosts) {
        session_.emit(ScanEvent{ScanEventType::HostDiscovered, {}, StageKind::Discovery, std::nullopt, std::nullopt,
                                host.address, {}});
    }
    emit_stage(ScanEventType::StageCompleted, StageKind::Discovery, "discovery completed");
    return true;
}

bool ScanPipeline::execute_port_scan(
    const core::Target &target,
    std::vector<portscan::PortResult> &results,
    std::optional<scanengine::ScanMetrics> &metrics)
{
    if (cancelled()) {
        return false;
    }
    if (target.resolved_hosts.empty()) {
        return true;
    }
    (void)session_.transition(PipelineState::PortScanning);
    emit_stage(ScanEventType::StageStarted, StageKind::PortScan, "port scan started");
    if (cancelled()) {
        return false;
    }
    port_stage_ = std::make_unique<PortScanStage>(session_.io_engine(), config_, target, &dependencies_);
    const StageResult stage_result = port_stage_->start();
    if (stage_result.cancelled || cancelled()) {
        return false;
    }
    if (!stage_result.success()) {
        fail(stage_result.message, stage_result.status);
        return false;
    }
    results = port_stage_->results();
    if (port_stage_->timing_metrics() != nullptr) {
        metrics = *port_stage_->timing_metrics();
    }
    for (const portscan::PortResult &result : results) {
        session_.emit(ScanEvent{ScanEventType::PortCompleted, {}, StageKind::PortScan, std::nullopt,
                                result.port.number, result.target, {}});
    }
    emit_stage(ScanEventType::StageCompleted, StageKind::PortScan, "port scan completed");
    return true;
}

bool ScanPipeline::execute_udp_scan(
    const core::Target &target,
    std::vector<portscan::PortResult> &results,
    std::optional<scanengine::ScanMetrics> &metrics)
{
    if (cancelled()) {
        return false;
    }
    if (target.resolved_hosts.empty()) {
        return true;
    }
    (void)session_.transition(PipelineState::PortScanning);
    emit_stage(ScanEventType::StageStarted, StageKind::UdpScan, "UDP scan started");
    if (cancelled()) {
        return false;
    }
    udp_stage_ = std::make_unique<UdpScanStage>(session_.io_engine(), config_, target, &dependencies_);
    const StageResult stage_result = udp_stage_->start();
    if (stage_result.cancelled || cancelled()) {
        return false;
    }
    if (!stage_result.success()) {
        fail(stage_result.message, stage_result.status);
        return false;
    }
    results = udp_stage_->results();
    if (udp_stage_->timing_metrics() != nullptr && !metrics.has_value()) {
        metrics = *udp_stage_->timing_metrics();
    }
    for (const portscan::PortResult &result : results) {
        session_.emit(ScanEvent{ScanEventType::PortCompleted, {}, StageKind::UdpScan, std::nullopt,
                                result.port.number, result.target, {}});
    }
    emit_stage(ScanEventType::StageCompleted, StageKind::UdpScan, "UDP scan completed");
    return true;
}

bool ScanPipeline::execute_service_detection(
    const std::vector<portscan::PortResult> &ports,
    std::vector<detect::ServiceResult> &results)
{
    if (cancelled()) {
        return false;
    }
    const bool has_open = std::any_of(ports.begin(), ports.end(), [](const portscan::PortResult &port) {
        return port.state == portscan::PortState::Open;
    });
    if (!has_open) {
        return true;
    }
    (void)session_.transition(PipelineState::DetectingServices);
    emit_stage(ScanEventType::StageStarted, StageKind::ServiceDetection, "service detection started");
    if (cancelled()) {
        return false;
    }
    service_stage_ = std::make_unique<ServiceDetectionStage>(session_.io_engine(), config_, &dependencies_);
    const StageResult stage_result = service_stage_->start(ports);
    if (stage_result.cancelled || cancelled()) {
        return false;
    }
    if (!stage_result.success()) {
        fail(stage_result.message, stage_result.status);
        return false;
    }
    results = service_stage_->results();
    for (const detect::ServiceResult &result : results) {
        session_.emit(ScanEvent{ScanEventType::ServiceDetected, {}, StageKind::ServiceDetection, std::nullopt,
                                result.port.number, result.target, {}});
    }
    emit_stage(ScanEventType::StageCompleted, StageKind::ServiceDetection, "service detection completed");
    return true;
}

bool ScanPipeline::execute_os_detection(
    const core::Target &target,
    const std::vector<portscan::PortResult> &ports,
    const std::vector<detect::ServiceResult> &services,
    std::vector<OSReportEvidence> &results)
{
    if (cancelled()) {
        return false;
    }
    (void)session_.transition(PipelineState::DetectingOS);
    emit_stage(ScanEventType::StageStarted, StageKind::OSDetection, "OS detection started");
    if (cancelled()) {
        return false;
    }
    for (const core::Host &host : target.resolved_hosts) {
        if (cancelled()) {
            return false;
        }
        const auto port_begin = std::lower_bound(
            ports.begin(), ports.end(), host.address,
            [](const portscan::PortResult &port, const std::string &address) { return port.target < address; });
        const auto port_end = std::upper_bound(
            port_begin, ports.end(), host.address,
            [](const std::string &address, const portscan::PortResult &port) { return address < port.target; });
        std::vector<portscan::PortResult> host_ports;
        host_ports.reserve(static_cast<std::size_t>(std::distance(port_begin, port_end)));
        for (auto iterator = port_begin; iterator != port_end; ++iterator) {
            if (iterator->port.protocol == portscan::Protocol::Tcp) {
                host_ports.push_back(*iterator);
            }
        }
        const auto service_begin = std::lower_bound(
            services.begin(), services.end(), host.address,
            [](const detect::ServiceResult &service, const std::string &address) { return service.target < address; });
        const auto service_end = std::upper_bound(
            service_begin, services.end(), host.address,
            [](const std::string &address, const detect::ServiceResult &service) { return address < service.target; });
        std::vector<detect::ServiceResult> host_services;
        host_services.reserve(static_cast<std::size_t>(std::distance(service_begin, service_end)));
        host_services.insert(host_services.end(), service_begin, service_end);
        core::Target one_host{host.address, {host}};
        os_stage_ = std::make_unique<OSDetectionStage>(session_.io_engine(), config_, one_host, &dependencies_);
        const StageResult stage_result = os_stage_->start(host_ports, host_services);
        if (stage_result.cancelled || cancelled()) {
            return false;
        }
        if (!stage_result.success()) {
            fail(stage_result.message, stage_result.status);
            return false;
        }
        OSReportEvidence evidence{host.address, os_stage_->matches(), os_stage_->detection_result()};
        results.push_back(std::move(evidence));
        session_.emit(ScanEvent{ScanEventType::OSDetectionCompleted, {}, StageKind::OSDetection, std::nullopt,
                                std::nullopt, host.address, {}});
        if (os_stage_->unavailable()) {
            warnings_.push_back("OS detection unavailable for " + host.address);
        }
    }
    emit_stage(ScanEventType::StageCompleted, StageKind::OSDetection, "OS detection completed");
    return true;
}

bool ScanPipeline::serialize_report(std::ostream &output)
{
    session_.finish_clock();
    output::ScanReport built = ScanReportBuilder::build(
        config_, active_target_, discovery_results_, port_results_, service_results_, os_results_, timing_metrics_,
        session_.started_at(), session_.finished_at(), warnings_, errors_);
    const output::ScanSummary summary = output::calculate_summary(built);
    ScanCounters &counters = session_.counters();
    counters.hosts_total = summary.hosts;
    counters.hosts_up = summary.hosts_up;
    counters.hosts_down = summary.hosts_down;
    counters.hosts_unknown = summary.hosts_unknown;
    counters.ports_scanned = summary.ports_scanned;
    counters.ports_open = summary.open_ports;
    counters.ports_closed = summary.closed_ports;
    counters.ports_filtered = summary.filtered_ports;
    counters.services_detected = summary.services_detected;
    counters.os_matches = summary.os_matches;
    if (timing_metrics_.has_value()) {
        counters.probes_sent = timing_metrics_->total_submitted;
        counters.probes_completed = timing_metrics_->completed;
        counters.probes_timed_out = timing_metrics_->timed_out;
        counters.peak_pending = timing_metrics_->maximum_observed_parallelism;
    }
    session_.set_report(built);
    if (!config_.output_file.has_value()) {
        const output::OutputStatus status = output::OutputManager::write(config_.output_format, built, output, config_.output_context);
        if (status != output::OutputStatus::Ok) {
            fail(std::string("output serialization failed: ") + output::output_status_name(status),
                 status == output::OutputStatus::IoError ? core::StatusCode::IoError : core::StatusCode::InternalError);
            return false;
        }
        return true;
    }

    std::ostringstream serialized;
    output::OutputContext file_context = config_.output_context;
    file_context.terminal = {};
    const output::OutputStatus status = output::OutputManager::write(config_.output_format, built, serialized, file_context);
    if (status != output::OutputStatus::Ok) {
        fail(std::string("output serialization failed: ") + output::output_status_name(status),
             status == output::OutputStatus::IoError ? core::StatusCode::IoError : core::StatusCode::InternalError);
        return false;
    }
    if (!serialized.good() || !replace_output_file(*config_.output_file, serialized.str())) {
        fail("unable to atomically replace output file", core::StatusCode::IoError);
        return false;
    }
    return true;
}

void ScanPipeline::cancel_active() noexcept
{
    if (discovery_stage_ != nullptr) {
        discovery_stage_->cancel();
    }
    if (port_stage_ != nullptr) {
        port_stage_->cancel();
    }
    if (udp_stage_ != nullptr) {
        udp_stage_->cancel();
    }
    if (service_stage_ != nullptr) {
        service_stage_->cancel();
    }
    if (os_stage_ != nullptr) {
        os_stage_->cancel();
    }
    session_.io_engine().stop();
}

core::StatusCode ScanPipeline::run(std::ostream &output)
{
    if (session_.terminal() && !session_.cancelled()) {
        return final_status_ == core::StatusCode::Ok ? core::StatusCode::InvalidArgument : final_status_;
    }
    active_target_ = aggregate_target();
    if (config_.transport == ScanTransport::Linux && !config_.interface_name.has_value()) {
        const net::InterfaceResult selected = net::select_interface_for_target(active_target_);
        if (!selected.success()) {
            fail("raw interface selection failed: " + selected.message, selected.status == net::InterfaceStatus::RoutingUnavailable
                                                                            ? core::StatusCode::PermissionDenied
                                                                            : core::StatusCode::NotFound);
            (void)serialize_report(output);
            return final_status_;
        }
        config_.interface_name = selected.interface.name;
    }
    if (session_.cancelled()) {
        (void)serialize_report(output);
        return core::StatusCode::Ok;
    }
    const core::StatusCode config_status = config_.validate();
    if (config_status != core::StatusCode::Ok) {
        fail("invalid scan configuration", config_status);
        return final_status_;
    }
    if (session_.io_engine().initialization_status() != core::StatusCode::Ok) {
        fail("unable to initialize shared IOEngine", session_.io_engine().initialization_status());
        return final_status_;
    }
    (void)session_.transition(PipelineState::Initializing);
    session_.counters().hosts_total = active_target_.resolved_hosts.size();
    session_.emit(ScanEvent{ScanEventType::ScanStarted, {}, std::nullopt, active_target_, std::nullopt,
                            "scan started", {}});

    if (config_.discovery_enabled) {
        if (!execute_discovery(active_target_, discovery_results_)) {
            if (cancelled()) {
                (void)serialize_report(output);
                return core::StatusCode::Ok;
            }
            return final_status_;
        }
    }
    core::Target port_target = config_.discovery_enabled ? only_up_hosts(active_target_, *discovery_stage_) : active_target_;
    if (config_.port_scan_enabled && !execute_port_scan(port_target, port_results_, timing_metrics_)) {
        if (cancelled()) {
            (void)serialize_report(output);
            return core::StatusCode::Ok;
        }
        return final_status_;
    }
    if (config_.udp_enabled && !execute_udp_scan(port_target, udp_results_, timing_metrics_)) {
        if (cancelled()) {
            (void)serialize_report(output);
            return core::StatusCode::Ok;
        }
        return final_status_;
    }
    port_results_.insert(port_results_.end(), udp_results_.begin(), udp_results_.end());
    std::sort(port_results_.begin(), port_results_.end(), [](const portscan::PortResult &left,
                                                             const portscan::PortResult &right) {
        if (left.target != right.target) {
            return left.target < right.target;
        }
        if (left.port.number != right.port.number) {
            return left.port.number < right.port.number;
        }
        return left.port.protocol < right.port.protocol;
    });
    if (config_.service_detection_enabled && !execute_service_detection(port_results_, service_results_)) {
        if (cancelled()) {
            (void)serialize_report(output);
            return core::StatusCode::Ok;
        }
        return final_status_;
    }
    if (config_.os_detection_enabled && !execute_os_detection(active_target_, port_results_, service_results_, os_results_)) {
        if (cancelled()) {
            (void)serialize_report(output);
            return core::StatusCode::Ok;
        }
        return final_status_;
    }
    if (cancelled()) {
        (void)serialize_report(output);
        return core::StatusCode::Ok;
    }
    (void)session_.transition(PipelineState::Serializing);
    emit_stage(ScanEventType::StageStarted, StageKind::Output, "serialization started");
    if (!serialize_report(output)) {
        return final_status_;
    }
    emit_stage(ScanEventType::StageCompleted, StageKind::Output, "serialization completed");
    (void)session_.transition(PipelineState::Completed);
    final_status_ = core::StatusCode::Ok;
    session_.emit(ScanEvent{ScanEventType::ScanCompleted, {}, std::nullopt, active_target_, std::nullopt,
                            "scan completed", {}});
    return final_status_;
}

void ScanPipeline::cancel() noexcept { session_.cancel(); }

} // namespace skan::orchestrator
