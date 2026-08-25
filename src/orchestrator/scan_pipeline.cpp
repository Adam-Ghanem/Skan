#include "orchestrator/scan_pipeline.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <utility>

#include "output/output_manager.hpp"

namespace skan::orchestrator {
namespace {

core::Target aggregate_targets(const std::vector<core::Target> &targets)
{
    core::Target aggregate;
    for (const core::Target &target : targets) {
        if (!aggregate.original_specification.empty()) {
            aggregate.original_specification += ";";
        }
        aggregate.original_specification += target.original_specification;
        for (const core::Host &host : target.resolved_hosts) {
            const auto found = std::find_if(aggregate.resolved_hosts.begin(), aggregate.resolved_hosts.end(),
                                            [&](const core::Host &existing) { return existing.address == host.address; });
            if (found == aggregate.resolved_hosts.end()) {
                aggregate.resolved_hosts.push_back(host);
            }
        }
    }
    std::sort(aggregate.resolved_hosts.begin(), aggregate.resolved_hosts.end(),
              [](const core::Host &left, const core::Host &right) {
                  const auto left_address = discovery::parse_ipv4_address(left.address);
                  const auto right_address = discovery::parse_ipv4_address(right.address);
                  if (left_address.has_value() && right_address.has_value()) {
                      return *left_address < *right_address;
                  }
                  return left.address < right.address;
              });
    return aggregate;
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
        std::vector<portscan::PortResult> host_ports;
        std::vector<detect::ServiceResult> host_services;
        for (const portscan::PortResult &port : ports) {
            if (port.target == host.address && port.port.protocol == portscan::Protocol::Tcp) {
                host_ports.push_back(port);
            }
        }
        for (const detect::ServiceResult &service : services) {
            if (service.target == host.address) {
                host_services.push_back(service);
            }
        }
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
    std::ofstream file;
    std::ostream *destination = &output;
    if (config_.output_file.has_value()) {
        file.open(*config_.output_file, std::ios::out | std::ios::trunc);
        if (!file.is_open()) {
            fail("unable to open output file", core::StatusCode::IoError);
            return false;
        }
        destination = &file;
    }
    const output::OutputStatus status = output::OutputManager::write(config_.output_format, built, *destination);
    if (status != output::OutputStatus::Ok) {
        fail(std::string("output serialization failed: ") + output::output_status_name(status),
             status == output::OutputStatus::IoError ? core::StatusCode::IoError : core::StatusCode::InternalError);
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
    if (config_.service_detection_enabled && !execute_service_detection(port_results_, service_results_)) {
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
