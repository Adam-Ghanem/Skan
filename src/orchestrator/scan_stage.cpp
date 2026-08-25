#include "orchestrator/scan_stage.hpp"

#include <algorithm>
#include <utility>

#include "db/os_db.hpp"
#include "detect/service_db.hpp"
#include "detect/service_probe.hpp"
#include "discovery/discovery_types.hpp"
#include "net/linux_discovery_transport.hpp"
#include "net/linux_os_probe_transport.hpp"
#include "net/network_scan_transport.hpp"
#include "net/udp_network_scan_transport.hpp"
#include "portscan/tcp_connect.hpp"

namespace skan::orchestrator {
namespace {

bool has_ipv6_hosts(const core::Target &target) noexcept
{
    return std::any_of(target.resolved_hosts.begin(), target.resolved_hosts.end(), [](const core::Host &host) {
        return host.ip_address.is_ipv6() || host.address.find(':') != std::string::npos;
    });
}

StageResult stage_success()
{
    return {core::StatusCode::Ok, true, false, {}};
}

StageResult stage_failure(core::StatusCode status, std::string message)
{
    return {status, false, false, std::move(message)};
}

StageResult stage_cancelled()
{
    return {core::StatusCode::Ok, false, true, "stage cancelled"};
}

} // namespace

DiscoveryStage::DiscoveryStage(io::IOEngine &engine, const ScanConfig &config, core::Target target,
                                 const ScanStageDependencies *dependencies)
    : engine_(engine), config_(config), target_(std::move(target)), dependencies_(dependencies)
{
}

DiscoveryStage::~DiscoveryStage() = default;
StageKind DiscoveryStage::kind() const noexcept { return StageKind::Discovery; }

StageResult DiscoveryStage::start()
{
    if (cancelled_) {
        result_ = stage_cancelled();
        return result_;
    }
    discovery::DiscoveryConfig discovery_config;
    discovery_config.timeout = config_.timeout;
    discovery_config.max_outstanding = config_.max_parallelism;

    if (dependencies_ != nullptr && dependencies_->discovery_transport) {
        transport_ = dependencies_->discovery_transport(engine_, config_);
    } else if (config_.transport == ScanTransport::Linux) {
        if (has_ipv6_hosts(target_)) {
            result_ = stage_failure(core::StatusCode::PermissionDenied, "IPv6 Linux discovery is unavailable; no fallback transport is used");
            return result_;
        }
        if (!config_.interface_name.has_value()) {
            result_ = stage_failure(core::StatusCode::InvalidArgument, "Linux discovery requires an interface");
            return result_;
        }
        auto linux = std::make_unique<net::LinuxDiscoveryTransport>(engine_, *config_.interface_name);
        const net::NetworkScanResult opened = linux->open();
        if (!opened.success()) {
            result_ = stage_failure(core::StatusCode::PermissionDenied, opened.message);
            return result_;
        }
        linux_transport_ = linux.get();
        transport_ = std::move(linux);
    } else {
        transport_ = std::make_unique<discovery::RecordingTransport>();
    }
    if (transport_ == nullptr) {
        result_ = stage_failure(core::StatusCode::InternalError, "discovery transport factory returned null");
        return result_;
    }

    discovery_ = std::make_unique<discovery::Discovery>(engine_, discovery_config, *transport_);
    if (linux_transport_ != nullptr) {
        linux_transport_->set_response_handler([this](const discovery::DiscoveryResponse &response) {
            if (!cancelled_ && discovery_ != nullptr) {
                (void)discovery_->receive(response);
            }
        });
    }
    const core::StatusCode submitted = discovery_->submit(target_);
    if (submitted != core::StatusCode::Ok) {
        result_ = stage_failure(submitted, "discovery submission failed");
        return result_;
    }
    if (dependencies_ != nullptr && dependencies_->after_discovery_submit) {
        dependencies_->after_discovery_submit(*discovery_);
    }
    const core::StatusCode run_status = discovery_->run();
    if (cancelled_) {
        result_ = stage_cancelled();
        return result_;
    }
    if (run_status != core::StatusCode::Ok) {
        result_ = stage_failure(run_status, "discovery stage failed");
        return result_;
    }
    results_ = discovery_->results();
    result_ = stage_success();
    return result_;
}

void DiscoveryStage::cancel() noexcept
{
    cancelled_ = true;
    if (discovery_ != nullptr) {
        discovery_->stop();
    }
    discovery_.reset();
    transport_.reset();
    linux_transport_ = nullptr;
    result_ = stage_cancelled();
}

bool DiscoveryStage::completed() const noexcept { return result_.completed; }
const StageResult &DiscoveryStage::result() const noexcept { return result_; }
const std::vector<discovery::DiscoveryResult> &DiscoveryStage::results() const noexcept { return results_; }

discovery::HostState DiscoveryStage::host_state(const std::string &address) const noexcept
{
    if (discovery_ != nullptr) {
        return discovery_->host_state(address);
    }
    for (const discovery::DiscoveryResult &result : results_) {
        if (result.target == address && result.state == discovery::HostState::Up) {
            return discovery::HostState::Up;
        }
    }
    return discovery::HostState::Unknown;
}

PortScanStage::PortScanStage(io::IOEngine &engine, const ScanConfig &config, core::Target target,
                               const ScanStageDependencies *dependencies)
    : engine_(engine), config_(config), target_(std::move(target)), dependencies_(dependencies)
{
}

PortScanStage::~PortScanStage() = default;
StageKind PortScanStage::kind() const noexcept { return StageKind::PortScan; }

StageResult PortScanStage::start()
{
    if (cancelled_) {
        result_ = stage_cancelled();
        return result_;
    }
    portscan::PortScanConfig scan_config;
    scan_config.method = config_.port_method;
    scan_config.timeout = config_.timeout;
    scan_config.max_outstanding = config_.max_parallelism;
    scan_config.adaptive_timing = config_.adaptive_timing;
    scan_config.timing_profile = config_.timing_profile;
    scan_config.timing_profile.min_parallelism = config_.min_parallelism;
    scan_config.timing_profile.max_parallelism = config_.max_parallelism;
    scan_config.timing_profile.max_retries = config_.retries;
    configured_ports_.clear();
    for (const std::uint16_t port : config_.ports) {
        configured_ports_.push_back(portscan::Port{port, portscan::Protocol::Tcp});
    }

    if (dependencies_ != nullptr && dependencies_->port_transport) {
        transport_ = dependencies_->port_transport(engine_, config_);
    } else if (config_.transport == ScanTransport::Offline) {
        transport_ = std::make_unique<portscan::RecordingPortScanTransport>();
    } else if (config_.transport == ScanTransport::Connect) {
        transport_ = std::make_unique<portscan::TcpConnectTransport>(engine_);
    } else {
        if (!config_.interface_name.has_value()) {
            result_ = stage_failure(core::StatusCode::InvalidArgument, "Linux port scan requires an interface");
            return result_;
        }
        net::NetworkScanConfig linux_config;
        linux_config.interface_name = *config_.interface_name;
        auto linux = std::make_unique<net::LinuxNetworkScanTransport>(engine_, std::move(linux_config));
        const net::NetworkScanResult opened = linux->open();
        if (!opened.success()) {
            result_ = stage_failure(core::StatusCode::PermissionDenied, opened.message);
            return result_;
        }
        transport_ = std::move(linux);
    }
    if (transport_ == nullptr) {
        result_ = stage_failure(core::StatusCode::InternalError, "port transport factory returned null");
        return result_;
    }
    scheduler_ = std::make_unique<portscan::PortScanScheduler>(engine_, *transport_, scan_config);
    const core::StatusCode submitted = config_.ports.empty()
                                           ? scheduler_->submit_default(target_)
                                           : scheduler_->submit(target_, configured_ports_);
    if (submitted != core::StatusCode::Ok) {
        result_ = stage_failure(submitted, "port-scan submission failed");
        return result_;
    }
    if (dependencies_ != nullptr && dependencies_->after_port_submit) {
        dependencies_->after_port_submit(*scheduler_);
    }
    const core::StatusCode run_status = scheduler_->run();
    if (cancelled_) {
        result_ = stage_cancelled();
        return result_;
    }
    results_ = scheduler_->results();
    if (run_status != core::StatusCode::Ok) {
        result_ = stage_failure(run_status, "port-scan stage failed");
        return result_;
    }
    result_ = stage_success();
    return result_;
}

void PortScanStage::cancel() noexcept
{
    cancelled_ = true;
    scheduler_.reset();
    transport_.reset();
    result_ = stage_cancelled();
}

bool PortScanStage::completed() const noexcept { return result_.completed; }
const StageResult &PortScanStage::result() const noexcept { return result_; }
const std::vector<portscan::PortResult> &PortScanStage::results() const noexcept { return results_; }
const scanengine::ScanMetrics *PortScanStage::timing_metrics() const noexcept
{
    return scheduler_ != nullptr && scheduler_->timing_controller() != nullptr
               ? &scheduler_->timing_controller()->metrics()
               : nullptr;
}

UdpScanStage::UdpScanStage(io::IOEngine &engine, const ScanConfig &config, core::Target target,
                             const ScanStageDependencies *dependencies)
    : engine_(engine), config_(config), target_(std::move(target)), dependencies_(dependencies)
{
}

UdpScanStage::~UdpScanStage() = default;
StageKind UdpScanStage::kind() const noexcept { return StageKind::UdpScan; }

StageResult UdpScanStage::start()
{
    if (cancelled_) {
        result_ = stage_cancelled();
        return result_;
    }
    portscan::PortScanConfig scan_config;
    scan_config.method = portscan::ScanProbeType::Udp;
    scan_config.timeout = config_.udp_timeout;
    scan_config.max_outstanding = config_.udp_max_outstanding;
    scan_config.retries = config_.udp_retries;
    scan_config.adaptive_timing = config_.adaptive_timing;
    scan_config.timing_profile = config_.timing_profile;
    scan_config.timing_profile.min_parallelism = config_.min_parallelism;
    scan_config.timing_profile.max_parallelism = config_.udp_max_outstanding;
    scan_config.timing_profile.max_retries = config_.udp_retries;
    configured_ports_.clear();
    for (const std::uint16_t port : config_.udp_ports) {
        configured_ports_.push_back(portscan::Port{port, portscan::Protocol::Udp});
    }

    portscan::UDPProbeDatabase database;
    if (config_.udp_probe_db_path.empty()) {
        database = portscan::UDPProbeDatabase::built_in();
    } else {
        core::StatusCode db_status = core::StatusCode::Ok;
        database = portscan::UDPProbeDatabase::load_file(config_.udp_probe_db_path, db_status);
        if (db_status != core::StatusCode::Ok) {
            result_ = stage_failure(db_status, "UDP probe database loading failed");
            return result_;
        }
    }
    if (dependencies_ != nullptr && dependencies_->udp_transport) {
        transport_ = dependencies_->udp_transport(engine_, config_);
    } else if (config_.transport == ScanTransport::Offline) {
        transport_ = std::make_unique<portscan::RecordingUDPTransport>();
    } else if (config_.transport == ScanTransport::Linux) {
        if (!config_.interface_name.has_value()) {
            result_ = stage_failure(core::StatusCode::InvalidArgument, "Linux UDP scan requires an interface");
            return result_;
        }
        auto linux = std::make_unique<net::LinuxUDPScanTransport>(engine_, net::NetworkScanConfig{
            *config_.interface_name, 65535U, true, std::nullopt});
        const net::NetworkScanResult opened = linux->open();
        if (!opened.success()) {
            const core::StatusCode mapped = opened.status == net::NetworkScanStatus::PermissionDenied ||
                                                    opened.status == net::NetworkScanStatus::RoutingUnavailable
                                                 ? core::StatusCode::PermissionDenied
                                                 : opened.status == net::NetworkScanStatus::InterfaceNotFound
                                                       ? core::StatusCode::NotFound
                                                       : core::StatusCode::IoError;
            result_ = stage_failure(mapped, opened.message);
            return result_;
        }
        transport_ = std::move(linux);
    } else {
        result_ = stage_failure(core::StatusCode::InvalidArgument, "UDP scanning does not support connect transport");
        return result_;
    }
    if (transport_ == nullptr) {
        result_ = stage_failure(core::StatusCode::InternalError, "UDP transport factory returned null");
        return result_;
    }
    scheduler_ = std::make_unique<portscan::UDPScheduler>(engine_, *transport_, std::move(database), scan_config);
    const core::StatusCode submitted = config_.udp_ports.empty()
                                           ? scheduler_->submit_default(target_)
                                           : scheduler_->submit(target_, configured_ports_);
    if (submitted != core::StatusCode::Ok) {
        result_ = stage_failure(submitted, "UDP scan submission failed");
        return result_;
    }
    if (dependencies_ != nullptr && dependencies_->after_udp_submit) {
        dependencies_->after_udp_submit(*scheduler_);
    }
    const core::StatusCode run_status = scheduler_->run();
    if (cancelled_) {
        result_ = stage_cancelled();
        return result_;
    }
    results_ = scheduler_->results();
    if (run_status != core::StatusCode::Ok) {
        result_ = stage_failure(run_status, "UDP scan stage failed");
        return result_;
    }
    result_ = stage_success();
    return result_;
}

void UdpScanStage::cancel() noexcept
{
    cancelled_ = true;
    scheduler_.reset();
    transport_.reset();
    result_ = stage_cancelled();
}

bool UdpScanStage::completed() const noexcept { return result_.completed; }
const StageResult &UdpScanStage::result() const noexcept { return result_; }
const std::vector<portscan::PortResult> &UdpScanStage::results() const noexcept { return results_; }
const scanengine::ScanMetrics *UdpScanStage::timing_metrics() const noexcept
{
    return scheduler_ != nullptr && scheduler_->timing_controller() != nullptr
               ? &scheduler_->timing_controller()->metrics()
               : nullptr;
}

ServiceDetectionStage::ServiceDetectionStage(io::IOEngine &engine, const ScanConfig &config,
                                             const ScanStageDependencies *dependencies)
    : engine_(engine), config_(config), dependencies_(dependencies)
{
}

ServiceDetectionStage::~ServiceDetectionStage() = default;
StageKind ServiceDetectionStage::kind() const noexcept { return StageKind::ServiceDetection; }

StageResult ServiceDetectionStage::start(const std::vector<portscan::PortResult> &port_results)
{
    if (cancelled_) {
        result_ = stage_cancelled();
        return result_;
    }
    input_results_ = port_results;
    detect::ServiceDetectionConfig detection_config;
    detection_config.timeout = config_.timeout;
    detection_config.max_outstanding = config_.max_parallelism;
    detection_config.max_response_bytes = config_.max_response_bytes;
    detection_config.max_probes_per_port = config_.max_probes_per_port;
    detection_config.adaptive_timing = config_.adaptive_timing;
    detection_config.timing_profile = config_.timing_profile;
    detection_config.timing_profile.min_parallelism = config_.min_parallelism;
    detection_config.timing_profile.max_parallelism = config_.max_parallelism;
    detection_config.timing_profile.max_retries = config_.retries;
    detect::ServiceProbeDatabase database;
    if (config_.service_db_path.empty()) {
        database = detect::ServiceProbeDatabase::built_in();
    } else {
        core::StatusCode db_status = core::StatusCode::Ok;
        database = detect::ServiceProbeDatabase::load_file(config_.service_db_path, db_status);
        if (db_status != core::StatusCode::Ok) {
            result_ = stage_failure(db_status, "service database loading failed");
            return result_;
        }
    }
    if (dependencies_ != nullptr && dependencies_->service_transport) {
        transport_ = dependencies_->service_transport(engine_, config_);
    } else if (config_.transport == ScanTransport::Offline) {
        transport_ = std::make_unique<detect::RecordingServiceTransport>();
    } else {
        transport_ = std::make_unique<detect::ServiceTcpTransport>(engine_);
    }
    if (transport_ == nullptr) {
        result_ = stage_failure(core::StatusCode::InternalError, "service transport factory returned null");
        return result_;
    }
    detector_ = std::make_unique<detect::ServiceDetector>(engine_, *transport_, detection_config, std::move(database));
    const core::StatusCode submitted = detector_->submit(input_results_);
    if (submitted != core::StatusCode::Ok) {
        result_ = stage_failure(submitted, "service detection submission failed");
        return result_;
    }
    if (dependencies_ != nullptr && dependencies_->after_service_submit) {
        dependencies_->after_service_submit(*detector_);
    }
    const core::StatusCode run_status = detector_->run();
    if (cancelled_) {
        result_ = stage_cancelled();
        return result_;
    }
    results_ = detector_->results();
    if (run_status != core::StatusCode::Ok) {
        result_ = stage_failure(run_status, "service detection stage failed");
        return result_;
    }
    result_ = stage_success();
    return result_;
}

StageResult ServiceDetectionStage::start() { return start(input_results_); }
void ServiceDetectionStage::cancel() noexcept
{
    cancelled_ = true;
    detector_.reset();
    transport_.reset();
    result_ = stage_cancelled();
}
bool ServiceDetectionStage::completed() const noexcept { return result_.completed; }
const StageResult &ServiceDetectionStage::result() const noexcept { return result_; }
const std::vector<detect::ServiceResult> &ServiceDetectionStage::results() const noexcept { return results_; }

OSDetectionStage::OSDetectionStage(io::IOEngine &engine, const ScanConfig &config, core::Target target,
                                           const ScanStageDependencies *dependencies)
    : engine_(engine), config_(config), target_(std::move(target)), dependencies_(dependencies)
{
}

OSDetectionStage::~OSDetectionStage() = default;
StageKind OSDetectionStage::kind() const noexcept { return StageKind::OSDetection; }

StageResult OSDetectionStage::start(
    const std::vector<portscan::PortResult> &port_results,
    const std::vector<detect::ServiceResult> &service_results)
{
    (void)service_results;
    if (cancelled_) {
        result_ = stage_cancelled();
        return result_;
    }
    const bool injected_transport = dependencies_ != nullptr && dependencies_->os_transport;
    osdetect::OSSchedulerConfig os_config;
    os_config.timeout = config_.timeout;
    os_config.max_outstanding = config_.max_parallelism;
    os_config.adaptive_timing = config_.adaptive_timing;
    os_config.timing_profile = config_.timing_profile;
    os_config.timing_profile.max_retries = config_.retries;
    os_config.timing_profile.max_parallelism = config_.max_parallelism;
    os_config.udp_probe_port = 161U;
    if (injected_transport) {
        transport_ = dependencies_->os_transport(engine_, config_);
    } else if (config_.transport == ScanTransport::Offline) {
        transport_ = std::make_unique<osdetect::RecordingOSProbeTransport>();
    } else if (config_.transport == ScanTransport::Linux) {
        if (!config_.interface_name.has_value()) {
            unavailable_ = true;
            result_ = stage_success();
            return result_;
        }
        auto linux = std::make_unique<net::LinuxOSProbeTransport>(
            engine_, net::NetworkScanConfig{*config_.interface_name, 65535U, true, std::nullopt});
        const net::NetworkScanResult opened = linux->open();
        if (!opened.success()) {
            unavailable_ = true;
            osdetect::OSDetectionResult unavailable;
            unavailable.target = target_.original_specification;
            unavailable.state = osdetect::OSDetectionState::Unavailable;
            unavailable.error = opened.status == net::NetworkScanStatus::PermissionDenied ||
                                        opened.status == net::NetworkScanStatus::NotSupported
                                    ? osdetect::OSDetectionError::CapabilityUnavailable
                                    : osdetect::OSDetectionError::TransportFailure;
            detection_result_ = std::move(unavailable);
            result_ = stage_success();
            return result_;
        }
        os_config.source_address = linux->local_source_address();
        transport_ = std::move(linux);
    } else {
        unavailable_ = true;
        osdetect::OSDetectionResult unavailable;
        unavailable.target = target_.original_specification;
        unavailable.state = osdetect::OSDetectionState::Unavailable;
        unavailable.error = osdetect::OSDetectionError::CapabilityUnavailable;
        detection_result_ = std::move(unavailable);
        result_ = stage_success();
        return result_;
    }
    if (transport_ == nullptr) {
        result_ = stage_failure(core::StatusCode::InternalError, "OS transport factory returned null");
        return result_;
    }
    db::OSFingerprintDatabase database;
    if (config_.os_db_path.empty()) {
        database = db::OSFingerprintDatabase::built_in();
    } else {
        core::StatusCode db_status = core::StatusCode::Ok;
        database = db::OSFingerprintDatabase::load_file(config_.os_db_path, db_status);
        if (db_status != core::StatusCode::Ok) {
            result_ = stage_failure(db_status, "OS database loading failed");
            return result_;
        }
    }
    detector_ = std::make_unique<osdetect::OSDetector>(engine_, *transport_, os_config, std::move(database));
    const core::StatusCode submitted = detector_->submit(target_, port_results, service_results);
    if (submitted != core::StatusCode::Ok) {
        result_ = stage_failure(submitted, "OS detection submission failed");
        return result_;
    }
    if (dependencies_ != nullptr && dependencies_->after_os_submit) {
        dependencies_->after_os_submit(*detector_);
    }
    const core::StatusCode run_status = detector_->run();
    if (cancelled_) {
        result_ = stage_cancelled();
        return result_;
    }
    if (detector_->result().has_value()) {
        detection_result_ = detector_->result();
        matches_ = detector_->result()->matches;
        unavailable_ = detector_->result()->state == osdetect::OSDetectionState::Unavailable;
    }
    if (run_status != core::StatusCode::Ok) {
        result_ = stage_failure(run_status, "OS detection stage failed");
        return result_;
    }
    result_ = stage_success();
    return result_;
}

StageResult OSDetectionStage::start() { return start({}, {}); }
void OSDetectionStage::cancel() noexcept
{
    cancelled_ = true;
    if (detector_ != nullptr) {
        detector_->stop();
    }
    detector_.reset();
    transport_.reset();
    result_ = stage_cancelled();
}
bool OSDetectionStage::completed() const noexcept { return result_.completed; }
const StageResult &OSDetectionStage::result() const noexcept { return result_; }
const std::vector<osdetect::OSMatchResult> &OSDetectionStage::matches() const noexcept { return matches_; }
const std::optional<osdetect::OSDetectionResult> &OSDetectionStage::detection_result() const noexcept
{
    return detection_result_;
}
bool OSDetectionStage::unavailable() const noexcept { return unavailable_; }

} // namespace skan::orchestrator
