#ifndef SKAN_ORCHESTRATOR_SCAN_STAGE_HPP
#define SKAN_ORCHESTRATOR_SCAN_STAGE_HPP

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "detect/service_detector.hpp"
#include "discovery/discovery.hpp"
#include "orchestrator/scan_config.hpp"
#include "osdetect/os_detector.hpp"
#include "portscan/port_scheduler.hpp"
#include "net/linux_discovery_transport.hpp"
#include "net/network_scan_transport.hpp"
#include "scanengine/scan_metrics.hpp"

namespace skan::orchestrator {

class ScanSession;

struct ScanStageDependencies final {
    std::function<std::unique_ptr<discovery::DiscoveryTransport>(io::IOEngine &, const ScanConfig &)> discovery_transport;
    std::function<std::unique_ptr<portscan::PortScanTransport>(io::IOEngine &, const ScanConfig &)> port_transport;
    std::function<std::unique_ptr<detect::ServiceTransport>(io::IOEngine &, const ScanConfig &)> service_transport;
    std::function<std::unique_ptr<osdetect::OSProbeTransport>(io::IOEngine &, const ScanConfig &)> os_transport;
    std::function<void(discovery::Discovery &)> after_discovery_submit;
    std::function<void(portscan::PortScanScheduler &)> after_port_submit;
    std::function<void(detect::ServiceDetector &)> after_service_submit;
    std::function<void(osdetect::OSDetector &)> after_os_submit;
};

struct StageResult final {
    core::StatusCode status{core::StatusCode::Ok};
    bool completed{false};
    bool cancelled{false};
    std::string message;

    bool success() const noexcept
    {
        return status == core::StatusCode::Ok && completed && !cancelled;
    }
};

class ScanStageRunner {
public:
    virtual ~ScanStageRunner() = default;
    virtual StageKind kind() const noexcept = 0;
    virtual StageResult start() = 0;
    virtual void cancel() noexcept = 0;
    virtual bool completed() const noexcept = 0;
    virtual const StageResult &result() const noexcept = 0;
};

class DiscoveryStage final : public ScanStageRunner {
public:
    DiscoveryStage(io::IOEngine &engine, const ScanConfig &config, core::Target target,
                   const ScanStageDependencies *dependencies = nullptr);
    ~DiscoveryStage() override;

    StageKind kind() const noexcept override;
    StageResult start() override;
    void cancel() noexcept override;
    bool completed() const noexcept override;
    const StageResult &result() const noexcept override;

    const std::vector<discovery::DiscoveryResult> &results() const noexcept;
    discovery::HostState host_state(const std::string &address) const noexcept;

private:
    io::IOEngine &engine_;
    const ScanConfig &config_;
    core::Target target_;
    const ScanStageDependencies *dependencies_{nullptr};
    std::unique_ptr<discovery::DiscoveryTransport> transport_;
    std::unique_ptr<discovery::Discovery> discovery_;
    net::LinuxDiscoveryTransport *linux_transport_{nullptr};
    std::vector<discovery::DiscoveryResult> results_;
    StageResult result_;
    bool cancelled_{false};
};

class PortScanStage final : public ScanStageRunner {
public:
    PortScanStage(io::IOEngine &engine, const ScanConfig &config, core::Target target,
                  const ScanStageDependencies *dependencies = nullptr);
    ~PortScanStage() override;

    StageKind kind() const noexcept override;
    StageResult start() override;
    void cancel() noexcept override;
    bool completed() const noexcept override;
    const StageResult &result() const noexcept override;

    const std::vector<portscan::PortResult> &results() const noexcept;
    const scanengine::ScanMetrics *timing_metrics() const noexcept;

private:
    io::IOEngine &engine_;
    const ScanConfig &config_;
    core::Target target_;
    const ScanStageDependencies *dependencies_{nullptr};
    std::vector<portscan::Port> configured_ports_;
    std::unique_ptr<portscan::PortScanTransport> transport_;
    std::unique_ptr<portscan::PortScanScheduler> scheduler_;
    std::vector<portscan::PortResult> results_;
    StageResult result_;
    bool cancelled_{false};
};

class ServiceDetectionStage final : public ScanStageRunner {
public:
    ServiceDetectionStage(io::IOEngine &engine, const ScanConfig &config,
                           const ScanStageDependencies *dependencies = nullptr);
    ~ServiceDetectionStage() override;

    StageKind kind() const noexcept override;
    StageResult start(const std::vector<portscan::PortResult> &port_results);
    StageResult start() override;
    void cancel() noexcept override;
    bool completed() const noexcept override;
    const StageResult &result() const noexcept override;

    const std::vector<detect::ServiceResult> &results() const noexcept;

private:
    io::IOEngine &engine_;
    const ScanConfig &config_;
    const ScanStageDependencies *dependencies_{nullptr};
    std::unique_ptr<detect::ServiceTransport> transport_;
    std::unique_ptr<detect::ServiceDetector> detector_;
    std::vector<portscan::PortResult> input_results_;
    std::vector<detect::ServiceResult> results_;
    StageResult result_;
    bool cancelled_{false};
};

class OSDetectionStage final : public ScanStageRunner {
public:
    OSDetectionStage(io::IOEngine &engine, const ScanConfig &config, core::Target target,
                      const ScanStageDependencies *dependencies = nullptr);
    ~OSDetectionStage() override;

    StageKind kind() const noexcept override;
    StageResult start(
        const std::vector<portscan::PortResult> &port_results,
        const std::vector<detect::ServiceResult> &service_results);
    StageResult start() override;
    void cancel() noexcept override;
    bool completed() const noexcept override;
    const StageResult &result() const noexcept override;

    const std::vector<osdetect::OSMatchResult> &matches() const noexcept;
    bool unavailable() const noexcept;

private:
    io::IOEngine &engine_;
    const ScanConfig &config_;
    core::Target target_;
    const ScanStageDependencies *dependencies_{nullptr};
    std::unique_ptr<osdetect::OSProbeTransport> transport_;
    std::unique_ptr<osdetect::OSDetector> detector_;
    std::vector<osdetect::OSMatchResult> matches_;
    StageResult result_;
    bool unavailable_{true};
    bool cancelled_{false};
};

} // namespace skan::orchestrator

#endif // SKAN_ORCHESTRATOR_SCAN_STAGE_HPP
