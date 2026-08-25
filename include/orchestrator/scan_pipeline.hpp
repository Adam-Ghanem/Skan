#ifndef SKAN_ORCHESTRATOR_SCAN_PIPELINE_HPP
#define SKAN_ORCHESTRATOR_SCAN_PIPELINE_HPP

#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

#include "orchestrator/scan_report_builder.hpp"
#include "orchestrator/scan_session.hpp"
#include "orchestrator/scan_stage.hpp"

namespace skan::orchestrator {

class ScanPipeline final {
public:
    explicit ScanPipeline(ScanConfig config, ScanEventSink sink = {}, ScanStageDependencies dependencies = {});
    ~ScanPipeline();

    ScanPipeline(const ScanPipeline &) = delete;
    ScanPipeline &operator=(const ScanPipeline &) = delete;

    core::StatusCode run(std::ostream &output);
    void cancel() noexcept;

    const ScanConfig &config() const noexcept;
    const ScanSession &session() const noexcept;
    ScanSession &session() noexcept;
    PipelineState state() const noexcept;
    const std::optional<output::ScanReport> &report() const noexcept;

private:
    core::Target aggregate_target() const;
    bool execute_discovery(const core::Target &target, std::vector<discovery::DiscoveryResult> &results);
    bool execute_port_scan(
        const core::Target &target,
        std::vector<portscan::PortResult> &results,
        std::optional<scanengine::ScanMetrics> &metrics);
    bool execute_service_detection(
        const std::vector<portscan::PortResult> &ports,
        std::vector<detect::ServiceResult> &results);
    bool execute_os_detection(
        const core::Target &target,
        const std::vector<portscan::PortResult> &ports,
        const std::vector<detect::ServiceResult> &services,
        std::vector<OSReportEvidence> &results);
    bool serialize_report(std::ostream &output);
    void cancel_active() noexcept;
    void fail(std::string message, core::StatusCode status);
    void emit_stage(ScanEventType type, StageKind stage, std::string message);
    bool cancelled() const noexcept;

    ScanConfig config_;
    ScanStageDependencies dependencies_;
    ScanSession session_;
    std::unique_ptr<DiscoveryStage> discovery_stage_;
    std::unique_ptr<PortScanStage> port_stage_;
    std::unique_ptr<ServiceDetectionStage> service_stage_;
    std::unique_ptr<OSDetectionStage> os_stage_;
    std::vector<discovery::DiscoveryResult> discovery_results_;
    std::vector<portscan::PortResult> port_results_;
    std::vector<detect::ServiceResult> service_results_;
    std::vector<OSReportEvidence> os_results_;
    std::vector<std::string> warnings_;
    std::vector<std::string> errors_;
    std::optional<scanengine::ScanMetrics> timing_metrics_;
    core::Target active_target_;
    core::StatusCode final_status_{core::StatusCode::Ok};
};

} // namespace skan::orchestrator

#endif // SKAN_ORCHESTRATOR_SCAN_PIPELINE_HPP
