#ifndef SKAN_ORCHESTRATOR_SCAN_ORCHESTRATOR_HPP
#define SKAN_ORCHESTRATOR_SCAN_ORCHESTRATOR_HPP

#include <optional>
#include <ostream>

#include "orchestrator/scan_pipeline.hpp"

namespace skan::orchestrator {

class ScanOrchestrator final {
public:
    explicit ScanOrchestrator(ScanConfig config, ScanEventSink sink = {}, ScanStageDependencies dependencies = {});
    ~ScanOrchestrator();

    ScanOrchestrator(const ScanOrchestrator &) = delete;
    ScanOrchestrator &operator=(const ScanOrchestrator &) = delete;

    core::StatusCode run(std::ostream &output);
    void cancel() noexcept;

    PipelineState state() const noexcept;
    const ScanSession &session() const noexcept;
    const std::optional<output::ScanReport> &report() const noexcept;

private:
    ScanPipeline pipeline_;
};

} // namespace skan::orchestrator

#endif // SKAN_ORCHESTRATOR_SCAN_ORCHESTRATOR_HPP
