#include "orchestrator/scan_orchestrator.hpp"

#include <utility>

namespace skan::orchestrator {

ScanOrchestrator::ScanOrchestrator(ScanConfig config, ScanEventSink sink, ScanStageDependencies dependencies)
    : pipeline_(std::move(config), std::move(sink), std::move(dependencies))
{
}

ScanOrchestrator::~ScanOrchestrator() = default;
core::StatusCode ScanOrchestrator::run(std::ostream &output) { return pipeline_.run(output); }
void ScanOrchestrator::cancel() noexcept { pipeline_.cancel(); }
PipelineState ScanOrchestrator::state() const noexcept { return pipeline_.state(); }
const ScanSession &ScanOrchestrator::session() const noexcept { return pipeline_.session(); }
const std::optional<output::ScanReport> &ScanOrchestrator::report() const noexcept { return pipeline_.report(); }

} // namespace skan::orchestrator
