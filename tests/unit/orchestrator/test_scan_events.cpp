#include <cassert>
#include <vector>

#include "orchestrator/scan_events.hpp"
#include "orchestrator/scan_session.hpp"

int main()
{
    assert(std::string_view{skan::orchestrator::scan_event_type_name(skan::orchestrator::ScanEventType::ScanStarted)} == "scan-started");
    assert(std::string_view{skan::orchestrator::pipeline_state_name(skan::orchestrator::PipelineState::Completed)} == "completed");
    std::vector<skan::orchestrator::ScanEventType> seen;
    skan::orchestrator::ScanSession session("events", [&](const skan::orchestrator::ScanEvent &event) {
        seen.push_back(event.type);
    });
    session.emit({skan::orchestrator::ScanEventType::ScanStarted, {}, std::nullopt, std::nullopt, std::nullopt, {}, {}});
    assert(seen.size() == 1U);
    assert(session.transition(skan::orchestrator::PipelineState::Initializing) == skan::core::StatusCode::Ok);
    assert(session.transition(skan::orchestrator::PipelineState::Serializing) == skan::core::StatusCode::Ok);
    session.cancel();
    session.cancel();
    assert(seen.size() == 2U);
    assert(seen.back() == skan::orchestrator::ScanEventType::ScanCancelled);
    return 0;
}
