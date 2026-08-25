#include <cassert>
#include <sstream>

#include "orchestrator/scan_session.hpp"

int main()
{
    std::size_t cancel_calls = 0U;
    std::size_t cancel_events = 0U;
    skan::orchestrator::ScanSession session("session-test", [&](const skan::orchestrator::ScanEvent &event) {
        if (event.type == skan::orchestrator::ScanEventType::ScanCancelled) {
            ++cancel_events;
        }
    });
    session.set_cancel_callback([&cancel_calls]() { ++cancel_calls; });
    session.counters().hosts_total = 3U;
    session.counters().peak_pending = 2U;
    assert(session.counters().hosts_total == 3U);
    skan::output::ScanReport report;
    report.target_spec = "127.0.0.1";
    session.set_report(report);
    assert(session.report().has_value());
    session.cancel();
    session.cancel();
    assert(session.cancelled());
    assert(session.state() == skan::orchestrator::PipelineState::Cancelled);
    assert(cancel_calls == 1U);
    assert(cancel_events == 1U);
    assert(session.io_engine().initialization_status() == skan::core::StatusCode::Ok);
    return 0;
}
