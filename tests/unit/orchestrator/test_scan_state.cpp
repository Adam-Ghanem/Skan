#include <cassert>

#include "orchestrator/scan_session.hpp"

int main()
{
    skan::orchestrator::ScanSession session("state-test");
    assert(session.state() == skan::orchestrator::PipelineState::Created);
    assert(session.transition(skan::orchestrator::PipelineState::PortScanning) == skan::core::StatusCode::InvalidArgument);
    assert(session.transition(skan::orchestrator::PipelineState::Initializing) == skan::core::StatusCode::Ok);
    assert(session.transition(skan::orchestrator::PipelineState::PortScanning) == skan::core::StatusCode::Ok);
    assert(session.transition(skan::orchestrator::PipelineState::Serializing) == skan::core::StatusCode::Ok);
    assert(session.transition(skan::orchestrator::PipelineState::Completed) == skan::core::StatusCode::Ok);
    assert(session.transition(skan::orchestrator::PipelineState::Created) == skan::core::StatusCode::InvalidArgument);
    session.cancel();
    assert(session.state() == skan::orchestrator::PipelineState::Completed);
    assert(!session.cancelled());
    return 0;
}
