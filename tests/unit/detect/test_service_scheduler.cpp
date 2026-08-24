#include <cassert>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <string>
#include <vector>

#include "detect/service_scheduler.hpp"

namespace {

skan::portscan::PortResult open_port(const char *target, std::uint16_t port)
{
    skan::portscan::PortResult result;
    result.target = target;
    result.port = {port, skan::portscan::Protocol::Tcp};
    result.state = skan::portscan::PortState::Open;
    result.probe = skan::portscan::ScanProbeType::TcpConnect;
    return result;
}

skan::detect::ServiceProbeDatabase demo_database()
{
    skan::core::StatusCode status = skan::core::StatusCode::InternalError;
    const auto database = skan::detect::ServiceProbeDatabase::parse(
        "Probe TCP First rarity=1 ports=80\n"
        "send \"PING\"\n"
        "match type=prefix pattern=\"AAA\" service=first product=First confidence=0.7\n"
        "Probe TCP Second rarity=2\n"
        "send \"PONG\"\n"
        "match type=prefix pattern=\"BBB\" service=second product=Second confidence=0.8\n",
        status);
    assert(status == skan::core::StatusCode::Ok);
    return database;
}

} // namespace

int main()
{
    using namespace skan::detect;

    {
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        ServiceDetectionConfig config{2U, std::chrono::milliseconds{100}, 32U, 2U};
        const ServiceProbeDatabase database = demo_database();
        ServiceScheduler scheduler(
            engine, transport, database, skan::discovery::AuthorizationGate::loopback_only(), config);
        const auto port = open_port("127.0.0.1", 80U);
        assert(scheduler.submit({port}) == skan::core::StatusCode::Ok);
        assert(scheduler.pending_count() == 1U);
        assert(transport.submissions().front().probe_name == "First");
        const auto first = transport.submissions().front();
        transport.deliver({first.id, first.target, ServiceResponseKind::Data, 0, {'X', 'X'}, false,
                           DetectionClock::now()});
        assert(scheduler.pending_count() == 1U);
        transport.deliver({first.id, first.target, ServiceResponseKind::Closed, 0, {}, false,
                           DetectionClock::now()});
        assert(scheduler.results().empty());
        assert(transport.submissions().size() == 2U);
        const auto second = transport.submissions().back();
        transport.deliver({second.id, second.target, ServiceResponseKind::Data, 0, {'B'}, false,
                           DetectionClock::now()});
        assert(scheduler.pending_count() == 1U);
        transport.deliver({second.id, second.target, ServiceResponseKind::Data, 0, {'B', 'B'}, false,
                           DetectionClock::now()});
        assert(scheduler.complete());
        assert(scheduler.results().size() == 1U);
        assert(scheduler.results().front().state == DetectionState::Detected);
        assert(scheduler.results().front().service == "second");
        transport.deliver({second.id, second.target, ServiceResponseKind::Data, 0, {'B', 'B', 'B'}, false,
                           DetectionClock::now()});
        assert(scheduler.results().size() == 1U);
    }

    {
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        ServiceDetectionConfig config{1U, std::chrono::milliseconds{2}, 32U, 1U};
        const ServiceProbeDatabase database = ServiceProbeDatabase::built_in();
        ServiceScheduler scheduler(
            engine, transport, database, skan::discovery::AuthorizationGate::loopback_only(), config);
        assert(scheduler.submit({open_port("127.0.0.1", 80U), open_port("127.0.0.1", 22U)}) ==
               skan::core::StatusCode::Ok);
        assert(scheduler.pending_count() == 1U);
        assert(scheduler.queued_count() == 1U);
        assert(scheduler.run() == skan::core::StatusCode::Ok);
        assert(scheduler.complete());
        assert(scheduler.results().size() == 2U);
        assert(scheduler.results()[0].state == DetectionState::Timeout);
        assert(scheduler.results()[1].state == DetectionState::Timeout);
    }

    {
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        ServiceDetectionConfig config{1U, std::chrono::milliseconds{100}, 2U, 1U};
        const ServiceProbeDatabase database = demo_database();
        ServiceScheduler scheduler(
            engine, transport, database, skan::discovery::AuthorizationGate::loopback_only(), config);
        assert(scheduler.submit({open_port("127.0.0.1", 80U)}) == skan::core::StatusCode::Ok);
        const auto submission = transport.submissions().front();
        transport.deliver({submission.id, submission.target, ServiceResponseKind::Data,
                           0, {'A', 'B', 'C'}, false, DetectionClock::now()});
        assert(scheduler.complete());
        assert(scheduler.results().size() == 1U);
        assert(scheduler.results().front().state == DetectionState::ResponseTooLarge);
        assert(scheduler.results().front().error == DetectionError::ResponseTooLarge);
    }

    {
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        const ServiceProbeDatabase database = ServiceProbeDatabase::built_in();
        ServiceScheduler scheduler(
            engine, transport, database, skan::discovery::AuthorizationGate::loopback_only(), {});
        assert(scheduler.submit({open_port("192.0.2.1", 80U)}) == skan::core::StatusCode::PermissionDenied);
        assert(scheduler.results().size() == 1U);
        assert(scheduler.results().front().state == DetectionState::Unauthorized);
        assert(transport.submissions().empty());
    }

    {
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        const ServiceProbeDatabase database = ServiceProbeDatabase::built_in();
        ServiceScheduler scheduler(
            engine, transport, database, skan::discovery::AuthorizationGate::loopback_only(), {});
        auto closed = open_port("127.0.0.1", 80U);
        closed.state = skan::portscan::PortState::Closed;
        assert(scheduler.submit({closed}) == skan::core::StatusCode::Ok);
        assert(scheduler.complete());
        assert(scheduler.results().empty());
    }
    return 0;
}
