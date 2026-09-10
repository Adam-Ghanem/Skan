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
        "Probe TCP First rarity=1 ports=80 fallback=Second\n"
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
        skan::core::StatusCode status = skan::core::StatusCode::InternalError;
        const ServiceProbeDatabase database = ServiceProbeDatabase::parse(
            "Probe TCP First rarity=1 timeout=25 ports=80 fallback=Second\n"
            "send \"ONE\"\n"
            "softmatch type=prefix pattern=\"220\" service=banner product=Generic confidence=0.5\n"
            "Probe TCP Second rarity=2\n"
            "send \"TWO\"\n"
            "match type=prefix pattern=\"SSH-\" service=ssh product=SSH confidence=0.9\n",
            status);
        assert(status == skan::core::StatusCode::Ok);
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        ServiceScheduler scheduler(
            engine, transport, database,
            ServiceDetectionConfig{1U, std::chrono::milliseconds{100}, 32U, 2U});
        assert(scheduler.submit({open_port("127.0.0.1", 80U)}) == skan::core::StatusCode::Ok);
        const auto first = transport.submissions().front();
        transport.deliver({first.id, first.target, ServiceResponseKind::Data, 0, {'2', '2', '0'}, false,
                           DetectionClock::now()});
        assert(!scheduler.complete());
        transport.deliver({first.id, first.target, ServiceResponseKind::Closed, 0, {}, false,
                           DetectionClock::now()});
        assert(transport.submissions().size() == 2U);
        const auto second = transport.submissions().back();
        transport.deliver({second.id, second.target, ServiceResponseKind::Closed, 0, {}, false,
                           DetectionClock::now()});
        assert(scheduler.complete());
        assert(scheduler.results().size() == 1U);
        assert(scheduler.results().front().state == DetectionState::Detected);
        assert(scheduler.results().front().service == "banner");
        assert(scheduler.results().front().probe_name == "First");
    }

    {
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        ServiceDetectionConfig config{2U, std::chrono::milliseconds{100}, 32U, 2U};
        const ServiceProbeDatabase database = demo_database();
        ServiceScheduler scheduler(engine, transport, database, config);
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
        skan::core::StatusCode status = skan::core::StatusCode::InternalError;
        const ServiceProbeDatabase database = ServiceProbeDatabase::parse(
            "Probe TCP TLSClientHello rarity=1 priority=100 timeout=100 ports=443 fallback=HTTPGet\n"
            "send \"TLS\"\n"
            "softmatch type=prefix pattern=\"\\x16\\x03\" service=tls product=TLS confidence=0.9\n"
            "Probe TCP HTTPGet rarity=1 priority=95 timeout=100 ports=443\n"
            "send \"GET / HTTP/1.0\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n\"\n"
            "match type=regex pattern=\"^HTTP/([0-9.]+)[\\\\s\\\\S]*Server: ([A-Za-z0-9._-]+)/([0-9A-Za-z._-]+)\" service=http product=\"$2\" version=\"$3\" confidence=0.96\n",
            status);
        assert(status == skan::core::StatusCode::Ok);
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        ServiceScheduler scheduler(
            engine, transport, database,
            ServiceDetectionConfig{1U, std::chrono::milliseconds{100}, 256U, 2U});
        assert(scheduler.submit({open_port("127.0.0.1", 443U)}) == skan::core::StatusCode::Ok);
        assert(transport.submissions().size() == 1U);
        assert(transport.submissions().front().probe_name == "TLSClientHello");
        const auto tls = transport.submissions().front();
        transport.deliver({tls.id, tls.target, ServiceResponseKind::SocketError, ECONNRESET, {}, false,
                           DetectionClock::now()});
        assert(transport.submissions().size() == 2U);
        assert(transport.submissions().back().probe_name == "HTTPGet");
        const auto http = transport.submissions().back();
        const std::string http_response =
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.29\r\nConnection: close\r\n\r\n";
        const std::vector<std::uint8_t> http_bytes(http_response.begin(), http_response.end());
        transport.deliver({http.id, http.target, ServiceResponseKind::Data, 0, http_bytes, false,
                           DetectionClock::now()});
        assert(scheduler.complete());
        assert(scheduler.results().size() == 1U);
        assert(scheduler.results().front().state == DetectionState::Detected);
        assert(scheduler.results().front().service == "http");
        assert(scheduler.results().front().product == "Apache");
        assert(scheduler.results().front().version == "2.4.29");
    }

    {
        skan::core::StatusCode status = skan::core::StatusCode::InternalError;
        const ServiceProbeDatabase database = ServiceProbeDatabase::parse(
            "Probe TCP OnlyProbe rarity=1 priority=100 timeout=100 ports=443\n"
            "send \"ONLY\"\n"
            "match type=prefix pattern=\"OK\" service=only product=Only confidence=0.9\n",
            status);
        assert(status == skan::core::StatusCode::Ok);
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        ServiceScheduler scheduler(
            engine, transport, database,
            ServiceDetectionConfig{1U, std::chrono::milliseconds{100}, 32U, 1U});
        assert(scheduler.submit({open_port("127.0.0.1", 443U)}) == skan::core::StatusCode::Ok);
        assert(transport.submissions().size() == 1U);
        const auto only = transport.submissions().front();
        transport.deliver({only.id, only.target, ServiceResponseKind::SocketError, ECONNRESET, {}, false,
                           DetectionClock::now()});
        assert(scheduler.complete());
        assert(transport.submissions().size() == 1U);
        assert(scheduler.results().size() == 1U);
        assert(scheduler.results().front().state == DetectionState::Error);
        assert(scheduler.results().front().error == DetectionError::TransportFailure);
        assert(scheduler.results().front().probe_name == "OnlyProbe");
    }

    {
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        ServiceDetectionConfig config{2U, std::chrono::milliseconds{100}, 32U, 1U};
        const ServiceProbeDatabase database = demo_database();
        ServiceScheduler scheduler(engine, transport, database, config);
        const auto duplicate = open_port("127.0.0.1", 80U);
        const auto distinct = open_port("127.0.0.2", 80U);
        assert(scheduler.submit({duplicate, duplicate, distinct}) == skan::core::StatusCode::Ok);
        assert(transport.submissions().size() == 2U);
        assert(scheduler.pending_count() == 2U);
        for (const auto &submission : transport.submissions()) {
            transport.deliver({submission.id, submission.target, ServiceResponseKind::Closed, 0, {}, false,
                               DetectionClock::now()});
        }
        assert(scheduler.complete());
        assert(scheduler.results().size() == 2U);
        assert(scheduler.results()[0].target == "127.0.0.1");
        assert(scheduler.results()[1].target == "127.0.0.2");
    }

    {
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        ServiceDetectionConfig config{1U, std::chrono::milliseconds{2}, 32U, 1U};
        const ServiceProbeDatabase database = ServiceProbeDatabase::built_in();
        ServiceScheduler scheduler(engine, transport, database, config);
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
        ServiceScheduler scheduler(engine, transport, database, config);
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
        ServiceDetectionConfig config{1U, std::chrono::milliseconds{100}, 3U, 1U};
        const ServiceProbeDatabase database = demo_database();
        ServiceScheduler scheduler(engine, transport, database, config);
        assert(scheduler.submit({open_port("127.0.0.1", 80U)}) == skan::core::StatusCode::Ok);
        const auto submission = transport.submissions().front();
        transport.deliver({submission.id, submission.target, ServiceResponseKind::Data,
                           0, {'A', 'B'}, false, DetectionClock::now()});
        assert(!scheduler.complete());
        transport.deliver({submission.id, submission.target, ServiceResponseKind::Data,
                           0, {'C', 'D'}, false, DetectionClock::now()});
        assert(scheduler.complete());
        assert(scheduler.results().size() == 1U);
        assert(scheduler.results().front().state == DetectionState::ResponseTooLarge);
        assert(scheduler.results().front().error == DetectionError::ResponseTooLarge);
    }

    {
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        const ServiceProbeDatabase database = ServiceProbeDatabase::built_in();
        ServiceDetectionConfig config{1U, std::chrono::milliseconds{100}, 32U, 1U};
        assert(engine.shutdown() == skan::core::StatusCode::Ok);
        ServiceScheduler scheduler(engine, transport, database, config);
        assert(scheduler.submit({open_port("127.0.0.1", 80U)}) == skan::core::StatusCode::InternalError);
        assert(scheduler.complete());
        assert(scheduler.pending_count() == 0U);
        assert(scheduler.results().size() == 1U);
        assert(scheduler.results().front().state == DetectionState::Error);
    }

    {
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        const ServiceProbeDatabase database = ServiceProbeDatabase::built_in();
        ServiceScheduler scheduler(engine, transport, database, {});
        auto closed = open_port("127.0.0.1", 80U);
        closed.state = skan::portscan::PortState::Closed;
        assert(scheduler.submit({closed}) == skan::core::StatusCode::Ok);
        assert(scheduler.complete());
        assert(scheduler.results().empty());
    }
    return 0;
}
