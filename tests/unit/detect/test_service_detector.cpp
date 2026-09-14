#include <cassert>
#include <cerrno>
#include <chrono>

#include "detect/service_detector.hpp"

int main()
{
    using namespace skan::detect;

    {
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        ServiceDetector detector(
            engine,
            transport,
            ServiceDetectionConfig{1U, std::chrono::milliseconds{100}, 1024U, 1U});
        assert(detector.database().status() == skan::core::StatusCode::Ok);

        skan::portscan::PortResult open;
        open.target = "127.0.0.1";
        open.port = {80U, skan::portscan::Protocol::Tcp};
        open.state = skan::portscan::PortState::Open;
        open.probe = skan::portscan::ScanProbeType::TcpConnect;
        skan::portscan::PortResult closed = open;
        closed.port.number = 81U;
        closed.state = skan::portscan::PortState::Closed;
        assert(detector.submit({open, closed}) == skan::core::StatusCode::Ok);
        assert(detector.pending_count() == 1U);
        const auto submission = transport.submissions().front();
        transport.deliver({submission.id, submission.target, ServiceResponseKind::Data, 0,
                           {'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0'}, false,
                           DetectionClock::now()});
        assert(detector.complete());
        assert(detector.results().size() == 1U);
        assert(detector.results().front().port.number == 80U);
        assert(detector.results().front().service == "http");
        assert(detector.results().front().state == DetectionState::Detected);
    }

    // A valid TLS soft match must survive later transient failures from fallback
    // probes. Hardened TLS endpoints commonly reset plaintext fallbacks instead
    // of closing them cleanly; that must not erase already-observed TLS evidence.
    {
        skan::io::IOEngine engine;
        RecordingServiceTransport transport;
        ServiceDetector detector(
            engine,
            transport,
            ServiceDetectionConfig{1U, std::chrono::milliseconds{2500}, 1024U, 3U});
        assert(detector.database().status() == skan::core::StatusCode::Ok);

        skan::portscan::PortResult open;
        open.target = "127.0.0.1";
        open.port = {443U, skan::portscan::Protocol::Tcp};
        open.state = skan::portscan::PortState::Open;
        open.probe = skan::portscan::ScanProbeType::TcpConnect;
        assert(detector.submit({open}) == skan::core::StatusCode::Ok);

        assert(transport.submissions().size() == 1U);
        const auto tls = transport.submissions().front();
        assert(tls.probe_name == "TLSClientHello");
        transport.deliver({tls.id, tls.target, ServiceResponseKind::Data, 0,
                           {0x16U, 0x03U, 0x03U, 0x00U, 0x00U}, false,
                           DetectionClock::now()});
        assert(!detector.complete());
        transport.deliver({tls.id, tls.target, ServiceResponseKind::Closed, 0, {}, false,
                           DetectionClock::now()});

        assert(transport.submissions().size() == 2U);
        const auto http = transport.submissions().back();
        assert(http.probe_name == "HTTPGet");
        transport.deliver({http.id, http.target, ServiceResponseKind::SocketError, ECONNRESET, {}, false,
                           DetectionClock::now()});

        assert(transport.submissions().size() == 3U);
        const auto generic = transport.submissions().back();
        assert(generic.probe_name == "GenericBanner");
        transport.deliver({generic.id, generic.target, ServiceResponseKind::SocketError, ECONNRESET, {}, false,
                           DetectionClock::now()});

        assert(detector.complete());
        assert(detector.results().size() == 1U);
        assert(detector.results().front().state == DetectionState::Detected);
        assert(detector.results().front().service == "tls");
        assert(detector.results().front().probe_name == "TLSClientHello");
    }

    return 0;
}
