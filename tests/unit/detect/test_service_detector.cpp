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
        assert(!detector.complete());
        transport.deliver({submission.id, submission.target, ServiceResponseKind::Closed, 0, {}, false,
                           DetectionClock::now()});
        assert(detector.complete());
        assert(detector.results().size() == 1U);
        assert(detector.results().front().port.number == 80U);
        // EOF cannot validate an unfinished status line or missing headers.
        assert(detector.results().front().service.empty());
        assert(detector.results().front().state == DetectionState::Unknown);
    }

    // A completed TLS handshake must survive transient failures from encrypted
    // fallback attempts without fabricating application identity.
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
        ServiceResponse established;
        established.id = tls.id;
        established.source_address = tls.target;
        established.kind = ServiceResponseKind::TlsEstablished;
        established.tls.emplace();
        established.tls->detected = true;
        established.tls->protocol_version = "TLS 1.3";
        transport.deliver(established);

        assert(transport.submissions().size() == 2U);
        const auto http = transport.submissions().back();
        assert(http.probe_name == "HTTPGet" && http.tls_session);
        transport.deliver({http.id, http.target, ServiceResponseKind::SocketError, ECONNRESET, {}, false,
                           DetectionClock::now()});

        assert(transport.submissions().size() == 3U);
        const auto generic = transport.submissions().back();
        assert(generic.probe_name == "GenericBanner" && generic.tls_session);
        transport.deliver({generic.id, generic.target, ServiceResponseKind::SocketError, ECONNRESET, {}, false,
                           DetectionClock::now()});

        assert(detector.complete());
        assert(detector.results().size() == 1U);
        assert(detector.results().front().state == DetectionState::Detected);
        assert(detector.results().front().service == "tls");
        assert(detector.results().front().product.empty() && detector.results().front().version.empty());
        assert(detector.results().front().tls_version == "TLS 1.3");
        assert(detector.results().front().probe_name == "TLSClientHello");
    }

    return 0;
}
