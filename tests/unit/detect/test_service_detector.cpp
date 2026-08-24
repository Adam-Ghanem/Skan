#include <cassert>
#include <chrono>

#include "detect/service_detector.hpp"

int main()
{
    using namespace skan::detect;
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
    return 0;
}
