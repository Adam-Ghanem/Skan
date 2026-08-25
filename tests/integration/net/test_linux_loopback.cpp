#include <cassert>
#include <cstdint>
#include <iostream>
#include <span>
#include <vector>

#include "io/io_engine.hpp"
#include "net/capture.hpp"
#include "net/interface.hpp"
#include "net/linux_capture.hpp"
#include "net/packet_receiver.hpp"
#include "net/transport.hpp"

#include "../../unit/net/net_test_fixture.hpp"

int main()
{
    const skan::net::InterfaceEnumerationResult interfaces = skan::net::enumerate_interfaces_result();
    if (!interfaces.success()) {
        std::cout << "SKIPPED: interface enumeration unavailable: " << interfaces.message << '\n';
        return 0;
    }
    const auto loopback = skan::net::find_interface("lo");
    if (!loopback.has_value()) {
        std::cout << "SKIPPED: loopback interface unavailable\n";
        return 0;
    }

    const std::vector<std::uint8_t> frame = skan::test::test_tcp_frame();
    skan::net::RecordingTransport recording;
    assert(recording.open(skan::net::TransportConfig{"lo", true}).success());
    assert(recording.send(std::span<const std::uint8_t>{frame}).success());
    assert(recording.frame_count() == 1U);
    assert(recording.frames().front() == frame);
    recording.close();

    skan::net::LinuxCapture capture;
    const skan::net::CaptureResult opened = capture.open(
        skan::net::CaptureConfig{"lo", 65535U, true});
    if (!opened.success()) {
        std::cout << "SKIPPED: Linux loopback capture unavailable: " << opened.message << '\n';
        return 0;
    }
    assert(capture.file_descriptor() >= 0);
    skan::io::IOEngine io_engine;
    assert(io_engine.initialization_status() == skan::core::StatusCode::Ok);
    skan::net::PacketReceiver receiver(capture);
    assert(receiver.attach(io_engine, [](skan::io::Event &) {}) == skan::core::StatusCode::Ok);
    assert(io_engine.run_once(0) == skan::core::StatusCode::Ok);
    assert(receiver.detach(io_engine) == skan::core::StatusCode::Ok);
    receiver.close();
    capture.close();
    capture.close();
    assert(!capture.is_open());
    return 0;
}
