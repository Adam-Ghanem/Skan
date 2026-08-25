#include <cassert>
#include <cstdint>
#include <span>
#include <vector>

#include "net/linux_transport.hpp"
#include "net/transport.hpp"

int main()
{
    const skan::net::TransportConfig config{"unit-test0", true};
    const std::vector<std::uint8_t> first{0x00U, 0x01U, 0xFEU};
    const std::vector<std::uint8_t> second{0x10U, 0x20U};

    skan::net::RecordingTransport recording;
    assert(recording.send(first).status == skan::net::TransportStatus::NotOpen);
    assert(recording.open(config).success());
    assert(recording.is_open());
    assert(recording.send(first).success());
    assert(recording.send(second).success());
    assert(recording.frame_count() == 2U);
    assert(recording.frames()[0] == first);
    assert(recording.frames()[1] == second);
    recording.close();
    recording.close();
    assert(!recording.is_open());
    assert(recording.send(std::span<const std::uint8_t>{first}).status == skan::net::TransportStatus::NotOpen);
    assert(recording.open(skan::net::TransportConfig{}).success());

    skan::net::NullTransport null_transport;
    assert(null_transport.open(config).success());
    assert(null_transport.send(first).success());
    assert(null_transport.send_count() == 1U);
    null_transport.close();
    assert(null_transport.send(first).status == skan::net::TransportStatus::NotOpen);

    skan::net::LinuxTransport invalid;
    assert(invalid.open(skan::net::TransportConfig{}).status == skan::net::TransportStatus::InvalidConfiguration);
    return 0;
}
