#include <cassert>
#include <iostream>
#include <string>

#include "net/interface.hpp"
#include "net/linux_transport.hpp"

int main()
{
    skan::net::LinuxTransport transport;
    assert(transport.send({}).status == skan::net::TransportStatus::NotOpen);
    assert(transport.open(skan::net::TransportConfig{}).status ==
           skan::net::TransportStatus::InvalidConfiguration);

    const auto loopback = skan::net::find_interface("lo");
    if (!loopback.has_value()) {
        std::cout << "SKIPPED: loopback interface unavailable\n";
        return 0;
    }
    const skan::net::TransportResult opened = transport.open(
        skan::net::TransportConfig{"lo", true});
    if (!opened.success()) {
        std::cout << "SKIPPED: Linux packet transport unavailable: " << opened.message << '\n';
        return 0;
    }
    assert(transport.is_open());
    assert(transport.file_descriptor() >= 0);
    transport.close();
    transport.close();
    assert(!transport.is_open());
    assert(transport.send({}).status == skan::net::TransportStatus::NotOpen);
    return 0;
}
