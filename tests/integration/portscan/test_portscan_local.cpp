#include <cassert>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "io/io_engine.hpp"
#include "portscan/port_scheduler.hpp"
#include "portscan/tcp_connect.hpp"

namespace {

std::uint16_t local_port(int socket_fd)
{
    sockaddr_in address{};
    socklen_t length = sizeof(address);
    assert(::getsockname(socket_fd, reinterpret_cast<sockaddr *>(&address), &length) == 0);
    return ntohs(address.sin_port);
}

int make_listener()
{
    const int socket_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(socket_fd >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(0U);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(::bind(socket_fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0);
    assert(::listen(socket_fd, 4) == 0);
    return socket_fd;
}

std::uint16_t local_port6(int socket_fd)
{
    sockaddr_in6 address{};
    socklen_t length = sizeof(address);
    assert(::getsockname(socket_fd, reinterpret_cast<sockaddr *>(&address), &length) == 0);
    return ntohs(address.sin6_port);
}

int make_listener6()
{
    const int socket_fd = ::socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) {
        return -1;
    }
    sockaddr_in6 address{};
    address.sin6_family = AF_INET6;
    address.sin6_port = htons(0U);
    address.sin6_addr = in6addr_loopback;
    if (::bind(socket_fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0 ||
        ::listen(socket_fd, 4) != 0) {
        (void)::close(socket_fd);
        return -1;
    }
    return socket_fd;
}

int make_closed_port_socket()
{
    const int socket_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(socket_fd >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(0U);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(::bind(socket_fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0);
    return socket_fd;
}

} // namespace

int main()
{
    using namespace skan::portscan;

    const int listener = make_listener();
    const std::uint16_t open_port = local_port(listener);
    const int closed_port_socket = make_closed_port_socket();
    const std::uint16_t closed_port = local_port(closed_port_socket);
    assert(::close(closed_port_socket) == 0);

    skan::io::IOEngine engine;
    TcpConnectTransport transport(engine);
    PortScanConfig config{ScanProbeType::TcpConnect, std::chrono::milliseconds{500}, 2U};
    PortScanScheduler scheduler(engine, transport, config);
    const skan::core::Target target{"local-service", {{"127.0.0.1", std::nullopt, true}}};
    assert(scheduler.submit(
               target,
               {{open_port, Protocol::Tcp}, {closed_port, Protocol::Tcp}}) == skan::core::StatusCode::Ok);
    assert(scheduler.run() == skan::core::StatusCode::Ok);
    assert(scheduler.complete());
    assert(scheduler.results().size() == 2U);
    assert(scheduler.results()[0].target == "127.0.0.1");
    assert(scheduler.results()[0].port.number == std::min(open_port, closed_port));
    bool saw_open = false;
    bool saw_closed = false;
    for (const PortResult &result : scheduler.results()) {
        if (result.port.number == open_port) {
            saw_open = result.state == PortState::Open;
        }
        if (result.port.number == closed_port) {
            saw_closed = result.state == PortState::Closed;
        }
    }
    assert(saw_open);
    assert(saw_closed);
    assert(::close(listener) == 0);

    const int listener6 = make_listener6();
    if (listener6 >= 0) {
        const std::uint16_t open_port6 = local_port6(listener6);
        skan::io::IOEngine engine6;
        TcpConnectTransport transport6(engine6);
        PortScanConfig config6{ScanProbeType::TcpConnect, std::chrono::milliseconds{500}, 1U};
        PortScanScheduler scheduler6(engine6, transport6, config6);
        const skan::core::Host host6{
            "::1", std::nullopt, true,
            skan::core::IpAddress::from_ipv6({0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
                                               0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U})};
        const skan::core::Target target6{"local-service-v6", {host6}};
        assert(scheduler6.submit(target6, {{open_port6, Protocol::Tcp}}) == skan::core::StatusCode::Ok);
        assert(scheduler6.run() == skan::core::StatusCode::Ok);
        assert(scheduler6.complete());
        assert(scheduler6.results().size() == 1U);
        assert(scheduler6.results()[0].target == "::1");
        assert(scheduler6.results()[0].state == PortState::Open);
        assert(::close(listener6) == 0);
    } else {
        // IPv6 loopback is a platform capability; an unavailable local stack is a clear skip.
        (void)::fprintf(stderr, "SKIP: IPv6 loopback listener unavailable (%s)\\n", std::strerror(errno));
    }

    return 0;
}
