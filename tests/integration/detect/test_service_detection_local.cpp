#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "detect/service_detector.hpp"

namespace {

int make_listener()
{
    const int socket_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(socket_fd >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(0U);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(::bind(socket_fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0);
    assert(::listen(socket_fd, 2) == 0);
    return socket_fd;
}

std::uint16_t listener_port(int socket_fd)
{
    sockaddr_in address{};
    socklen_t length = sizeof(address);
    assert(::getsockname(socket_fd, reinterpret_cast<sockaddr *>(&address), &length) == 0);
    return ntohs(address.sin_port);
}

skan::portscan::PortResult open_result(std::uint16_t port)
{
    skan::portscan::PortResult result;
    result.target = "127.0.0.1";
    result.port = {port, skan::portscan::Protocol::Tcp};
    result.state = skan::portscan::PortState::Open;
    result.probe = skan::portscan::ScanProbeType::TcpConnect;
    return result;
}

void serve_once(int listener, const char *response)
{
    const int client = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    if (client >= 0) {
        (void)::send(client, response, std::strlen(response), MSG_NOSIGNAL);
        (void)::shutdown(client, SHUT_WR);
        char request[256];
        while (::recv(client, request, sizeof(request), 0) > 0) {
        }
        (void)::close(client);
    }
    (void)::close(listener);
    ::_exit(client >= 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

} // namespace

int main()
{
    const int ssh_listener = make_listener();
    const int http_listener = make_listener();
    const std::uint16_t ssh_port = listener_port(ssh_listener);
    const std::uint16_t http_port = listener_port(http_listener);

    const pid_t ssh_child = ::fork();
    assert(ssh_child >= 0);
    if (ssh_child == 0) {
        (void)::close(http_listener);
        serve_once(ssh_listener, "SSH-2.0-OpenSSH_9.6\r\n");
    }
    const pid_t http_child = ::fork();
    assert(http_child >= 0);
    if (http_child == 0) {
        (void)::close(ssh_listener);
        serve_once(http_listener, "HTTP/1.1 200 OK\r\nServer: TestHTTP/1.2\r\n\r\n");
    }

    skan::io::IOEngine engine;
    skan::detect::ServiceTcpTransport transport(engine);
    skan::detect::ServiceDetector detector(
        engine,
        transport,
        skan::detect::ServiceDetectionConfig{2U, std::chrono::milliseconds{500}, 4096U, 1U});
    assert(detector.submit({open_result(ssh_port), open_result(http_port)}) == skan::core::StatusCode::Ok);
    assert(detector.run() == skan::core::StatusCode::Ok);
    assert(detector.complete());
    assert(detector.results().size() == 2U);
    assert(detector.results()[0].port.number == std::min(ssh_port, http_port));

    bool saw_ssh = false;
    bool saw_http = false;
    for (const skan::detect::ServiceResult &result : detector.results()) {
        if (result.port.number == ssh_port) {
            saw_ssh = result.service == "ssh" && result.product == "OpenSSH" && result.version == "9.6";
        }
        if (result.port.number == http_port) {
            saw_http = result.service == "http" && result.product == "HTTP" && result.version == "1.1";
        }
    }
    assert(saw_ssh);
    assert(saw_http);
    assert(::close(ssh_listener) == 0);
    assert(::close(http_listener) == 0);
    int ssh_status = 0;
    int http_status = 0;
    assert(::waitpid(ssh_child, &ssh_status, 0) == ssh_child);
    assert(::waitpid(http_child, &http_status, 0) == http_child);
    assert(WIFEXITED(ssh_status));
    assert(WIFEXITED(http_status));
    assert(WEXITSTATUS(ssh_status) == EXIT_SUCCESS);
    assert(WEXITSTATUS(http_status) == EXIT_SUCCESS);
    return 0;
}
