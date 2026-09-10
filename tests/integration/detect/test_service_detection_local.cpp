#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <netinet/in.h>
#include <string>
#include <utility>
#include <vector>
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

int make_ipv6_listener()
{
    const int socket_fd = ::socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) {
        return -1;
    }
    int enabled = 1;
    (void)::setsockopt(socket_fd, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled));
    sockaddr_in6 address{};
    address.sin6_family = AF_INET6;
    address.sin6_port = htons(0U);
    address.sin6_addr = in6addr_loopback;
    if (::bind(socket_fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0 ||
        ::listen(socket_fd, 2) != 0) {
        (void)::close(socket_fd);
        return -1;
    }
    return socket_fd;
}

std::uint16_t listener_port(int socket_fd)
{
    sockaddr_storage address{};
    socklen_t length = sizeof(address);
    assert(::getsockname(socket_fd, reinterpret_cast<sockaddr *>(&address), &length) == 0);
    if (address.ss_family == AF_INET6) {
        return ntohs(reinterpret_cast<const sockaddr_in6 *>(&address)->sin6_port);
    }
    return ntohs(reinterpret_cast<const sockaddr_in *>(&address)->sin_port);
}

skan::portscan::PortResult open_result(std::string target, std::uint16_t port)
{
    skan::portscan::PortResult result;
    result.target = std::move(target);
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

void serve_fragmented_http(int listener, int release_fd)
{
    const int client = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    bool served = client >= 0;
    if (served) {
        char request[512];
        served = ::recv(client, request, sizeof(request), 0) > 0;
    }
    if (served) {
        static constexpr char first[] = "H";
        static constexpr char rest[] =
            "TTP/1.1 200 OK\r\nServer: Apache/2.4.29\r\nConnection: close\r\n\r\n";
        served = ::send(client, first, sizeof(first) - 1U, MSG_NOSIGNAL) ==
                 static_cast<ssize_t>(sizeof(first) - 1U);
        char release = '\0';
        served = served && ::read(release_fd, &release, 1U) == 1 && release == 'R';
        served = served && ::send(client, rest, sizeof(rest) - 1U, MSG_NOSIGNAL) ==
                               static_cast<ssize_t>(sizeof(rest) - 1U);
        (void)::shutdown(client, SHUT_WR);
        (void)::close(client);
    }
    (void)::close(release_fd);
    (void)::close(listener);
    ::_exit(served ? EXIT_SUCCESS : EXIT_FAILURE);
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
    assert(detector.submit({open_result("127.0.0.1", ssh_port), open_result("127.0.0.1", http_port)}) ==
           skan::core::StatusCode::Ok);
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

    const int fragmented_listener = make_listener();
    const std::uint16_t fragmented_port = listener_port(fragmented_listener);
    int release_pipe[2]{};
    assert(::pipe2(release_pipe, O_CLOEXEC) == 0);
    const pid_t fragmented_child = ::fork();
    assert(fragmented_child >= 0);
    if (fragmented_child == 0) {
        (void)::close(release_pipe[1]);
        serve_fragmented_http(fragmented_listener, release_pipe[0]);
    }
    (void)::close(release_pipe[0]);
    skan::detect::ServiceTcpTransport fragmented_transport(engine);
    skan::detect::ServiceSubmission fragmented_submission;
    fragmented_submission.id = 10'000U;
    fragmented_submission.target = "127.0.0.1";
    fragmented_submission.port = {fragmented_port, skan::portscan::Protocol::Tcp};
    fragmented_submission.probe_id = "fragmented-http";
    fragmented_submission.probe_name = "HTTPGet";
    const std::string request = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    fragmented_submission.payload.assign(request.begin(), request.end());
    fragmented_submission.max_response_bytes = 4096U;
    fragmented_submission.target_ip = skan::core::IpAddress::from_ipv4(0x7F000001U);
    std::vector<std::string> data_chunks;
    bool fragmented_terminal = false;
    assert(fragmented_transport.submit(
               fragmented_submission,
               [&](const skan::detect::ServiceResponse &response) {
                   if (response.kind == skan::detect::ServiceResponseKind::Data) {
                       data_chunks.emplace_back(
                           reinterpret_cast<const char *>(response.bytes.data()), response.bytes.size());
                       if (data_chunks.size() == 1U) {
                           const char release = 'R';
                           assert(::write(release_pipe[1], &release, 1U) == 1);
                       }
                   } else {
                       fragmented_terminal = true;
                   }
               }) == skan::core::StatusCode::Ok);
    for (std::size_t iteration = 0U; iteration < 10U && !fragmented_terminal; ++iteration) {
        assert(engine.run_once(500) == skan::core::StatusCode::Ok);
    }
    assert(fragmented_terminal);
    assert(!data_chunks.empty());
    assert(data_chunks[0] == "H");
    std::string fragmented_response;
    for (const std::string &chunk : data_chunks) {
        fragmented_response += chunk;
    }
    assert(fragmented_response ==
           "HTTP/1.1 200 OK\r\nServer: Apache/2.4.29\r\nConnection: close\r\n\r\n");
    assert(::close(release_pipe[1]) == 0);
    assert(::close(fragmented_listener) == 0);
    int fragmented_status = 0;
    assert(::waitpid(fragmented_child, &fragmented_status, 0) == fragmented_child);
    assert(WIFEXITED(fragmented_status));
    assert(WEXITSTATUS(fragmented_status) == EXIT_SUCCESS);

    const int ipv6_ssh_listener = make_ipv6_listener();
    const int ipv6_http_listener = make_ipv6_listener();
    if (ipv6_ssh_listener >= 0 && ipv6_http_listener >= 0) {
        const std::uint16_t ipv6_ssh_port = listener_port(ipv6_ssh_listener);
        const std::uint16_t ipv6_http_port = listener_port(ipv6_http_listener);
        const pid_t ipv6_ssh_child = ::fork();
        assert(ipv6_ssh_child >= 0);
        if (ipv6_ssh_child == 0) {
            (void)::close(ipv6_http_listener);
            serve_once(ipv6_ssh_listener, "SSH-2.0-OpenSSH_9.6\\r\\n");
        }
        const pid_t ipv6_http_child = ::fork();
        assert(ipv6_http_child >= 0);
        if (ipv6_http_child == 0) {
            (void)::close(ipv6_ssh_listener);
            serve_once(ipv6_http_listener, "HTTP/1.1 200 OK\\r\\nServer: TestHTTP/1.2\\r\\n\\r\\n");
        }
        skan::detect::ServiceTcpTransport ipv6_transport(engine);
        skan::detect::ServiceDetector ipv6_detector(
            engine,
            ipv6_transport,
            skan::detect::ServiceDetectionConfig{2U, std::chrono::milliseconds{500}, 4096U, 1U});
        assert(ipv6_detector.submit({open_result("::1", ipv6_ssh_port), open_result("::1", ipv6_http_port)}) ==
               skan::core::StatusCode::Ok);
        assert(ipv6_detector.run() == skan::core::StatusCode::Ok);
        assert(ipv6_detector.complete());
        bool ipv6_saw_ssh = false;
        bool ipv6_saw_http = false;
        for (const skan::detect::ServiceResult &result : ipv6_detector.results()) {
            if (result.port.number == ipv6_ssh_port) {
                ipv6_saw_ssh = result.service == "ssh" && result.product == "OpenSSH" && result.version == "9.6";
            }
            if (result.port.number == ipv6_http_port) {
                ipv6_saw_http = result.service == "http" && result.product == "HTTP" && result.version == "1.1";
            }
        }
        assert(ipv6_saw_ssh);
        assert(ipv6_saw_http);
        (void)::close(ipv6_ssh_listener);
        (void)::close(ipv6_http_listener);
        int ipv6_ssh_status = 0;
        int ipv6_http_status = 0;
        assert(::waitpid(ipv6_ssh_child, &ipv6_ssh_status, 0) == ipv6_ssh_child);
        assert(::waitpid(ipv6_http_child, &ipv6_http_status, 0) == ipv6_http_child);
        assert(WIFEXITED(ipv6_ssh_status));
        assert(WIFEXITED(ipv6_http_status));
        assert(WEXITSTATUS(ipv6_ssh_status) == EXIT_SUCCESS);
        assert(WEXITSTATUS(ipv6_http_status) == EXIT_SUCCESS);
    } else {
        if (ipv6_ssh_listener >= 0) {
            (void)::close(ipv6_ssh_listener);
        }
        if (ipv6_http_listener >= 0) {
            (void)::close(ipv6_http_listener);
        }
    }
    return 0;
}
