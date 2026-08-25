#include "portscan/tcp_connect.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <utility>

namespace skan::portscan {
namespace {

std::optional<core::IpAddress> parse_target_address(std::string_view text) noexcept
{
    in_addr ipv4{};
    if (::inet_pton(AF_INET, std::string(text).c_str(), &ipv4) == 1) {
        return core::IpAddress::from_ipv4(ntohl(ipv4.s_addr));
    }
    in6_addr ipv6{};
    if (::inet_pton(AF_INET6, std::string(text).c_str(), &ipv6) == 1) {
        std::array<std::uint8_t, 16U> bytes{};
        std::copy(std::begin(ipv6.s6_addr), std::end(ipv6.s6_addr), bytes.begin());
        return core::IpAddress::from_ipv6(bytes);
    }
    return std::nullopt;
}

std::optional<core::IpAddress> submission_address(const PortSubmission &submission) noexcept
{
    return submission.target_ip.valid() ? std::optional<core::IpAddress>{submission.target_ip}
                                        : parse_target_address(submission.target);
}

} // namespace

ScanProbeType TcpConnectProbe::type() const noexcept
{
    return ScanProbeType::TcpConnect;
}

core::StatusCode TcpConnectProbe::build(
    PortProbeId id,
    const core::Host &target,
    const Port &port,
    const PortScanConfig &config,
    PortSubmission &submission) const
{
    (void)config;
    if (id == 0U || port.protocol != Protocol::Tcp || port.number == 0U || target.address.empty()) {
        return core::StatusCode::InvalidArgument;
    }
    const auto address = target.ip_address.valid() ? std::optional<core::IpAddress>{target.ip_address}
                                                   : parse_target_address(target.address);
    if (!address.has_value()) {
        return core::StatusCode::InvalidArgument;
    }
    submission = PortSubmission{};
    submission.id = id;
    submission.probe = type();
    submission.target = target.address;
    submission.port = port;
    submission.target_ip = *address;
    return core::StatusCode::Ok;
}

PortState TcpConnectProbe::timeout_state() const noexcept
{
    return PortState::Filtered;
}

ScanReason TcpConnectProbe::timeout_reason() const noexcept
{
    return ScanReason::Timeout;
}

core::StatusCode TcpConnectProbe::assess(
    const PortResponse &response,
    const PortSubmission &submission,
    PortState &state,
    ScanReason &reason) const
{
    if (response.id != submission.id ||
        (!response.source_address.empty() && response.source_address != submission.target)) {
        return core::StatusCode::NotFound;
    }
    switch (response.kind) {
    case PortResponseKind::Connected:
        state = PortState::Open;
        reason = ScanReason::ImmediateSuccess;
        return core::StatusCode::Ok;
    case PortResponseKind::ConnectionRefused:
        state = PortState::Closed;
        reason = ScanReason::ConnectionRefused;
        return core::StatusCode::Ok;
    case PortResponseKind::SocketError:
        if (response.system_error == ETIMEDOUT) {
            state = PortState::Filtered;
            reason = ScanReason::Timeout;
        } else {
            state = PortState::Unknown;
            reason = ScanReason::SocketError;
        }
        return core::StatusCode::Ok;
    case PortResponseKind::Packet:
    default:
        return core::StatusCode::ParseError;
    }
}

struct TcpConnectTransport::Connection final {
    int file_descriptor{-1};
    std::unique_ptr<io::Event> event;
    PortResponseCallback callback;
    bool completed{false};
    bool callback_in_progress{false};

    ~Connection() noexcept
    {
        if (file_descriptor >= 0) {
            ::close(file_descriptor);
        }
    }
};

TcpConnectTransport::TcpConnectTransport(io::IOEngine &engine) noexcept : engine_(engine)
{
}

TcpConnectTransport::~TcpConnectTransport()
{
    for (auto &entry : connections_) {
        close_connection(*entry.second);
    }
    connections_.clear();
}

bool TcpConnectTransport::supports(ScanProbeType probe) const noexcept
{
    return probe == ScanProbeType::TcpConnect;
}

core::StatusCode TcpConnectTransport::submit(
    const PortSubmission &submission,
    PortResponseCallback callback)
{
    if (!supports(submission.probe) || submission.id == 0U || submission.target.empty() ||
        submission.port.number == 0U || !callback) {
        return core::StatusCode::InvalidArgument;
    }
    reap_completed();
    if (connections_.find(submission.id) != connections_.end()) {
        return core::StatusCode::InvalidArgument;
    }

    const auto address = submission_address(submission);
    if (!address.has_value()) {
        return core::StatusCode::InvalidArgument;
    }
    const int address_family = address->is_ipv6() ? AF_INET6 : AF_INET;
    const int file_descriptor = ::socket(address_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (file_descriptor < 0) {
        return errno == EACCES || errno == EPERM ? core::StatusCode::PermissionDenied
                                                  : core::StatusCode::IoError;
    }
    const core::StatusCode nonblocking_status = io::IOEngine::set_nonblocking(file_descriptor);
    if (nonblocking_status != core::StatusCode::Ok) {
        ::close(file_descriptor);
        return nonblocking_status;
    }

    sockaddr_storage socket_address{};
    socklen_t socket_address_size = 0U;
    if (address->is_ipv6()) {
        auto *ipv6_address = reinterpret_cast<sockaddr_in6 *>(&socket_address);
        ipv6_address->sin6_family = AF_INET6;
        ipv6_address->sin6_port = htons(submission.port.number);
        std::copy(address->bytes.begin(), address->bytes.end(), ipv6_address->sin6_addr.s6_addr);
        socket_address_size = static_cast<socklen_t>(sizeof(sockaddr_in6));
    } else {
        auto *ipv4_address = reinterpret_cast<sockaddr_in *>(&socket_address);
        ipv4_address->sin_family = AF_INET;
        ipv4_address->sin_port = htons(submission.port.number);
        const std::uint32_t network_address = htonl(
            (static_cast<std::uint32_t>(address->bytes[0]) << 24U) |
            (static_cast<std::uint32_t>(address->bytes[1]) << 16U) |
            (static_cast<std::uint32_t>(address->bytes[2]) << 8U) |
            static_cast<std::uint32_t>(address->bytes[3]));
        ipv4_address->sin_addr.s_addr = network_address;
        socket_address_size = static_cast<socklen_t>(sizeof(sockaddr_in));
    }
    const int connect_result = ::connect(
        file_descriptor,
        reinterpret_cast<const sockaddr *>(&socket_address),
        socket_address_size);

    if (connect_result == 0) {
        PortResponse response;
        response.id = submission.id;
        response.source_address = submission.target;
        response.kind = PortResponseKind::Connected;
        response.received_at = PortScanClock::now();
        ::close(file_descriptor);
        callback(response);
        return core::StatusCode::Ok;
    }

    const int connect_error = errno;
    if (connect_error != EINPROGRESS) {
        PortResponse response;
        response.id = submission.id;
        response.source_address = submission.target;
        response.kind = connect_error == ECONNREFUSED ? PortResponseKind::ConnectionRefused
                                                       : PortResponseKind::SocketError;
        response.system_error = connect_error;
        response.received_at = PortScanClock::now();
        ::close(file_descriptor);
        callback(response);
        return core::StatusCode::Ok;
    }

    std::unique_ptr<Connection> connection;
    try {
        connection = std::make_unique<Connection>();
        connection->file_descriptor = file_descriptor;
        connection->callback = std::move(callback);
        connection->event = std::make_unique<io::Event>(
            file_descriptor,
            io::EventMask::Write | io::EventMask::Error | io::EventMask::Hangup,
            [this, id = submission.id](io::Event &) { on_event(id); });
    } catch (const std::bad_alloc &) {
        if (!connection) {
            ::close(file_descriptor);
        }
        return core::StatusCode::MemoryError;
    }
    try {
        const auto inserted = connections_.emplace(submission.id, std::move(connection));
        if (!inserted.second) {
            return core::StatusCode::InvalidArgument;
        }
        const core::StatusCode add_status = engine_.add(*inserted.first->second->event);
        if (add_status != core::StatusCode::Ok) {
            connections_.erase(inserted.first);
            return add_status;
        }
    } catch (const std::bad_alloc &) {
        if (connection) {
            connection.reset();
        }
        return core::StatusCode::MemoryError;
    }
    return core::StatusCode::Ok;
}

core::StatusCode TcpConnectTransport::cancel(PortProbeId id) noexcept
{
    const auto iterator = connections_.find(id);
    if (iterator == connections_.end() || iterator->second->callback_in_progress ||
        iterator->second->completed) {
        return core::StatusCode::Ok;
    }
    close_connection(*iterator->second);
    connections_.erase(iterator);
    return core::StatusCode::Ok;
}

void TcpConnectTransport::on_event(PortProbeId id) noexcept
{
    const auto iterator = connections_.find(id);
    if (iterator == connections_.end()) {
        return;
    }
    int socket_error = 0;
    socklen_t socket_error_size = sizeof(socket_error);
    if (::getsockopt(
            iterator->second->file_descriptor,
            SOL_SOCKET,
            SO_ERROR,
            &socket_error,
            &socket_error_size) != 0) {
        finish(id, PortResponseKind::SocketError, errno);
        return;
    }
    if (socket_error == 0) {
        finish(id, PortResponseKind::Connected, 0);
    } else if (socket_error == ECONNREFUSED) {
        finish(id, PortResponseKind::ConnectionRefused, socket_error);
    } else {
        finish(id, PortResponseKind::SocketError, socket_error);
    }
}

void TcpConnectTransport::finish(PortProbeId id, PortResponseKind kind, int system_error) noexcept
{
    const auto iterator = connections_.find(id);
    if (iterator == connections_.end()) {
        return;
    }
    Connection &connection = *iterator->second;
    if (connection.completed) {
        return;
    }
    connection.completed = true;
    connection.callback_in_progress = true;
    PortResponse response;
    response.id = id;
    response.kind = kind;
    response.system_error = system_error;
    response.received_at = PortScanClock::now();
    PortResponseCallback callback = std::move(connection.callback);
    close_connection(connection, true);
    if (callback) {
        try {
            callback(response);
        } catch (...) {
        }
    }
    connection.callback_in_progress = false;
}

void TcpConnectTransport::reap_completed() noexcept
{
    for (auto iterator = connections_.begin(); iterator != connections_.end();) {
        if (iterator->second->completed && !iterator->second->callback_in_progress) {
            close_connection(*iterator->second);
            iterator = connections_.erase(iterator);
        } else {
            ++iterator;
        }
    }
}

void TcpConnectTransport::close_connection(Connection &connection, bool retain_event) noexcept
{
    if (connection.event && connection.event->registered()) {
        (void)engine_.remove(*connection.event);
    }
    if (!retain_event) {
        connection.event.reset();
    }
    if (connection.file_descriptor >= 0) {
        ::close(connection.file_descriptor);
        connection.file_descriptor = -1;
    }
}

} // namespace skan::portscan
