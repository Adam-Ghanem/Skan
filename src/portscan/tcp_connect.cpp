#include "portscan/tcp_connect.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <utility>

namespace skan::portscan {

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
    in_addr address{};
    if (::inet_pton(AF_INET, target.address.c_str(), &address) != 1) {
        return core::StatusCode::InvalidArgument;
    }
    submission = PortSubmission{};
    submission.id = id;
    submission.probe = type();
    submission.target = target.address;
    submission.port = port;
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

    in_addr address{};
    if (::inet_pton(AF_INET, submission.target.c_str(), &address) != 1) {
        return core::StatusCode::InvalidArgument;
    }

    const int file_descriptor = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (file_descriptor < 0) {
        return errno == EACCES || errno == EPERM ? core::StatusCode::PermissionDenied
                                                  : core::StatusCode::IoError;
    }
    const core::StatusCode nonblocking_status = io::IOEngine::set_nonblocking(file_descriptor);
    if (nonblocking_status != core::StatusCode::Ok) {
        ::close(file_descriptor);
        return nonblocking_status;
    }

    sockaddr_in socket_address{};
    socket_address.sin_family = AF_INET;
    socket_address.sin_port = htons(submission.port.number);
    socket_address.sin_addr = address;
    const int connect_result = ::connect(
        file_descriptor,
        reinterpret_cast<const sockaddr *>(&socket_address),
        sizeof(socket_address));

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
