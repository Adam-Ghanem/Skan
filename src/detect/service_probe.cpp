#include "detect/service_probe.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <new>
#include <utility>

namespace skan::detect {

core::StatusCode RecordingServiceTransport::submit(
    const ServiceSubmission &submission,
    ServiceResponseCallback callback)
{
    if (submission.id == 0U || submission.target.empty() || !callback) {
        return core::StatusCode::InvalidArgument;
    }
    try {
        submissions_.push_back(submission);
        const auto inserted = callbacks_.emplace(submission.id, std::move(callback));
        if (!inserted.second) {
            submissions_.pop_back();
            return core::StatusCode::InvalidArgument;
        }
    } catch (const std::bad_alloc &) {
        if (!submissions_.empty() && submissions_.back().id == submission.id) {
            submissions_.pop_back();
        }
        return core::StatusCode::MemoryError;
    }
    return core::StatusCode::Ok;
}

core::StatusCode RecordingServiceTransport::cancel(ServiceProbeId id) noexcept
{
    callbacks_.erase(id);
    return core::StatusCode::Ok;
}

const std::vector<ServiceSubmission> &RecordingServiceTransport::submissions() const noexcept
{
    return submissions_;
}

void RecordingServiceTransport::deliver(const ServiceResponse &response)
{
    const auto iterator = callbacks_.find(response.id);
    if (iterator == callbacks_.end()) {
        return;
    }
    ServiceResponseCallback callback = iterator->second;
    if (response.kind != ServiceResponseKind::Data) {
        callbacks_.erase(iterator);
    }
    callback(response);
}

void RecordingServiceTransport::clear() noexcept
{
    callbacks_.clear();
    submissions_.clear();
}

ServiceProbe::ServiceProbe(const ServiceProbeDefinition &definition, std::size_t max_response_bytes) noexcept
    : definition_(definition), max_response_bytes_(max_response_bytes)
{
}

const ServiceProbeDefinition &ServiceProbe::definition() const noexcept
{
    return definition_;
}

core::StatusCode ServiceProbe::build(
    ServiceProbeId id,
    const core::Host &target,
    const DetectionPort &port,
    ServiceSubmission &submission) const
{
    if (id == 0U || target.address.empty() || port.protocol != TransportProtocol::Tcp || port.number == 0U ||
        definition_.protocol != TransportProtocol::Tcp || max_response_bytes_ == 0U) {
        return core::StatusCode::InvalidArgument;
    }
    in_addr address{};
    if (::inet_pton(AF_INET, target.address.c_str(), &address) != 1) {
        return core::StatusCode::InvalidArgument;
    }
    submission = ServiceSubmission{};
    submission.id = id;
    submission.target = target.address;
    submission.port = port;
    submission.probe_id = definition_.id;
    submission.probe_name = definition_.name;
    submission.payload = definition_.payload;
    submission.max_response_bytes = max_response_bytes_;
    return core::StatusCode::Ok;
}

core::StatusCode ServiceProbe::assess(
    const ServiceResponse &response,
    const ServiceSubmission &submission,
    std::string &bounded_response,
    DetectionError &error) const
{
    if (response.id != submission.id ||
        (!response.source_address.empty() && response.source_address != submission.target)) {
        return core::StatusCode::NotFound;
    }
    if (response.response_truncated || response.bytes.size() > max_response_bytes_) {
        error = DetectionError::ResponseTooLarge;
        return core::StatusCode::MemoryError;
    }
    if (response.kind == ServiceResponseKind::SocketError) {
        error = DetectionError::TransportFailure;
        return core::StatusCode::IoError;
    }
    if (response.kind == ServiceResponseKind::Closed) {
        error = DetectionError::ConnectionClosed;
        return core::StatusCode::NotFound;
    }
    try {
        bounded_response.assign(
            reinterpret_cast<const char *>(response.bytes.data()), response.bytes.size());
    } catch (const std::bad_alloc &) {
        error = DetectionError::InternalError;
        return core::StatusCode::MemoryError;
    }
    error = DetectionError::None;
    return core::StatusCode::Ok;
}

struct ServiceTcpTransport::Connection final {
    int file_descriptor{-1};
    std::unique_ptr<io::Event> event;
    ServiceResponseCallback callback;
    std::string target;
    std::vector<std::uint8_t> payload;
    std::size_t sent{0U};
    std::size_t max_response_bytes{0U};
    std::vector<std::uint8_t> response;
    bool connected{false};
    bool completed{false};
    bool callback_in_progress{false};
    bool cancel_requested{false};

    ~Connection() noexcept
    {
        if (file_descriptor >= 0) {
            ::close(file_descriptor);
        }
    }
};

ServiceTcpTransport::ServiceTcpTransport(io::IOEngine &engine) noexcept : engine_(engine)
{
}

ServiceTcpTransport::~ServiceTcpTransport()
{
    for (auto &entry : connections_) {
        cleanup(*entry.second);
    }
    connections_.clear();
}

core::StatusCode ServiceTcpTransport::submit(
    const ServiceSubmission &submission,
    ServiceResponseCallback callback)
{
    if (submission.id == 0U || submission.target.empty() || submission.port.number == 0U ||
        submission.port.protocol != TransportProtocol::Tcp || !callback || submission.max_response_bytes == 0U) {
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
    if (connect_result < 0 && errno != EINPROGRESS) {
        const int connect_error = errno;
        ::close(file_descriptor);
        ServiceResponse response;
        response.id = submission.id;
        response.source_address = submission.target;
        response.kind = ServiceResponseKind::SocketError;
        response.system_error = connect_error;
        response.received_at = DetectionClock::now();
        try {
            callback(response);
        } catch (...) {
        }
        return core::StatusCode::Ok;
    }

    std::unique_ptr<Connection> connection;
    try {
        connection = std::make_unique<Connection>();
        connection->file_descriptor = file_descriptor;
        connection->callback = std::move(callback);
        connection->target = submission.target;
        connection->payload.assign(submission.payload.begin(), submission.payload.end());
        connection->max_response_bytes = submission.max_response_bytes;
        connection->event = std::make_unique<io::Event>(
            file_descriptor,
            io::EventMask::Read | io::EventMask::Write | io::EventMask::Error | io::EventMask::Hangup,
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
    if (connect_result == 0) {
        on_writable(submission.id);
    }
    return core::StatusCode::Ok;
}

core::StatusCode ServiceTcpTransport::cancel(ServiceProbeId id) noexcept
{
    const auto iterator = connections_.find(id);
    if (iterator == connections_.end() || iterator->second->completed) {
        return core::StatusCode::Ok;
    }
    if (iterator->second->callback_in_progress) {
        iterator->second->cancel_requested = true;
        return core::StatusCode::Ok;
    }
    cleanup(*iterator->second);
    connections_.erase(iterator);
    return core::StatusCode::Ok;
}

void ServiceTcpTransport::on_event(ServiceProbeId id) noexcept
{
    const auto iterator = connections_.find(id);
    if (iterator == connections_.end() || iterator->second->completed) {
        return;
    }
    const io::EventMask ready = iterator->second->event->ready_mask();
    if (!iterator->second->connected &&
        (io::has_event(ready, io::EventMask::Write) || io::has_event(ready, io::EventMask::Read) ||
         io::has_event(ready, io::EventMask::Error) || io::has_event(ready, io::EventMask::Hangup))) {
        int socket_error = 0;
        socklen_t size = sizeof(socket_error);
        if (::getsockopt(iterator->second->file_descriptor, SOL_SOCKET, SO_ERROR, &socket_error, &size) != 0) {
            emit(id, ServiceResponseKind::SocketError, nullptr, 0U, false, errno);
            return;
        }
        if (socket_error != 0) {
            emit(id, ServiceResponseKind::SocketError, nullptr, 0U, false, socket_error);
            return;
        }
        iterator->second->connected = true;
    }
    if (iterator->second->connected && io::has_event(ready, io::EventMask::Write)) {
        on_writable(id);
    }
    if (iterator->second->connected &&
        (io::has_event(ready, io::EventMask::Read) || io::has_event(ready, io::EventMask::Error) ||
         io::has_event(ready, io::EventMask::Hangup))) {
        on_readable(id);
    }
}

void ServiceTcpTransport::on_writable(ServiceProbeId id) noexcept
{
    const auto iterator = connections_.find(id);
    if (iterator == connections_.end() || iterator->second->completed) {
        return;
    }
    Connection &connection = *iterator->second;
    connection.connected = true;
    while (connection.sent < connection.payload.size()) {
        const std::size_t remaining = connection.payload.size() - connection.sent;
        const ssize_t sent = ::send(
            connection.file_descriptor,
            connection.payload.data() + connection.sent,
            remaining,
            MSG_NOSIGNAL);
        if (sent > 0) {
            connection.sent += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        emit(id, ServiceResponseKind::SocketError, nullptr, 0U, false, sent < 0 ? errno : EIO);
        return;
    }
    if (connection.sent >= connection.payload.size()) {
        connection.event->set_mask(io::EventMask::Read | io::EventMask::Error | io::EventMask::Hangup);
        if (connection.event->registered()) {
            (void)engine_.modify(*connection.event);
        }
    }
}

void ServiceTcpTransport::on_readable(ServiceProbeId id) noexcept
{
    const auto iterator = connections_.find(id);
    if (iterator == connections_.end() || iterator->second->completed) {
        return;
    }
    Connection &connection = *iterator->second;
    std::uint8_t buffer[1024];
    for (;;) {
        const ssize_t received = ::recv(connection.file_descriptor, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (received > 0) {
            const std::size_t count = static_cast<std::size_t>(received);
            const std::size_t remaining = connection.max_response_bytes - connection.response.size();
            if (count > remaining) {
                if (remaining > 0U) {
                    connection.response.insert(connection.response.end(), buffer, buffer + remaining);
                }
                emit(id, ServiceResponseKind::Data, connection.response.data(), connection.response.size(), true, 0);
                return;
            }
            connection.response.insert(connection.response.end(), buffer, buffer + count);
            emit(id, ServiceResponseKind::Data, connection.response.data(), connection.response.size(), false, 0);
            return;
        }
        if (received == 0) {
            emit(id, ServiceResponseKind::Closed, connection.response.data(), connection.response.size(), false, 0);
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        emit(id, ServiceResponseKind::SocketError, connection.response.data(), connection.response.size(), false, errno);
        return;
    }
}

void ServiceTcpTransport::emit(
    ServiceProbeId id,
    ServiceResponseKind kind,
    const std::uint8_t *bytes,
    std::size_t byte_count,
    bool truncated,
    int system_error) noexcept
{
    const auto iterator = connections_.find(id);
    if (iterator == connections_.end() || iterator->second->completed) {
        return;
    }
    Connection &connection = *iterator->second;
    const bool terminal = kind != ServiceResponseKind::Data || truncated;
    connection.completed = terminal;
    connection.callback_in_progress = true;
    ServiceResponse response;
    response.id = id;
    response.source_address = connection.target;
    response.kind = kind;
    response.system_error = system_error;
    response.response_truncated = truncated;
    response.received_at = DetectionClock::now();
    try {
        if (bytes != nullptr && byte_count > 0U) {
            response.bytes.assign(bytes, bytes + byte_count);
        }
    } catch (...) {
        response.bytes.clear();
        response.response_truncated = true;
    }
    if (terminal) {
        ServiceResponseCallback callback = std::move(connection.callback);
        cleanup(connection, true);
        if (callback) {
            try {
                callback(response);
            } catch (...) {
            }
        }
    } else if (connection.callback) {
        try {
            connection.callback(response);
        } catch (...) {
        }
    }
    connection.callback_in_progress = false;
    if (!terminal && connection.cancel_requested) {
        connection.completed = true;
        cleanup(connection, true);
    }
}

void ServiceTcpTransport::cleanup(Connection &connection, bool retain_event) noexcept
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

void ServiceTcpTransport::reap_completed() noexcept
{
    for (auto iterator = connections_.begin(); iterator != connections_.end();) {
        if (iterator->second->completed && !iterator->second->callback_in_progress) {
            cleanup(*iterator->second);
            iterator = connections_.erase(iterator);
        } else {
            ++iterator;
        }
    }
}

} // namespace skan::detect
