#ifndef SKAN_NET_TRANSPORT_TYPES_HPP
#define SKAN_NET_TRANSPORT_TYPES_HPP

#include <cstdint>
#include <string>
#include <string_view>

namespace skan::net {

enum class TransportStatus {
    Success,
    InvalidConfiguration,
    InterfaceNotFound,
    PermissionDenied,
    NotSupported,
    NotOpen,
    SendFailed,
    CaptureFailed,
    Closed,
    SystemError
};

const char *transport_status_name(TransportStatus status) noexcept;

struct TransportCapabilities final {
    bool can_capture{false};
    bool can_inject{false};
};

struct TransportConfig final {
    std::string interface_name;
    bool nonblocking{true};
};

struct TransportResult final {
    TransportStatus status{TransportStatus::Success};
    int system_error{0};
    std::string message;

    bool success() const noexcept { return status == TransportStatus::Success; }
};

TransportResult transport_success();
TransportResult transport_failure(TransportStatus status, int system_error, std::string_view message);

} // namespace skan::net

#endif // SKAN_NET_TRANSPORT_TYPES_HPP
