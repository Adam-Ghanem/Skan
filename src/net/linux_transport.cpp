#include "net/linux_transport.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

namespace skan::net {
namespace {

TransportResult system_failure(TransportStatus status, int error_number, const char *operation)
{
    return transport_failure(status, error_number, std::string{operation} + ": " + std::strerror(error_number));
}

TransportStatus socket_error_status(int error_number) noexcept
{
    if (error_number == EACCES || error_number == EPERM) {
        return TransportStatus::PermissionDenied;
    }
    return TransportStatus::SystemError;
}

int open_packet_socket(unsigned int interface_index, bool nonblocking, int &error_number)
{
    const int descriptor = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (descriptor < 0) {
        error_number = errno;
        return -1;
    }
    sockaddr_ll address{};
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = static_cast<int>(interface_index);
    if (::bind(descriptor, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        error_number = errno;
        (void)::close(descriptor);
        return -1;
    }
    if (nonblocking) {
        const int flags = ::fcntl(descriptor, F_GETFL, 0);
        if (flags < 0 || ::fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
            error_number = errno;
            (void)::close(descriptor);
            return -1;
        }
    }
    error_number = 0;
    return descriptor;
}

} // namespace

LinuxTransport::~LinuxTransport() noexcept
{
    close();
}

TransportResult LinuxTransport::open(const TransportConfig &config)
{
    close();
    if (config.interface_name.empty()) {
        return transport_failure(TransportStatus::InvalidConfiguration, 0, "interface name is required");
    }
    const unsigned int interface_index = if_nametoindex(config.interface_name.c_str());
    if (interface_index == 0U) {
        return system_failure(TransportStatus::InterfaceNotFound, errno, "if_nametoindex");
    }
    int error_number = 0;
    const int descriptor = open_packet_socket(interface_index, config.nonblocking, error_number);
    if (descriptor < 0) {
        return system_failure(socket_error_status(error_number), error_number, "AF_PACKET transport open");
    }
    file_descriptor_.reset(descriptor);
    configuration_ = config;
    return transport_success();
}

TransportResult LinuxTransport::send(std::span<const std::uint8_t> frame)
{
    if (!is_open()) {
        return transport_failure(TransportStatus::NotOpen, 0, "transport is not open");
    }
    if (frame.empty()) {
        return transport_failure(TransportStatus::InvalidConfiguration, 0, "frame must not be empty");
    }
    const int flags = configuration_.nonblocking ? MSG_DONTWAIT : 0;
    const ssize_t sent = ::send(file_descriptor_.get(), frame.data(), frame.size(), flags);
    if (sent < 0) {
        return system_failure(TransportStatus::SendFailed, errno, "AF_PACKET send");
    }
    if (static_cast<std::size_t>(sent) != frame.size()) {
        return transport_failure(TransportStatus::SendFailed, 0, "AF_PACKET send was partial");
    }
    return transport_success();
}

void LinuxTransport::close() noexcept
{
    file_descriptor_.reset();
    configuration_ = TransportConfig{};
}

bool LinuxTransport::is_open() const noexcept
{
    return file_descriptor_.get() >= 0;
}

int LinuxTransport::file_descriptor() const noexcept
{
    return file_descriptor_.get();
}

const TransportConfig &LinuxTransport::configuration() const noexcept
{
    return configuration_;
}

TransportCapabilities LinuxTransport::detect_capabilities(std::string_view interface_name)
{
    TransportCapabilities capabilities;
    if (interface_name.empty()) {
        return capabilities;
    }
    const unsigned int interface_index = if_nametoindex(std::string{interface_name}.c_str());
    if (interface_index == 0U) {
        return capabilities;
    }
    int error_number = 0;
    const int descriptor = open_packet_socket(interface_index, true, error_number);
    if (descriptor < 0) {
        return capabilities;
    }
    capabilities.can_capture = true;
    capabilities.can_inject = true;
    (void)::close(descriptor);
    return capabilities;
}

} // namespace skan::net
