#include "net/linux_capture.hpp"

#include <cerrno>
#include <cstring>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

namespace skan::net {
namespace {

constexpr std::size_t kMaximumFrameSize = 65535U;

CaptureResult system_failure(CaptureStatus status, int error_number, const char *operation)
{
    return capture_failure(status, error_number, std::string{operation} + ": " + std::strerror(error_number));
}

CaptureStatus socket_error_status(int error_number) noexcept
{
    if (error_number == EACCES || error_number == EPERM) {
        return CaptureStatus::PermissionDenied;
    }
    return CaptureStatus::SystemError;
}

} // namespace

LinuxCapture::~LinuxCapture() noexcept
{
    close();
}

CaptureResult LinuxCapture::open(const CaptureConfig &config)
{
    close();
    if (config.interface_name.empty() || config.max_frame_size == 0U ||
        config.max_frame_size > kMaximumFrameSize) {
        return capture_failure(CaptureStatus::InvalidConfiguration, 0, "invalid capture configuration");
    }
    const unsigned int interface_index = if_nametoindex(config.interface_name.c_str());
    if (interface_index == 0U) {
        const int error_number = errno == 0 ? ENODEV : errno;
        return system_failure(CaptureStatus::InterfaceNotFound, error_number, "if_nametoindex");
    }
    const int descriptor = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (descriptor < 0) {
        return system_failure(socket_error_status(errno), errno, "AF_PACKET capture socket");
    }
    sockaddr_ll address{};
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = static_cast<int>(interface_index);
    if (::bind(descriptor, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        const int error_number = errno;
        (void)::close(descriptor);
        return system_failure(socket_error_status(error_number), error_number, "AF_PACKET capture bind");
    }
    if (config.nonblocking) {
        const int flags = ::fcntl(descriptor, F_GETFL, 0);
        if (flags < 0 || ::fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
            const int error_number = errno;
            (void)::close(descriptor);
            return system_failure(CaptureStatus::SystemError, error_number, "AF_PACKET capture nonblocking");
        }
    }
    file_descriptor_.reset(descriptor);
    configuration_ = config;
    return capture_success(0U);
}

CaptureResult LinuxCapture::receive(std::span<std::uint8_t> buffer)
{
    if (!is_open()) {
        return capture_failure(CaptureStatus::NotOpen, 0, "capture is not open");
    }
    if (buffer.empty()) {
        return capture_failure(CaptureStatus::BufferTooSmall, 0, "receive buffer is empty");
    }
    iovec vector{};
    vector.iov_base = buffer.data();
    vector.iov_len = buffer.size();
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1U;
    const int flags = MSG_TRUNC | (configuration_.nonblocking ? MSG_DONTWAIT : 0);
    const ssize_t received = ::recvmsg(file_descriptor_.get(), &message, flags);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return capture_failure(CaptureStatus::WouldBlock, errno, "capture would block");
        }
        if (errno == EINTR) {
            return capture_failure(CaptureStatus::WouldBlock, errno, "capture interrupted");
        }
        return system_failure(CaptureStatus::ReceiveFailed, errno, "AF_PACKET receive");
    }
    if (received == 0) {
        return capture_failure(CaptureStatus::Empty, 0, "capture returned an empty frame");
    }
    const std::size_t frame_size = static_cast<std::size_t>(received);
    if (frame_size > configuration_.max_frame_size || frame_size > buffer.size()) {
        CaptureResult result = capture_failure(CaptureStatus::OversizedFrame, 0, "captured frame exceeds configured buffer");
        result.bytes_received = frame_size;
        return result;
    }
    return capture_success(frame_size);
}

void LinuxCapture::close() noexcept
{
    file_descriptor_.reset();
    configuration_ = CaptureConfig{};
}

bool LinuxCapture::is_open() const noexcept
{
    return file_descriptor_.get() >= 0;
}

int LinuxCapture::file_descriptor() const noexcept
{
    return file_descriptor_.get();
}

const CaptureConfig &LinuxCapture::configuration() const noexcept
{
    return configuration_;
}

} // namespace skan::net
