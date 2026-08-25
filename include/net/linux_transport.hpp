#ifndef SKAN_NET_LINUX_TRANSPORT_HPP
#define SKAN_NET_LINUX_TRANSPORT_HPP

#include <span>
#include <cstdint>

#include "net/transport.hpp"
#include "net/unique_fd.hpp"

namespace skan::net {

class LinuxTransport final : public Transport {
public:
    LinuxTransport() noexcept = default;
    ~LinuxTransport() noexcept override;

    TransportResult open(const TransportConfig &config) override;
    TransportResult send(std::span<const std::uint8_t> frame) override;
    void close() noexcept override;
    bool is_open() const noexcept override;

    int file_descriptor() const noexcept;
    const TransportConfig &configuration() const noexcept;

    static TransportCapabilities detect_capabilities(std::string_view interface_name);

private:
    detail::UniqueFd file_descriptor_;
    TransportConfig configuration_;
};

} // namespace skan::net

#endif // SKAN_NET_LINUX_TRANSPORT_HPP
