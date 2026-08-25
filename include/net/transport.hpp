#ifndef SKAN_NET_TRANSPORT_HPP
#define SKAN_NET_TRANSPORT_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "net/transport_types.hpp"

namespace skan::net {

class Transport {
public:
    virtual ~Transport() = default;

    virtual TransportResult open(const TransportConfig &config) = 0;
    virtual TransportResult send(std::span<const std::uint8_t> frame) = 0;
    virtual void close() noexcept = 0;
    virtual bool is_open() const noexcept = 0;
};

class RecordingTransport final : public Transport {
public:
    TransportResult open(const TransportConfig &config) override;
    TransportResult send(std::span<const std::uint8_t> frame) override;
    void close() noexcept override;
    bool is_open() const noexcept override;

    const std::vector<std::vector<std::uint8_t>> &frames() const noexcept;
    std::size_t frame_count() const noexcept;
    void clear_frames() noexcept;

private:
    bool open_{false};
    std::vector<std::vector<std::uint8_t>> frames_;
};

class NullTransport final : public Transport {
public:
    TransportResult open(const TransportConfig &config) override;
    TransportResult send(std::span<const std::uint8_t> frame) override;
    void close() noexcept override;
    bool is_open() const noexcept override;

    std::size_t send_count() const noexcept;

private:
    bool open_{false};
    std::size_t send_count_{0U};
};

} // namespace skan::net

#endif // SKAN_NET_TRANSPORT_HPP
