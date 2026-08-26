#ifndef SKAN_DETECT_SERVICE_PROBE_HPP
#define SKAN_DETECT_SERVICE_PROBE_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/status.hpp"
#include "core/types.hpp"
#include "detect/service_db.hpp"
#include "detect/service_types.hpp"
#include "io/event.hpp"
#include "io/io_engine.hpp"

namespace skan::detect {

using ServiceProbeId = std::uint64_t;
struct ServiceResponse;
using ServiceResponseCallback = std::function<void(const ServiceResponse &)>;

enum class ServiceResponseKind {
    Data = 0,
    Closed,
    SocketError
};

struct ServiceSubmission final {
    ServiceProbeId id{0U};
    std::string target;
    DetectionPort port;
    std::string probe_id;
    std::string probe_name;
    std::string payload;
    std::size_t max_response_bytes{8192U};
    core::IpAddress target_ip{};
};

struct ServiceResponse final {
    ServiceProbeId id{0U};
    std::string source_address;
    ServiceResponseKind kind{ServiceResponseKind::Data};
    int system_error{0};
    std::vector<std::uint8_t> bytes;
    bool response_truncated{false};
    DetectionTimePoint received_at{};
};

class ServiceTransport {
public:
    virtual ~ServiceTransport() = default;

    virtual core::StatusCode submit(
        const ServiceSubmission &submission,
        ServiceResponseCallback callback) = 0;
    virtual bool supports(TransportProtocol protocol) const noexcept
    {
        return protocol == TransportProtocol::Tcp || protocol == TransportProtocol::Udp;
    }
    virtual core::StatusCode cancel(ServiceProbeId id) noexcept = 0;
};

class RecordingServiceTransport final : public ServiceTransport {
public:
    core::StatusCode submit(
        const ServiceSubmission &submission,
        ServiceResponseCallback callback) override;
    core::StatusCode cancel(ServiceProbeId id) noexcept override;

    const std::vector<ServiceSubmission> &submissions() const noexcept;
    void deliver(const ServiceResponse &response);
    void clear() noexcept;

private:
    std::vector<ServiceSubmission> submissions_;
    std::unordered_map<ServiceProbeId, ServiceResponseCallback> callbacks_;
};

class ServiceTcpTransport final : public ServiceTransport {
public:
    explicit ServiceTcpTransport(io::IOEngine &engine) noexcept;
    ~ServiceTcpTransport() override;

    ServiceTcpTransport(const ServiceTcpTransport &) = delete;
    ServiceTcpTransport &operator=(const ServiceTcpTransport &) = delete;

    core::StatusCode submit(
        const ServiceSubmission &submission,
        ServiceResponseCallback callback) override;
    bool supports(TransportProtocol protocol) const noexcept override;
    core::StatusCode cancel(ServiceProbeId id) noexcept override;

private:
    struct Connection;

    void on_event(ServiceProbeId id) noexcept;
    void on_writable(ServiceProbeId id) noexcept;
    void on_readable(ServiceProbeId id) noexcept;
    void emit(ServiceProbeId id, ServiceResponseKind kind, const std::uint8_t *bytes,
              std::size_t byte_count, bool truncated, int system_error) noexcept;
    void cleanup(Connection &connection, bool retain_event = false) noexcept;
    void reap_completed() noexcept;

    io::IOEngine &engine_;
    std::unordered_map<ServiceProbeId, std::unique_ptr<Connection>> connections_;
};

class ServiceUdpTransport final : public ServiceTransport {
public:
    explicit ServiceUdpTransport(io::IOEngine &engine) noexcept;
    ~ServiceUdpTransport() override;

    ServiceUdpTransport(const ServiceUdpTransport &) = delete;
    ServiceUdpTransport &operator=(const ServiceUdpTransport &) = delete;

    core::StatusCode submit(
        const ServiceSubmission &submission,
        ServiceResponseCallback callback) override;
    bool supports(TransportProtocol protocol) const noexcept override;
    core::StatusCode cancel(ServiceProbeId id) noexcept override;

private:
    struct Datagram;

    void on_event(ServiceProbeId id) noexcept;
    void emit(ServiceProbeId id, ServiceResponseKind kind, const std::uint8_t *bytes,
              std::size_t byte_count, bool truncated, int system_error) noexcept;
    void cleanup(Datagram &datagram) noexcept;

    io::IOEngine &engine_;
    std::unordered_map<ServiceProbeId, std::unique_ptr<Datagram>> datagrams_;
};

class ServiceTransportRouter final : public ServiceTransport {
public:
    explicit ServiceTransportRouter(io::IOEngine &engine) noexcept;
    ~ServiceTransportRouter() override = default;

    ServiceTransportRouter(const ServiceTransportRouter &) = delete;
    ServiceTransportRouter &operator=(const ServiceTransportRouter &) = delete;

    core::StatusCode submit(
        const ServiceSubmission &submission,
        ServiceResponseCallback callback) override;
    bool supports(TransportProtocol protocol) const noexcept override;
    core::StatusCode cancel(ServiceProbeId id) noexcept override;

private:
    io::IOEngine &engine_;
    ServiceTcpTransport tcp_;
    ServiceUdpTransport udp_;
    std::unordered_map<ServiceProbeId, TransportProtocol> routes_;
};

class ServiceProbe final {
public:
    ServiceProbe(const ServiceProbeDefinition &definition, std::size_t max_response_bytes) noexcept;

    const ServiceProbeDefinition &definition() const noexcept;
    core::StatusCode build(
        ServiceProbeId id,
        const core::Host &target,
        const DetectionPort &port,
        ServiceSubmission &submission) const;
    core::StatusCode assess(
        const ServiceResponse &response,
        const ServiceSubmission &submission,
        std::string &bounded_response,
        DetectionError &error) const;

private:
    const ServiceProbeDefinition &definition_;
    std::size_t max_response_bytes_;
};

} // namespace skan::detect

#endif // SKAN_DETECT_SERVICE_PROBE_HPP
