#ifndef SKAN_PORTSCAN_PORT_PROBE_HPP
#define SKAN_PORTSCAN_PORT_PROBE_HPP

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/status.hpp"
#include "core/types.hpp"
#include "io/io_engine.hpp"
#include "portscan/port_result.hpp"

namespace skan::portscan {

using PortProbeId = std::uint64_t;

struct PortResponse;

enum class PortResponseKind {
    Connected = 0,
    ConnectionRefused,
    SocketError,
    Packet
};

struct PortSubmission final {
    PortProbeId id{0U};
    ScanProbeType probe{ScanProbeType::TcpConnect};
    std::string target;
    Port port;
    std::vector<std::uint8_t> packet;
    std::uint16_t source_port{0U};
    std::uint32_t sequence_number{0U};
};

using PortResponseCallback = std::function<void(const PortResponse &)>;

struct PortResponse final {
    PortProbeId id{0U};
    std::string source_address;
    PortResponseKind kind{PortResponseKind::Packet};
    int system_error{0};
    std::vector<std::uint8_t> bytes;
    PortScanTimePoint received_at{};
};

class PortScanTransport {
public:
    virtual ~PortScanTransport() = default;

    virtual bool supports(ScanProbeType probe) const noexcept = 0;
    virtual core::StatusCode submit(
        const PortSubmission &submission, PortResponseCallback callback) = 0;
    virtual core::StatusCode cancel(PortProbeId id) noexcept = 0;
};

class RecordingPortScanTransport final : public PortScanTransport {
public:
    bool supports(ScanProbeType probe) const noexcept override;
    core::StatusCode submit(
        const PortSubmission &submission, PortResponseCallback callback) override;
    core::StatusCode cancel(PortProbeId id) noexcept override;

    const std::vector<PortSubmission> &submissions() const noexcept;
    void deliver(const PortResponse &response);
    void clear() noexcept;

private:
    std::vector<PortSubmission> submissions_;
    std::unordered_map<PortProbeId, PortResponseCallback> callbacks_;
};

class PortProbe {
public:
    virtual ~PortProbe() = default;

    virtual ScanProbeType type() const noexcept = 0;
    virtual core::StatusCode build(
        PortProbeId id,
        const core::Host &target,
        const Port &port,
        const PortScanConfig &config,
        PortSubmission &submission) const = 0;
    virtual PortState timeout_state() const noexcept = 0;
    virtual ScanReason timeout_reason() const noexcept = 0;
    virtual core::StatusCode assess(
        const PortResponse &response,
        const PortSubmission &submission,
        PortState &state,
        ScanReason &reason) const = 0;
};

} // namespace skan::portscan

#endif // SKAN_PORTSCAN_PORT_PROBE_HPP
