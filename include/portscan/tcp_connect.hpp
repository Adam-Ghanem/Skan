#ifndef SKAN_PORTSCAN_TCP_CONNECT_HPP
#define SKAN_PORTSCAN_TCP_CONNECT_HPP

#include <memory>
#include <unordered_map>

#include "io/event.hpp"
#include "portscan/port_probe.hpp"

namespace skan::portscan {

class TcpConnectProbe final : public PortProbe {
public:
    ScanProbeType type() const noexcept override;
    core::StatusCode build(
        PortProbeId id,
        const core::Host &target,
        const Port &port,
        const PortScanConfig &config,
        PortSubmission &submission) const override;
    PortState timeout_state() const noexcept override;
    ScanReason timeout_reason() const noexcept override;
    core::StatusCode assess(
        const PortResponse &response,
        const PortSubmission &submission,
        PortState &state,
        ScanReason &reason) const override;
};

class TcpConnectTransport final : public PortScanTransport {
public:
    explicit TcpConnectTransport(io::IOEngine &engine) noexcept;
    ~TcpConnectTransport() override;

    TcpConnectTransport(const TcpConnectTransport &) = delete;
    TcpConnectTransport &operator=(const TcpConnectTransport &) = delete;

    bool supports(ScanProbeType probe) const noexcept override;
    core::StatusCode submit(
        const PortSubmission &submission, PortResponseCallback callback) override;
    core::StatusCode cancel(PortProbeId id) noexcept override;

private:
    struct Connection;

    void on_event(PortProbeId id) noexcept;
    void finish(PortProbeId id, PortResponseKind kind, int system_error) noexcept;
    void reap_completed() noexcept;
    void close_connection(Connection &connection, bool retain_event = false) noexcept;

    io::IOEngine &engine_;
    std::unordered_map<PortProbeId, std::unique_ptr<Connection>> connections_;
};

} // namespace skan::portscan

#endif // SKAN_PORTSCAN_TCP_CONNECT_HPP
