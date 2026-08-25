#ifndef SKAN_PORTSCAN_PORT_RESULT_HPP
#define SKAN_PORTSCAN_PORT_RESULT_HPP

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>

#include "portscan/port_types.hpp"

namespace skan::portscan {

using PortScanClock = std::chrono::steady_clock;
using PortScanTimePoint = PortScanClock::time_point;

struct PortResult final {
    std::string target;
    Port port;
    PortState state{PortState::Unknown};
    ScanProbeType probe{ScanProbeType::TcpConnect};
    ScanReason reason{ScanReason::InternalError};
    std::optional<double> rtt_ms;
    PortScanTimePoint timestamp{};
    std::size_t retry_count{0U};
    std::optional<std::string> probe_name;
};

const char *port_result_state_name(PortState state) noexcept;

} // namespace skan::portscan

#endif // SKAN_PORTSCAN_PORT_RESULT_HPP
