#ifndef SKAN_DETECT_SERVICE_TYPES_HPP
#define SKAN_DETECT_SERVICE_TYPES_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/status.hpp"
#include "core/types.hpp"
#include "portscan/port_result.hpp"
#include "portscan/port_types.hpp"

namespace skan::detect {

using DetectionClock = std::chrono::steady_clock;
using DetectionTimePoint = DetectionClock::time_point;
using TransportProtocol = portscan::Protocol;
using DetectionPort = portscan::Port;
using DetectionPortState = portscan::PortState;

enum class DetectionState {
    Detected = 0,
    Unknown,
    Timeout,
    ConnectionClosed,
    ResponseTooLarge,
    InvalidTarget,
    Error
};

enum class DetectionError {
    None = 0,
    Timeout,
    ConnectionClosed,
    ResponseTooLarge,
    InvalidTarget,
    TransportFailure,
    MalformedResponse,
    NoMatch,
    UnsupportedProtocol,
    InternalError
};

enum class DetectionMethod {
    Banner = 0,
    Probe,
    Unknown
};

struct ServiceResult final {
    std::string target;
    DetectionPort port;
    TransportProtocol protocol{TransportProtocol::Tcp};
    DetectionPortState port_state{DetectionPortState::Unknown};
    DetectionState state{DetectionState::Unknown};
    std::string service;
    std::string product;
    std::string version;
    std::string extra;
    double confidence{0.0};
    DetectionMethod method{DetectionMethod::Unknown};
    std::string probe_name;
    std::optional<double> rtt_ms;
    DetectionError error{DetectionError::None};
    DetectionTimePoint timestamp{};
};

struct ServiceDetectionConfig final {
    std::size_t max_outstanding{16U};
    std::chrono::milliseconds timeout{1000};
    std::size_t max_response_bytes{8192U};
    std::size_t max_probes_per_port{2U};
};

struct ServiceDetectionSelection final {
    core::StatusCode status{core::StatusCode::Ok};
    std::vector<DetectionPort> ports;
};

const char *detection_state_name(DetectionState state) noexcept;
const char *detection_error_name(DetectionError error) noexcept;
const char *detection_method_name(DetectionMethod method) noexcept;

bool service_result_less(const ServiceResult &left, const ServiceResult &right) noexcept;

} // namespace skan::detect

#endif // SKAN_DETECT_SERVICE_TYPES_HPP
