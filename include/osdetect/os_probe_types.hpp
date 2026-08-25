#ifndef SKAN_OSDETECT_OS_PROBE_TYPES_HPP
#define SKAN_OSDETECT_OS_PROBE_TYPES_HPP

#include <cstdint>

namespace skan::osdetect {

enum class OSProbeType : std::uint8_t {
    TcpSynStandard = 0,
    TcpSynVariant,
    TcpSynTimestamp,
    TcpEcn,
    TcpAck,
    TcpFin,
    TcpNull,
    TcpXmas,
    TcpClosedStandard,
    TcpClosedVariant,
    IcmpEcho,
    UdpFingerprint,
    UdpPortUnreachable = UdpFingerprint
};

enum class OSProbeStatus : std::uint8_t {
    Generated = 0,
    Sent,
    ResponseReceived,
    Timeout,
    Unsupported,
    Malformed
};

enum class OSProbeResponseKind : std::uint8_t {
    Data = 0,
    Closed,
    IcmpError,
    Error
};

const char *os_probe_type_name(OSProbeType type) noexcept;
const char *os_probe_status_name(OSProbeStatus status) noexcept;
const char *os_probe_response_kind_name(OSProbeResponseKind kind) noexcept;

} // namespace skan::osdetect

#endif // SKAN_OSDETECT_OS_PROBE_TYPES_HPP
