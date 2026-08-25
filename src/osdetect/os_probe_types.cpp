#include "osdetect/os_probe_types.hpp"

namespace skan::osdetect {

const char *os_probe_type_name(OSProbeType type) noexcept
{
    switch (type) {
    case OSProbeType::TcpSynStandard:
        return "TCP_SYN_STANDARD";
    case OSProbeType::TcpSynVariant:
        return "TCP_SYN_VARIANT";
    case OSProbeType::TcpSynTimestamp:
        return "TCP_SYN_TIMESTAMP";
    case OSProbeType::TcpEcn:
        return "TCP_ECN";
    case OSProbeType::TcpAck:
        return "TCP_ACK";
    case OSProbeType::TcpFin:
        return "TCP_FIN";
    case OSProbeType::TcpNull:
        return "TCP_NULL";
    case OSProbeType::TcpXmas:
        return "TCP_XMAS";
    case OSProbeType::TcpClosedStandard:
        return "TCP_CLOSED_STANDARD";
    case OSProbeType::TcpClosedVariant:
        return "TCP_CLOSED_VARIANT";
    case OSProbeType::IcmpEcho:
        return "ICMP_ECHO";
    case OSProbeType::UdpFingerprint:
        return "UDP_FINGERPRINT";
    default:
        return "UNKNOWN";
    }
}

const char *os_probe_status_name(OSProbeStatus status) noexcept
{
    switch (status) {
    case OSProbeStatus::Generated:
        return "GENERATED";
    case OSProbeStatus::Sent:
        return "SENT";
    case OSProbeStatus::ResponseReceived:
        return "RESPONSE_RECEIVED";
    case OSProbeStatus::Timeout:
        return "TIMEOUT";
    case OSProbeStatus::Unsupported:
        return "UNSUPPORTED";
    case OSProbeStatus::Malformed:
        return "MALFORMED";
    default:
        return "UNKNOWN";
    }
}

const char *os_probe_response_kind_name(OSProbeResponseKind kind) noexcept
{
    switch (kind) {
    case OSProbeResponseKind::Data:
        return "DATA";
    case OSProbeResponseKind::Closed:
        return "CLOSED";
    case OSProbeResponseKind::IcmpError:
        return "ICMP_ERROR";
    case OSProbeResponseKind::Error:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

} // namespace skan::osdetect
