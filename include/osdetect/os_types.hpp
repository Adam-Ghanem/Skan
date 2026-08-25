#ifndef SKAN_OSDETECT_OS_TYPES_HPP
#define SKAN_OSDETECT_OS_TYPES_HPP

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/types.hpp"
#include "osdetect/os_probe_types.hpp"
#include "packet/tcp.hpp"

namespace skan::osdetect {

enum class ObservationState : std::uint8_t {
    Absent = 0,
    Observed,
    Invalid,
    TimedOut,
    Unsupported,
    Malformed
};

template <typename T>
struct ObservedValue final {
    ObservationState state{ObservationState::Absent};
    T value{};

    static ObservedValue observed(T observed_value)
    {
        return {ObservationState::Observed, observed_value};
    }

    static ObservedValue absent() noexcept
    {
        return {};
    }
};

enum class TimestampBehavior : std::uint8_t {
    Unknown = 0,
    Absent,
    Present,
    EchoesPeer,
    Monotonic
};

enum class AckBehavior : std::uint8_t {
    Unknown = 0,
    NoAck,
    AcknowledgesSyn,
    AcknowledgesPayload,
    RstWithoutAck
};

enum class SequenceBehavior : std::uint8_t {
    Unknown = 0,
    Zero,
    Incremental,
    Randomized,
    TimeBased
};

enum class ResponseBehavior : std::uint8_t {
    Unknown = 0,
    SynAck,
    Rst,
    EchoReply,
    UdpResponse,
    PortUnreachable,
    NoResponse,
    Malformed
};

struct TCPObservation final {
    std::string source_address;
    std::string destination_address;
    std::uint16_t source_port{0U};
    std::uint16_t destination_port{0U};
    ObservedValue<std::uint8_t> ttl;
    ObservedValue<bool> dont_fragment;
    ObservedValue<std::uint16_t> window;
    ObservedValue<std::uint16_t> mss;
    ObservedValue<std::uint8_t> window_scale;
    ObservedValue<bool> sack_permitted;
    ObservedValue<bool> timestamps;
    TimestampBehavior timestamp_behavior{TimestampBehavior::Unknown};
    std::vector<packet::TcpOptionKind> options;
    std::uint16_t flags{0U};
    AckBehavior ack_behavior{AckBehavior::Unknown};
    SequenceBehavior sequence_behavior{SequenceBehavior::Unknown};
    ObservedValue<std::uint32_t> sequence_number;
    ObservedValue<std::uint32_t> acknowledgment_number;
    std::size_t payload_length{0U};
    ResponseBehavior response_behavior{ResponseBehavior::Unknown};
    OSProbeStatus probe_status{OSProbeStatus::ResponseReceived};
    core::AddressFamily family{core::AddressFamily::Unknown};
};

struct UDPObservation final {
    std::uint16_t source_port{0U};
    std::uint16_t destination_port{0U};
    ObservedValue<std::size_t> payload_length;
    ObservedValue<std::uint8_t> ttl;
    ObservedValue<std::uint16_t> ip_identification;
    ObservedValue<bool> dont_fragment;
    ResponseBehavior response_behavior{ResponseBehavior::Unknown};
    OSProbeStatus probe_status{OSProbeStatus::ResponseReceived};
    core::AddressFamily family{core::AddressFamily::Unknown};
};

struct ICMPObservation final {
    ObservedValue<std::uint8_t> ttl;
    ObservedValue<std::uint8_t> type;
    ObservedValue<std::uint8_t> code;
    ResponseBehavior response_behavior{ResponseBehavior::Unknown};
    OSProbeStatus probe_status{OSProbeStatus::ResponseReceived};
    core::AddressFamily family{core::AddressFamily::Unknown};
};

struct ObservedOSFingerprint final {
    std::string target;
    std::vector<TCPObservation> tcp_observations;
    std::vector<ICMPObservation> icmp_observations;
    std::vector<UDPObservation> udp_observations;
    std::size_t probes_generated{0U};
    std::size_t probes_sent{0U};
    std::size_t responses_received{0U};
    std::size_t probes_timed_out{0U};
    std::size_t probes_unsupported{0U};
    std::size_t probes_malformed{0U};
    std::optional<double> rtt_ms;
    std::chrono::steady_clock::time_point timestamp{};
    core::AddressFamily family{core::AddressFamily::IPv4};
};

const char *observation_state_name(ObservationState state) noexcept;
const char *timestamp_behavior_name(TimestampBehavior behavior) noexcept;
const char *ack_behavior_name(AckBehavior behavior) noexcept;
const char *sequence_behavior_name(SequenceBehavior behavior) noexcept;
const char *response_behavior_name(ResponseBehavior behavior) noexcept;

} // namespace skan::osdetect

#endif // SKAN_OSDETECT_OS_TYPES_HPP
