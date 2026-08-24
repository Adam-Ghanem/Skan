#include "osdetect/os_types.hpp"

namespace skan::osdetect {

const char *observation_state_name(ObservationState state) noexcept
{
    switch (state) {
    case ObservationState::Absent:
        return "ABSENT";
    case ObservationState::Observed:
        return "OBSERVED";
    case ObservationState::Invalid:
        return "INVALID";
    case ObservationState::TimedOut:
        return "TIMED_OUT";
    case ObservationState::Unsupported:
        return "UNSUPPORTED";
    default:
        return "UNKNOWN";
    }
}

const char *timestamp_behavior_name(TimestampBehavior behavior) noexcept
{
    switch (behavior) {
    case TimestampBehavior::Unknown:
        return "UNKNOWN";
    case TimestampBehavior::Absent:
        return "ABSENT";
    case TimestampBehavior::Present:
        return "PRESENT";
    case TimestampBehavior::EchoesPeer:
        return "ECHOES_PEER";
    case TimestampBehavior::Monotonic:
        return "MONOTONIC";
    default:
        return "UNKNOWN";
    }
}

const char *ack_behavior_name(AckBehavior behavior) noexcept
{
    switch (behavior) {
    case AckBehavior::Unknown:
        return "UNKNOWN";
    case AckBehavior::NoAck:
        return "NO_ACK";
    case AckBehavior::AcknowledgesSyn:
        return "ACKNOWLEDGES_SYN";
    case AckBehavior::AcknowledgesPayload:
        return "ACKNOWLEDGES_PAYLOAD";
    case AckBehavior::RstWithoutAck:
        return "RST_WITHOUT_ACK";
    default:
        return "UNKNOWN";
    }
}

const char *sequence_behavior_name(SequenceBehavior behavior) noexcept
{
    switch (behavior) {
    case SequenceBehavior::Unknown:
        return "UNKNOWN";
    case SequenceBehavior::Zero:
        return "ZERO";
    case SequenceBehavior::Incremental:
        return "INCREMENTAL";
    case SequenceBehavior::Randomized:
        return "RANDOMIZED";
    case SequenceBehavior::TimeBased:
        return "TIME_BASED";
    default:
        return "UNKNOWN";
    }
}

const char *response_behavior_name(ResponseBehavior behavior) noexcept
{
    switch (behavior) {
    case ResponseBehavior::Unknown:
        return "UNKNOWN";
    case ResponseBehavior::SynAck:
        return "SYN_ACK";
    case ResponseBehavior::Rst:
        return "RST";
    case ResponseBehavior::EchoReply:
        return "ECHO_REPLY";
    case ResponseBehavior::PortUnreachable:
        return "PORT_UNREACHABLE";
    case ResponseBehavior::NoResponse:
        return "NO_RESPONSE";
    case ResponseBehavior::Malformed:
        return "MALFORMED";
    default:
        return "UNKNOWN";
    }
}

} // namespace skan::osdetect
