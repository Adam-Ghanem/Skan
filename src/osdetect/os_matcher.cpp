#include "osdetect/os_matcher.hpp"

#include <algorithm>
#include <new>
#include <string_view>

namespace skan::osdetect {
namespace {

struct Evidence final {
    bool available{false};
    bool matches{false};
    const char *name{"UNKNOWN"};
};

constexpr double weight_for(db::FingerprintField field) noexcept
{
    switch (field) {
    case db::FingerprintField::Ttl:
        return 0.10;
    case db::FingerprintField::DontFragment:
        return 0.05;
    case db::FingerprintField::Window:
        return 0.15;
    case db::FingerprintField::Mss:
        return 0.10;
    case db::FingerprintField::WindowScale:
        return 0.10;
    case db::FingerprintField::SackPermitted:
        return 0.10;
    case db::FingerprintField::Timestamps:
        return 0.10;
    case db::FingerprintField::TcpOptions:
        return 0.20;
    case db::FingerprintField::TcpFlags:
        return 0.05;
    case db::FingerprintField::AckBehavior:
        return 0.05;
    case db::FingerprintField::SequenceBehavior:
        return 0.05;
    case db::FingerprintField::ResponseBehavior:
        return 0.10;
    case db::FingerprintField::IcmpTtl:
        return 0.05;
    case db::FingerprintField::IcmpType:
        return 0.02;
    case db::FingerprintField::IcmpCode:
        return 0.02;
    case db::FingerprintField::UdpPayloadLength:
        return 0.08;
    case db::FingerprintField::UdpResponseBehavior:
        return 0.08;
    case db::FingerprintField::ResponsePresence:
        return 0.05;
    default:
        return 0.0;
    }
}

const TCPObservation *first_tcp(const ObservedOSFingerprint &observed) noexcept
{
    for (const TCPObservation &observation : observed.tcp_observations) {
        if (observation.probe_status == OSProbeStatus::ResponseReceived) {
            return &observation;
        }
    }
    return nullptr;
}

const UDPObservation *first_udp(const ObservedOSFingerprint &observed) noexcept
{
    for (const UDPObservation &observation : observed.udp_observations) {
        if (observation.probe_status == OSProbeStatus::ResponseReceived) {
            return &observation;
        }
    }
    return nullptr;
}

bool matches_number(const db::FingerprintSignature &signature, std::int64_t value) noexcept
{
    if (signature.number.has_value()) {
        return value == *signature.number;
    }
    if (signature.minimum.has_value() && signature.maximum.has_value()) {
        return value >= *signature.minimum && value <= *signature.maximum;
    }
    return false;
}

const ICMPObservation *first_icmp(const ObservedOSFingerprint &observed) noexcept
{
    for (const ICMPObservation &observation : observed.icmp_observations) {
        if (observation.probe_status == OSProbeStatus::ResponseReceived) {
            return &observation;
        }
    }
    return nullptr;
}

Evidence compare(const db::FingerprintSignature &signature, const ObservedOSFingerprint &observed) noexcept
{
    const TCPObservation *tcp = first_tcp(observed);
    const ICMPObservation *icmp = first_icmp(observed);
    Evidence evidence{false, false, db::fingerprint_field_name(signature.field)};
    switch (signature.field) {
    case db::FingerprintField::Ttl:
        if (tcp != nullptr && tcp->ttl.state == ObservationState::Observed && (signature.number.has_value() || (signature.minimum.has_value() && signature.maximum.has_value()))) {
            evidence.available = true;
            evidence.matches = matches_number(signature, static_cast<std::int64_t>(tcp->ttl.value));
        }
        break;
    case db::FingerprintField::DontFragment:
        if (tcp != nullptr && tcp->dont_fragment.state == ObservationState::Observed && signature.boolean.has_value()) {
            evidence.available = true;
            evidence.matches = tcp->dont_fragment.value == *signature.boolean;
        }
        break;
    case db::FingerprintField::Window:
        if (tcp != nullptr && tcp->window.state == ObservationState::Observed && (signature.number.has_value() || (signature.minimum.has_value() && signature.maximum.has_value()))) {
            evidence.available = true;
            evidence.matches = matches_number(signature, static_cast<std::int64_t>(tcp->window.value));
        }
        break;
    case db::FingerprintField::Mss:
        if (tcp != nullptr && tcp->mss.state == ObservationState::Observed && (signature.number.has_value() || (signature.minimum.has_value() && signature.maximum.has_value()))) {
            evidence.available = true;
            evidence.matches = matches_number(signature, static_cast<std::int64_t>(tcp->mss.value));
        }
        break;
    case db::FingerprintField::WindowScale:
        if (tcp != nullptr && tcp->window_scale.state == ObservationState::Observed && (signature.number.has_value() || (signature.minimum.has_value() && signature.maximum.has_value()))) {
            evidence.available = true;
            evidence.matches = matches_number(signature, static_cast<std::int64_t>(tcp->window_scale.value));
        }
        break;
    case db::FingerprintField::SackPermitted:
        if (tcp != nullptr && tcp->sack_permitted.state == ObservationState::Observed && signature.boolean.has_value()) {
            evidence.available = true;
            evidence.matches = tcp->sack_permitted.value == *signature.boolean;
        }
        break;
    case db::FingerprintField::Timestamps:
        if (tcp != nullptr && tcp->timestamps.state == ObservationState::Observed && signature.boolean.has_value()) {
            evidence.available = true;
            evidence.matches = tcp->timestamps.value == *signature.boolean;
        }
        break;
    case db::FingerprintField::TcpOptions:
        if (tcp != nullptr && !tcp->options.empty() && !signature.options.empty()) {
            evidence.available = true;
            evidence.matches = tcp->options == signature.options;
        }
        break;
    case db::FingerprintField::TcpFlags:
        if (tcp != nullptr && tcp->probe_status == OSProbeStatus::ResponseReceived && (signature.number.has_value() || (signature.minimum.has_value() && signature.maximum.has_value()))) {
            evidence.available = true;
            evidence.matches = matches_number(signature, static_cast<std::int64_t>(tcp->flags));
        }
        break;
    case db::FingerprintField::AckBehavior:
        if (tcp != nullptr && tcp->ack_behavior != AckBehavior::Unknown) {
            evidence.available = true;
            evidence.matches = ack_behavior_name(tcp->ack_behavior) == signature.text;
        }
        break;
    case db::FingerprintField::SequenceBehavior:
        if (tcp != nullptr && tcp->sequence_behavior != SequenceBehavior::Unknown) {
            evidence.available = true;
            evidence.matches = sequence_behavior_name(tcp->sequence_behavior) == signature.text;
        }
        break;
    case db::FingerprintField::ResponseBehavior:
        if (tcp != nullptr && tcp->response_behavior != ResponseBehavior::Unknown) {
            evidence.available = true;
            evidence.matches = response_behavior_name(tcp->response_behavior) == signature.text;
        }
        break;
    case db::FingerprintField::IcmpTtl:
        if (icmp != nullptr && icmp->ttl.state == ObservationState::Observed && (signature.number.has_value() || (signature.minimum.has_value() && signature.maximum.has_value()))) {
            evidence.available = true;
            evidence.matches = matches_number(signature, static_cast<std::int64_t>(icmp->ttl.value));
        }
        break;
    case db::FingerprintField::IcmpType:
        if (icmp != nullptr && icmp->type.state == ObservationState::Observed && (signature.number.has_value() || (signature.minimum.has_value() && signature.maximum.has_value()))) {
            evidence.available = true;
            evidence.matches = matches_number(signature, static_cast<std::int64_t>(icmp->type.value));
        }
        break;
    case db::FingerprintField::IcmpCode:
        if (icmp != nullptr && icmp->code.state == ObservationState::Observed &&
            (signature.number.has_value() || (signature.minimum.has_value() && signature.maximum.has_value()))) {
            evidence.available = true;
            evidence.matches = matches_number(signature, static_cast<std::int64_t>(icmp->code.value));
        }
        break;
    case db::FingerprintField::UdpPayloadLength:
        if (const UDPObservation *udp = first_udp(observed); udp != nullptr &&
            udp->payload_length.state == ObservationState::Observed &&
            (signature.number.has_value() || (signature.minimum.has_value() && signature.maximum.has_value()))) {
            evidence.available = true;
            evidence.matches = matches_number(signature, static_cast<std::int64_t>(udp->payload_length.value));
        }
        break;
    case db::FingerprintField::UdpResponseBehavior:
        if (const UDPObservation *udp = first_udp(observed); udp != nullptr &&
            udp->response_behavior != ResponseBehavior::Unknown && !signature.text.empty()) {
            evidence.available = true;
            evidence.matches = response_behavior_name(udp->response_behavior) == signature.text;
        }
        break;
    case db::FingerprintField::ResponsePresence:
        if (signature.boolean.has_value()) {
            evidence.available = true;
            const bool response_present = observed.responses_received > 0U || !observed.tcp_observations.empty() ||
                                          !observed.icmp_observations.empty() || !observed.udp_observations.empty();
            evidence.matches = response_present == *signature.boolean;
        }
        break;
    }
    return evidence;
}

} // namespace

OSMatcher::OSMatcher(const db::OSFingerprintDatabase &database) noexcept : database_(database)
{
}

std::vector<OSMatchResult> OSMatcher::match(
    const ObservedOSFingerprint &observed,
    std::size_t max_results) const
{
    std::vector<OSMatchResult> results;
    try {
        for (const db::OSFingerprint &fingerprint : database_.fingerprints()) {
            OSMatchResult result;
            result.fingerprint_name = fingerprint.name;
            result.vendor = fingerprint.vendor;
            result.family = fingerprint.family;
            result.generation = fingerprint.generation;
            result.device_type = fingerprint.device_type;
            double available_weight = 0.0;
            double matched_weight = 0.0;
            for (const db::FingerprintSignature &signature : fingerprint.signatures) {
                const Evidence evidence = compare(signature, observed);
                const std::string field_name = db::fingerprint_field_name(signature.field);
                if (!evidence.available) {
                    result.unavailable_fields.push_back(field_name);
                    continue;
                }
                available_weight += weight_for(signature.field);
                if (evidence.matches) {
                    matched_weight += weight_for(signature.field);
                    result.matched_fields.push_back(field_name);
                } else {
                    result.mismatched_fields.push_back(field_name);
                }
            }
            result.confidence = available_weight == 0.0 ? 0.0 : matched_weight / available_weight;
            if (result.confidence < kNoMatchThreshold) {
                result.category = db::MatchCategory::NoMatch;
            } else if (result.confidence < kLowConfidenceThreshold) {
                result.category = db::MatchCategory::LowConfidence;
            } else if (result.confidence < kPossibleMatchThreshold) {
                result.category = db::MatchCategory::PossibleMatch;
            } else {
                result.category = db::MatchCategory::StrongMatch;
            }
            results.push_back(std::move(result));
        }
        std::sort(results.begin(), results.end(), [](const OSMatchResult &left, const OSMatchResult &right) {
            if (left.confidence != right.confidence) {
                return left.confidence > right.confidence;
            }
            return left.fingerprint_name < right.fingerprint_name;
        });
        if (results.size() > max_results) {
            results.resize(max_results);
        }
    } catch (const std::bad_alloc &) {
        results.clear();
    }
    return results;
}

const char *os_detection_state_name(OSDetectionState state) noexcept
{
    switch (state) {
    case OSDetectionState::NotRun:
        return "not-run";
    case OSDetectionState::Running:
        return "running";
    case OSDetectionState::Complete:
        return "complete";
    case OSDetectionState::Partial:
        return "partial";
    case OSDetectionState::Unavailable:
        return "unavailable";
    case OSDetectionState::Failed:
        return "failed";
    }
    return "unknown";
}

const char *os_detection_error_name(OSDetectionError error) noexcept
{
    switch (error) {
    case OSDetectionError::None:
        return "none";
    case OSDetectionError::InvalidTarget:
        return "invalid-target";
    case OSDetectionError::NoUsablePort:
        return "no-usable-port";
    case OSDetectionError::CapabilityUnavailable:
        return "capability-unavailable";
    case OSDetectionError::Timeout:
        return "timeout";
    case OSDetectionError::MalformedResponse:
        return "malformed-response";
    case OSDetectionError::UnsupportedProbe:
        return "unsupported-probe";
    case OSDetectionError::TransportFailure:
        return "transport-failure";
    case OSDetectionError::InternalError:
        return "internal-error";
    }
    return "unknown";
}

} // namespace skan::osdetect
