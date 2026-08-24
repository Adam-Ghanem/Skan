#include "db/db_types.hpp"

namespace skan::db {

const char *fingerprint_field_name(FingerprintField field) noexcept
{
    switch (field) {
    case FingerprintField::Ttl:
        return "TTL";
    case FingerprintField::DontFragment:
        return "DF";
    case FingerprintField::Window:
        return "WINDOW";
    case FingerprintField::Mss:
        return "MSS";
    case FingerprintField::WindowScale:
        return "WSCALE";
    case FingerprintField::SackPermitted:
        return "SACK";
    case FingerprintField::Timestamps:
        return "TIMESTAMP";
    case FingerprintField::TcpOptions:
        return "TCP_OPTIONS";
    case FingerprintField::TcpFlags:
        return "TCP_FLAGS";
    case FingerprintField::AckBehavior:
        return "ACK_BEHAVIOR";
    case FingerprintField::SequenceBehavior:
        return "SEQUENCE_BEHAVIOR";
    case FingerprintField::ResponseBehavior:
        return "RESPONSE_BEHAVIOR";
    case FingerprintField::IcmpTtl:
        return "ICMP_TTL";
    case FingerprintField::IcmpType:
        return "ICMP_TYPE";
    case FingerprintField::IcmpCode:
        return "ICMP_CODE";
    default:
        return "UNKNOWN";
    }
}

const char *match_category_name(MatchCategory category) noexcept
{
    switch (category) {
    case MatchCategory::NoMatch:
        return "NO_MATCH";
    case MatchCategory::LowConfidence:
        return "LOW_CONFIDENCE";
    case MatchCategory::PossibleMatch:
        return "POSSIBLE_MATCH";
    case MatchCategory::StrongMatch:
        return "STRONG_MATCH";
    default:
        return "NO_MATCH";
    }
}

} // namespace skan::db
