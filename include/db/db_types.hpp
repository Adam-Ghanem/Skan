#ifndef SKAN_DB_DB_TYPES_HPP
#define SKAN_DB_DB_TYPES_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "osdetect/os_types.hpp"
#include "packet/tcp.hpp"

namespace skan::db {

enum class FingerprintField : std::uint8_t {
    Ttl = 0,
    DontFragment,
    Window,
    Mss,
    WindowScale,
    SackPermitted,
    Timestamps,
    TcpOptions,
    TcpFlags,
    AckBehavior,
    SequenceBehavior,
    ResponseBehavior,
    IcmpTtl,
    IcmpType,
    IcmpCode
};

struct FingerprintSignature final {
    FingerprintField field{FingerprintField::Ttl};
    std::optional<std::int64_t> number;
    std::optional<bool> boolean;
    std::string text;
    std::vector<packet::TcpOptionKind> options;
};

struct OSFingerprint final {
    std::string name;
    std::string vendor;
    std::string family;
    std::string generation;
    std::string device_type;
    std::vector<FingerprintSignature> signatures;
};

enum class MatchCategory : std::uint8_t {
    NoMatch = 0,
    LowConfidence,
    PossibleMatch,
    StrongMatch
};

const char *fingerprint_field_name(FingerprintField field) noexcept;
const char *match_category_name(MatchCategory category) noexcept;

} // namespace skan::db

#endif // SKAN_DB_DB_TYPES_HPP
