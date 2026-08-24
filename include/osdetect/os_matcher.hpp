#ifndef SKAN_OSDETECT_OS_MATCHER_HPP
#define SKAN_OSDETECT_OS_MATCHER_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "db/os_db.hpp"
#include "osdetect/os_types.hpp"

namespace skan::osdetect {

inline constexpr double kNoMatchThreshold = 0.30;
inline constexpr double kLowConfidenceThreshold = 0.60;
inline constexpr double kPossibleMatchThreshold = 0.85;

enum class OSDetectionState : std::uint8_t {
    NotRun = 0,
    Running,
    Complete,
    Partial,
    Unavailable,
    Failed
};

enum class OSDetectionError : std::uint8_t {
    None = 0,
    InvalidTarget,
    NoUsablePort,
    CapabilityUnavailable,
    Timeout,
    MalformedResponse,
    UnsupportedProbe,
    TransportFailure,
    InternalError
};

struct OSMatchResult final {
    std::string fingerprint_name;
    std::string vendor;
    std::string family;
    std::string generation;
    std::string device_type;
    double confidence{0.0};
    db::MatchCategory category{db::MatchCategory::NoMatch};
    std::vector<std::string> matched_fields;
    std::vector<std::string> mismatched_fields;
    std::vector<std::string> unavailable_fields;
};

struct OSDetectionResult final {
    std::string target;
    OSDetectionState state{OSDetectionState::NotRun};
    std::string vendor;
    std::string family;
    std::string generation;
    std::string device_type;
    double confidence{0.0};
    std::optional<db::MatchCategory> category;
    std::vector<OSMatchResult> matches;
    ObservedOSFingerprint observed;
    std::size_t probes_generated{0U};
    std::size_t probes_sent{0U};
    std::size_t responses_received{0U};
    std::size_t probes_timed_out{0U};
    std::size_t probes_unsupported{0U};
    std::size_t probes_malformed{0U};
    std::optional<double> rtt_ms;
    OSDetectionError error{OSDetectionError::None};
    std::chrono::steady_clock::time_point timestamp{};
};

const char *os_detection_state_name(OSDetectionState state) noexcept;
const char *os_detection_error_name(OSDetectionError error) noexcept;

class OSMatcher final {
public:
    explicit OSMatcher(const db::OSFingerprintDatabase &database) noexcept;

    std::vector<OSMatchResult> match(
        const ObservedOSFingerprint &observed,
        std::size_t max_results = 3U) const;

private:
    const db::OSFingerprintDatabase &database_;
};

} // namespace skan::osdetect

#endif // SKAN_OSDETECT_OS_MATCHER_HPP
