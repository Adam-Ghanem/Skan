#ifndef SKAN_DETECT_SERVICE_MATCHER_HPP
#define SKAN_DETECT_SERVICE_MATCHER_HPP

#include <cstddef>
#include <string>
#include <string_view>

#include "detect/service_db.hpp"
#include "detect/tls_metadata.hpp"

namespace skan::detect {

struct ServiceMatchResult final {
    bool matched{false};
    std::string service;
    std::string product;
    std::string version;
    std::string extra;
    std::string hostname;
    std::string tunnel;
    ServiceMatchStrength strength{ServiceMatchStrength::Hard};
    TlsMetadata tls;
    double confidence{0.0};
    std::size_t priority{0U};
    std::size_t specificity{0U};
    std::size_t rule_index{0U};
};

/**
 * Compare two matched results using the canonical evidence ordering.
 * Complete ties preserve the incumbent so probe ordering remains deterministic.
 */
bool service_match_is_better(
    const ServiceMatchResult &candidate,
    const ServiceMatchResult &incumbent) noexcept;

/** Return whether a match is strong enough to publish as a detected service. */
bool service_match_is_publishable(const ServiceMatchResult &match) noexcept;

class ServiceMatcher final {
public:
    explicit ServiceMatcher(const ServiceProbeDatabase &database) noexcept;

    ServiceMatchResult match(
        const ServiceProbeDefinition &probe,
        std::string_view response) const;

private:
    const ServiceProbeDatabase &database_;
};

} // namespace skan::detect

#endif // SKAN_DETECT_SERVICE_MATCHER_HPP
