#ifndef SKAN_DETECT_SERVICE_MATCHER_HPP
#define SKAN_DETECT_SERVICE_MATCHER_HPP

#include <cstddef>
#include <string>
#include <string_view>

#include "detect/service_db.hpp"

namespace skan::detect {

struct ServiceMatchResult final {
    bool matched{false};
    std::string service;
    std::string product;
    std::string version;
    std::string extra;
    double confidence{0.0};
    std::size_t specificity{0U};
    std::size_t rule_index{0U};
};

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
