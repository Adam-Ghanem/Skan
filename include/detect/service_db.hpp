#ifndef SKAN_DETECT_SERVICE_DB_HPP
#define SKAN_DETECT_SERVICE_DB_HPP

#include <cstddef>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include "core/status.hpp"
#include "detect/service_types.hpp"

namespace skan::detect {

enum class ServiceMatchType {
    Prefix = 0,
    Substring,
    Regex
};

struct ServiceMatchRule final {
    ServiceMatchType type{ServiceMatchType::Prefix};
    std::string pattern;
    std::string service;
    std::string product;
    std::string version;
    std::string extra;
    double confidence{0.0};
    std::size_t specificity{0U};
    std::optional<std::regex> compiled_regex;
};

struct ServiceProbeDefinition final {
    std::string id;
    std::string name;
    TransportProtocol protocol{TransportProtocol::Tcp};
    unsigned int rarity{1U};
    std::vector<DetectionPort> port_hints;
    std::string payload;
    std::vector<ServiceMatchRule> rules;
};

class ServiceProbeDatabase final {
public:
    ServiceProbeDatabase() = default;

    static ServiceProbeDatabase built_in();
    static ServiceProbeDatabase parse(std::string_view text, core::StatusCode &status);
    static ServiceProbeDatabase load_file(const std::string &path, core::StatusCode &status);

    const std::vector<ServiceProbeDefinition> &probes() const noexcept;
    core::StatusCode status() const noexcept;

    /** Return up to max_count probes, ordered by port hint, rarity, and declaration order. */
    std::vector<std::size_t> ordered_probe_indices(
        const DetectionPort &port,
        std::size_t max_count) const;

private:
    core::StatusCode status_{core::StatusCode::Ok};
    std::vector<ServiceProbeDefinition> probes_;
};

const char *service_match_type_name(ServiceMatchType type) noexcept;

} // namespace skan::detect

#endif // SKAN_DETECT_SERVICE_DB_HPP
