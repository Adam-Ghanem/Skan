#include <iostream>
#include <string>

#include "detect/service_db.hpp"

namespace {

bool same_rule(
    const skan::detect::ServiceMatchRule &left,
    const skan::detect::ServiceMatchRule &right)
{
    return left.type == right.type && left.pattern == right.pattern &&
           left.service == right.service && left.product == right.product &&
           left.version == right.version && left.extra == right.extra &&
           left.hostname == right.hostname && left.tunnel == right.tunnel &&
           left.strength == right.strength && left.confidence == right.confidence &&
           left.specificity == right.specificity &&
           left.compiled_regex.has_value() == right.compiled_regex.has_value();
}

bool same_probe(
    const skan::detect::ServiceProbeDefinition &left,
    const skan::detect::ServiceProbeDefinition &right)
{
    if (left.id != right.id || left.name != right.name ||
        left.protocol != right.protocol || left.rarity != right.rarity ||
        left.priority != right.priority || left.timeout != right.timeout ||
        left.port_hints != right.port_hints ||
        left.fallback_probe_names != right.fallback_probe_names ||
        left.payload != right.payload || left.rules.size() != right.rules.size()) {
        return false;
    }
    for (std::size_t index = 0U; index < left.rules.size(); ++index) {
        if (!same_rule(left.rules[index], right.rules[index])) {
            return false;
        }
    }
    return true;
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 3) {
        std::cerr << "usage: service_loader_probe LEGACY GENERATED\n";
        return 2;
    }

    skan::core::StatusCode legacy_status = skan::core::StatusCode::InternalError;
    skan::core::StatusCode generated_status = skan::core::StatusCode::InternalError;
    const auto legacy = skan::detect::ServiceProbeDatabase::load_file(argv[1], legacy_status);
    const auto generated = skan::detect::ServiceProbeDatabase::load_file(argv[2], generated_status);
    if (legacy_status != skan::core::StatusCode::Ok ||
        generated_status != skan::core::StatusCode::Ok) {
        std::cerr << "loader rejected an input corpus\n";
        return 3;
    }
    if (legacy.probes().size() != generated.probes().size()) {
        std::cerr << "probe count mismatch\n";
        return 4;
    }
    for (std::size_t index = 0U; index < legacy.probes().size(); ++index) {
        if (!same_probe(legacy.probes()[index], generated.probes()[index])) {
            std::cerr << "probe semantic mismatch at index " << index << " ("
                      << legacy.probes()[index].name << ")\n";
            return 5;
        }
    }
    return 0;
}
