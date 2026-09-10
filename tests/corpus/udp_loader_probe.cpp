#include <cstddef>
#include <iostream>
#include <string>

#include "core/status.hpp"
#include "portscan/udp_scan.hpp"

namespace {

bool equivalent(
    const skan::portscan::UDPProbeDefinition &left,
    const skan::portscan::UDPProbeDefinition &right)
{
    return left.name == right.name &&
           left.destination_port == right.destination_port &&
           left.payload == right.payload &&
           left.max_response_bytes == right.max_response_bytes &&
           left.protocol_hint == right.protocol_hint;
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 3) {
        std::cerr << "usage: udp_loader_probe LEGACY_DB GENERATED_DB\n";
        return 64;
    }

    skan::core::StatusCode legacy_status = skan::core::StatusCode::InternalError;
    skan::core::StatusCode generated_status = skan::core::StatusCode::InternalError;
    const auto legacy = skan::portscan::UDPProbeDatabase::load_file(argv[1], legacy_status);
    const auto generated = skan::portscan::UDPProbeDatabase::load_file(argv[2], generated_status);
    if (legacy_status != skan::core::StatusCode::Ok ||
        generated_status != skan::core::StatusCode::Ok) {
        std::cerr << "loader rejected an input database\n";
        return 2;
    }
    if (legacy.definitions().size() != generated.definitions().size()) {
        std::cerr << "definition count mismatch\n";
        return 3;
    }

    for (std::size_t index = 0; index < legacy.definitions().size(); ++index) {
        if (!equivalent(legacy.definitions()[index], generated.definitions()[index])) {
            std::cerr << "definition mismatch at index " << index << '\n';
            return 4;
        }
    }

    const auto &legacy_default = legacy.default_probe();
    const auto &generated_default = generated.default_probe();
    if (!equivalent(legacy_default, generated_default)) {
        std::cerr << "default probe mismatch\n";
        return 5;
    }

    for (const auto &definition : legacy.definitions()) {
        if (definition.destination_port == 0U) {
            continue;
        }
        const auto *left = legacy.for_port(definition.destination_port);
        const auto *right = generated.for_port(definition.destination_port);
        if (left == nullptr || right == nullptr || !equivalent(*left, *right)) {
            std::cerr << "port index mismatch for " << definition.destination_port << '\n';
            return 6;
        }
    }

    return 0;
}
