#include <cstddef>
#include <iostream>
#include <string>

#include "core/status.hpp"
#include "portscan/udp_scan.hpp"

namespace {

constexpr std::size_t kMaximumDatabaseBytes = 1U << 20U;
constexpr char kValidPrefix[] = "probe DEFAULT 0 generic 512 00\n#";

bool failed(
    const char *contract,
    skan::core::StatusCode actual,
    skan::core::StatusCode expected,
    std::size_t definitions,
    std::size_t expected_definitions)
{
    if (actual == expected && definitions == expected_definitions) {
        return false;
    }
    std::cerr << contract << " failed: status=" << static_cast<int>(actual)
              << " expected_status=" << static_cast<int>(expected)
              << " definitions=" << definitions
              << " expected_definitions=" << expected_definitions << '\n';
    return true;
}

std::string database_with_size(std::size_t size)
{
    std::string text{kValidPrefix};
    if (text.size() < size) {
        text.append(size - text.size(), 'x');
    }
    return text;
}

} // namespace

int main(int argc, char **argv)
{
    using skan::core::StatusCode;
    using skan::portscan::UDPProbeDatabase;

    if (argc != 4) {
        std::cerr << "usage: udp_loader_bounds_probe OVERSIZED_DB VALID_DB MISSING_DB\n";
        return 64;
    }

    StatusCode status = StatusCode::InternalError;
    const auto exact = UDPProbeDatabase::parse(database_with_size(kMaximumDatabaseBytes), status);
    if (failed("exact-size direct input", status, StatusCode::Ok, exact.definitions().size(), 1U)) {
        return 1;
    }

    status = StatusCode::InternalError;
    const auto direct = UDPProbeDatabase::parse(database_with_size(kMaximumDatabaseBytes + 1U), status);
    if (failed("oversized direct input", status, StatusCode::ParseError, direct.definitions().size(), 0U)) {
        return 2;
    }

    status = StatusCode::InternalError;
    const auto file = UDPProbeDatabase::load_file(argv[1], status);
    if (failed("oversized file input", status, StatusCode::ParseError, file.definitions().size(), 0U)) {
        return 3;
    }

    status = StatusCode::InternalError;
    const auto valid = UDPProbeDatabase::load_file(argv[2], status);
    if (failed("valid file input", status, StatusCode::Ok, valid.definitions().size(), 1U) ||
        valid.default_probe().name != "DEFAULT") {
        return 4;
    }

    status = StatusCode::InternalError;
    const auto missing = UDPProbeDatabase::load_file(argv[3], status);
    if (failed("missing file input", status, StatusCode::NotFound, missing.definitions().size(), 0U)) {
        return 5;
    }

    return 0;
}
