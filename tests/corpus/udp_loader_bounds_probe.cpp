#include <cstddef>
#include <iostream>
#include <string>

#include "core/status.hpp"
#include "portscan/udp_scan.hpp"

namespace {
constexpr std::size_t kMaximumDatabaseBytes = 1U << 20U;

int fail(const char *message)
{
    std::cerr << "udp loader bounds probe: " << message << '\n';
    return 1;
}
} // namespace

int main(int argc, char **argv)
{
    using skan::core::StatusCode;
    using skan::portscan::UDPProbeDatabase;

    if (argc != 3) {
        return fail("usage: udp_loader_bounds_probe OVERSIZED VALID");
    }

    std::string oversized = "probe DEFAULT 0 generic 512 00\n#";
    oversized.append(kMaximumDatabaseBytes, 'x');
    StatusCode status = StatusCode::InternalError;
    const auto parsed = UDPProbeDatabase::parse(oversized, status);
    if (status != StatusCode::ParseError || !parsed.definitions().empty()) {
        return fail("direct parse accepted an oversized database");
    }

    status = StatusCode::InternalError;
    const auto oversized_file = UDPProbeDatabase::load_file(argv[1], status);
    if (status != StatusCode::ParseError || !oversized_file.definitions().empty()) {
        return fail("file loader accepted an oversized database");
    }

    status = StatusCode::InternalError;
    const auto valid = UDPProbeDatabase::load_file(argv[2], status);
    if (status != StatusCode::Ok || valid.definitions().size() != 1U ||
        valid.default_probe().name != "DEFAULT") {
        return fail("bounded loader rejected a valid database");
    }

    status = StatusCode::InternalError;
    const auto missing = UDPProbeDatabase::load_file("/definitely/not/a/skan/udp/database", status);
    if (status != StatusCode::NotFound || !missing.definitions().empty()) {
        return fail("missing-file status contract changed");
    }

    return 0;
}
