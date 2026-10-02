#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include "detect/protocol_parsers.hpp"

// Deterministic sanitizer replay, not a substitute for coverage-guided fuzzing.
int main(int argc, char **argv)
{
    std::size_t cases = 0U;
    const auto replay = [&](std::string_view bytes) {
        for (bool terminal : {false, true}) {
            const auto http = skan::detect::parse_http_response(bytes, terminal);
            (void)skan::detect::parse_search_identity(http.body);
            (void)skan::detect::parse_zookeeper_srvr(bytes, terminal);
        }
        (void)skan::detect::parse_search_identity(bytes);
        ++cases;
    };
    for (int arg = 1; arg < argc; ++arg) {
        std::ifstream input(argv[arg], std::ios::binary);
        if (!input) return 1;
        const std::string seed{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
        if (seed.size() > 8192U) return 1;
        replay(seed);
        for (std::size_t length = 0U; length < seed.size(); ++length) replay(std::string_view{seed}.substr(0U, length));
        for (std::size_t pos = 0U; pos < seed.size(); ++pos) {
            std::string mutated = seed;
            for (unsigned int byte = 0U; byte <= 255U; ++byte) {
                mutated[pos] = static_cast<char>(byte);
                replay(mutated);
            }
        }
    }
    replay(std::string(8193U, 'x'));
    std::cout << cases << " deterministic parser replays passed\n";
}
