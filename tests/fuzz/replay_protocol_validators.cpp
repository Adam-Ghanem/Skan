#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "detect/protocol_validators.hpp"

// Deterministic mutation replay with installed, valid requests. This is not a
// replacement for coverage-guided fuzzing or live interoperability testing.
int main(int argc, char **argv)
{
    using namespace skan::detect;
    skan::core::StatusCode status{};
    const auto database = ServiceProbeDatabase::load_file("data/service-probes.db", status);
    if (status != skan::core::StatusCode::Ok || argc != 2)
        return 1;
    std::ifstream input(argv[1]);
    if (!input)
        return 1;
    std::size_t cases = 0U;
    std::string row;
    while (std::getline(input, row))
    {
        if (row.empty() || row.starts_with('#'))
            continue;
        std::vector<std::string> fields;
        std::stringstream columns(row);
        std::string field;
        while (std::getline(columns, field, '\t'))
            fields.push_back(field);
        if (fields.size() != 8U || fields[3].size() > 16384U || fields[3].size() % 2U)
            return 1;
        const ServiceProbeDefinition *probe = nullptr;
        for (const auto &p : database.probes())
            if (p.name == fields[2])
                probe = &p;
        if (!probe)
            return 1;
        std::set<std::string> families;
        for (const auto &rule : probe->rules)
            if (has_exchange_validator(rule.service) || has_api_validator(rule.service))
                families.insert(rule.service);
        if (families.empty())
            continue;
        std::string seed;
        for (std::size_t p = 0U; p < fields[3].size(); p += 2U)
            seed.push_back(static_cast<char>(std::stoul(fields[3].substr(p, 2U), nullptr, 16)));
        const auto replay = [&](std::string_view bytes)
        {
            for (bool terminal : {false, true})
            {
                const auto http = parse_http_response(bytes, terminal);
                for (const auto &family : families)
                {
                    if (has_api_validator(family))
                        (void)parse_api_identity(family, probe->payload, http);
                    else
                        (void)validate_exchange(family, *probe, bytes, terminal);
                }
            }
            ++cases;
        };
        replay(seed);
        for (std::size_t n = 0U; n < seed.size(); ++n)
            replay(std::string_view{seed}.substr(0U, n));
        for (std::size_t p = 0U; p < seed.size(); ++p)
        {
            auto mutated = seed;
            for (unsigned int b = 0U; b <= 255U; ++b)
            {
                mutated[p] = static_cast<char>(b);
                replay(mutated);
            }
        }
        replay(std::string(8193U, 'x'));
    }
    if (!input.eof() || !cases)
        return 1;
    std::cout << cases << " deterministic protocol replays passed\n";
}
