#include <array>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

#include "detect/service_matcher.hpp"

// Offline, truth-labeled regression microbenchmark, not broker/network speed.
// Keep this workload identical when comparing two engine revisions.
// correct_identity means correct protocol classification AND no invented
// product/version, including correct negative observations. It does not grade
// typed evidence, which is checked separately by the regression suite.
int main()
{
    using namespace skan::detect;
    skan::core::StatusCode status = skan::core::StatusCode::InternalError;
    const auto database = ServiceProbeDatabase::load_file("data/service-probes.db", status);
    if (status != skan::core::StatusCode::Ok) return EXIT_FAILURE;
    const ServiceProbeDefinition *probe = nullptr;
    for (const auto &candidate : database.probes()) {
        if (candidate.name == "MQTTConnect") probe = &candidate;
    }
    if (probe == nullptr) return EXIT_FAILURE;
    struct Case { std::string bytes; bool mqtt; };
    const std::array<Case, 10U> cases{{
        {std::string{"\x20\x02\x00\x00", 4U}, true},
        {std::string{"\x20\x02\x00\x01", 4U}, true},
        {std::string{"\x20\x02\x00\x05", 4U}, true},
        {std::string{"\x20\x02", 2U}, false},
        {std::string{"\x20\x02\x00", 3U}, false},
        {std::string{"\x20\x02\x0a\x00", 4U}, false},
        {std::string{"\x20\x02\x01\x00", 4U}, false},
        {std::string{"\x20\x02\x00\x06", 4U}, false},
        {std::string{"\x20\x03\x00\x00", 4U}, false},
        {"HTTP/1.1 200 OK\r\n\r\n", false}
    }};
    const ServiceMatcher matcher(database);
    constexpr std::size_t iterations = 10000U;
    std::cout << "sample,observations,correct_protocol,false_positive,false_negative,correct_identity,seconds,accurate_results_per_second\n";
    for (unsigned int sample = 0U; sample < 5U; ++sample) {
        std::size_t correct = 0U, false_positive = 0U, false_negative = 0U, identity = 0U;
        const auto start = std::chrono::steady_clock::now();
        for (std::size_t iteration = 0U; iteration < iterations; ++iteration) {
            for (const auto &fixture : cases) {
                const auto result = matcher.match(*probe, fixture.bytes);
                const bool detected = result.matched && result.service == "mqtt";
                correct += detected == fixture.mqtt;
                false_positive += detected && !fixture.mqtt;
                false_negative += !detected && fixture.mqtt;
                identity += detected == fixture.mqtt && result.product.empty() && result.version.empty();
            }
        }
        const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        if (seconds <= 0.0) return EXIT_FAILURE;
        std::cout << sample << ',' << iterations * cases.size() << ',' << correct << ','
                  << false_positive << ',' << false_negative << ',' << identity << ','
                  << std::setprecision(9) << seconds << ',' << static_cast<double>(identity) / seconds << '\n';
    }
}
