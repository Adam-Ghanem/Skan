#include <array>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>

#include "detect/service_matcher.hpp"

// Identical synthetic observations for baseline/current. Counts measure these
// fixtures only, not captured-service accuracy or end-to-end network speed.
int main()
{
    using namespace skan::detect;
    skan::core::StatusCode status{};
    const auto db = ServiceProbeDatabase::load_file("data/service-probes.db", status);
    if (status != skan::core::StatusCode::Ok) return 1;
    struct Case { std::string_view probe, response, service, product, version; };
    const std::array<Case, 12U> cases{{
        {"HTTPGet", "HTTP/1.1 200 OK\r\nsErVeR: nginx/1.26.2\r\n\r\n", "http", "nginx", "1.26.2"},
        {"HTTPGet", "HTTP/1.1 200 OK\r\n\r\nServer: nginx/9.9\r\n", "http", "", ""},
        {"HTTPGet", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"n\",\"cluster_name\":\"c\",\"version\":{\"number\":\"8.13.4\"},\"tagline\":\"You Know, for Search\"}", "elasticsearch", "Elasticsearch", "8.13.4"},
        {"HTTPGet", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"n\",\"cluster_name\":\"c\",\"version\":{\"number\":\"2.16.0\",\"distribution\":\"opensearch\"},\"tagline\":\"The OpenSearch Project: https://opensearch.org/\"}", "opensearch", "OpenSearch", "2.16.0"},
        {"HTTPGet", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"number\":\"8.13.4\",\"tagline\":\"You Know, for Search\"}", "http", "", ""},
        {"HTTPGet", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"n\",\"cluster_name\":\"c\",\"version\":{\"number\":\"8.13.4\"},\"tagline\":\"You Know, for Search\",}", "http", "", ""},
        {"HTTPGet", "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n\r\n{\"name\":\"n\",\"cluster_name\":\"c\",\"version\":{\"number\":\"8.13.4\"},\"tagline\":\"You Know, for Search\"}", "http", "", ""},
        {"HTTPGet", "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", "", "", ""},
        {"HTTPGet", "HTTP/1.1 200 OK\r\n", "", "", ""},
        {"ZooKeeperServer", "Zookeeper version: 3.9.5-build, built on date\nLatency min/avg/max: 0/1/2\nReceived: 10\nSent: 9\nConnections: 1\nOutstanding: 0\nZxid: 0x1\nMode: follower\nNode count: 42\n", "zookeeper", "Apache-ZooKeeper", "3.9.5-build"},
        {"ZooKeeperServer", "Zookeeper version: 3.9.5\nMode: follower\n", "", "", ""},
        {"ZooKeeperServer", "Zookeeper version: 3.9.5\nMode: followerish\nNode count: 42\n", "", "", ""}
    }};
    std::array<const ServiceProbeDefinition *, cases.size()> probes{};
    for (std::size_t i = 0U; i < cases.size(); ++i) {
        for (const auto &p : db.probes()) if (p.name == cases[i].probe) probes[i] = &p;
        if (probes[i] == nullptr) return 1;
    }
    const ServiceMatcher matcher(db);
    constexpr std::size_t iterations = 1000U;
    std::cout << "sample,observations,correct_protocol,false_positive,false_negative,correct_identity,seconds,accurate_results_per_second\n";
    for (unsigned int sample = 0U; sample < 5U; ++sample) {
        std::size_t correct = 0U, fp = 0U, fn = 0U, identities = 0U;
        const auto start = std::chrono::steady_clock::now();
        for (std::size_t iteration = 0U; iteration < iterations; ++iteration) {
            for (std::size_t i = 0U; i < cases.size(); ++i) {
                const auto &fixture = cases[i];
                const auto m = matcher.match(*probes[i], fixture.response);
                const bool protocol = m.service == fixture.service;
                correct += protocol;
                fp += !protocol && m.matched;
                fn += !protocol && !fixture.service.empty();
                identities += protocol && m.product == fixture.product && m.version == fixture.version;
            }
        }
        const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        if (seconds <= 0.0) return 1;
        std::cout << sample << ',' << iterations * cases.size() << ',' << correct << ',' << fp << ',' << fn << ','
            << identities << ',' << std::setprecision(9) << seconds << ',' << static_cast<double>(identities) / seconds << '\n';
    }
}
