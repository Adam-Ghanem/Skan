#include <cassert>
#include <iostream>
#include <string>
#include <string_view>

#include "detect/service_matcher.hpp"
#include "detect/protocol_parsers.hpp"

namespace {
using namespace skan::detect;

const ServiceProbeDefinition &probe(const ServiceProbeDatabase &db, std::string_view name)
{
    for (const auto &p : db.probes()) if (p.name == name) return p;
    assert(false);
    return db.probes().front();
}

std::string http(std::string_view body, std::string_view headers = {})
{
    return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\n" + std::string{headers} + "\r\n" + std::string{body};
}

void http_boundaries(const ServiceProbeDatabase &db)
{
    const ServiceMatcher matcher(db);
    const auto &p = probe(db, "HTTPGet");
    // A Server-looking string in a body is not a response header.
    auto m = matcher.match(p, "HTTP/1.1 200 OK\r\n\r\nServer: nginx/99.9\r\n");
    assert(m.matched && m.service == "http" && m.product.empty() && m.version.empty());
    m = matcher.match(p, "HTTP/1.1 200 OK\r\nsErVeR: nginx/1.26.2\r\n\r\n");
    assert(m.product == "nginx" && m.version == "1.26.2");
    for (const auto bad : {"HTTP/xyz 200 OK\r\n\r\n", "HTTP/1.1 20 OK\r\n\r\n",
        "HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n",
        "HTTP/1.1 200 OK\r\n Server: nginx/99\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n"}) {
        assert(!matcher.match(p, bad).matched);
    }
    m = matcher.match(p, "HTTP/1.1 200 OK\r\nServer: nginx/1.2\r\nServer: Apache/2.4\r\n\r\n");
    assert(m.matched && m.product.empty() && m.version.empty());
    m = matcher.match(p, "HTTP/1.1 200 OK\r\nServer:\r\nServer: nginx/1.2\r\n\r\n");
    assert(m.matched && m.product.empty() && m.version.empty());
    m = matcher.match(p, "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.54.v20240208)\r\n\r\n");
    assert(m.product == "Jetty" && m.version == "9.4.54.v20240208");
    assert(m.evidence && m.evidence->kind == "header" && m.evidence->version_source == "Server");
    assert(matcher.match(p, "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.54.v20240208\r\n\r\n").product.empty());
    assert(!matcher.match(p, std::string(8193U, 'x')).matched);
    m = matcher.match(p, "HTTP/1.1 200 OK\r\nServer: nginx/not-a-version\r\n\r\n");
    assert(m.version.empty());
    // Informational headers cannot contribute a final Server identity.
    m = matcher.match(p, "HTTP/1.1 100 Continue\r\nServer: fake/9.9\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    assert(m.service == "http" && m.product.empty() && m.evidence->status_code == 200U);
    assert(m.evidence->body_complete && m.evidence->protocol_version == "1.1");
    assert(parse_http_response("HTTP/1.1 200 OK\r\nContent-Length: 999999999999999999999999\r\n\r\n", true).state == HttpParseState::Malformed);
    assert(!matcher.match(p, "HTTP/1.1 200 OK\r\nX: " + std::string(4096U, 'a') + "\r\n\r\n").matched);
}

void search_structure(const ServiceProbeDatabase &db)
{
    const ServiceMatcher matcher(db);
    const auto &p = probe(db, "HTTPGet");
    const std::string es = R"({"name":"node","cluster_name":"lab","version":{"number":"8.13.4"},"tagline":"You Know, for Search"})";
    const std::string os = R"({"tagline":"The OpenSearch Project: https://opensearch.org/","version":{"number":"2.16.0","distribution":"opensearch"},"cluster_name":"lab","name":"node"})";
    auto m = matcher.match(p, http(os));
    assert(m.service == "opensearch" && m.product == "OpenSearch" && m.version == "2.16.0");
    m = matcher.match(p, http(es));
    assert(m.service == "elasticsearch" && m.version == "8.13.4");
    for (const auto collision : {
        R"({"number":"8.13.4","tagline":"You Know, for Search"})",
        R"({"version":{"number":"8.13.4"},"tagline":"You Know, for Search"})",
        R"({"name":"n","cluster_name":"c","version":{"number":8.13},"tagline":"You Know, for Search"})",
        R"({"name":"n","cluster_name":"c","version":{"number":"8.13.4","number":"9.0.0"},"tagline":"You Know, for Search"})",
        R"({"name":"n","cluster_name":"c","version":{"number":"8.13.4"},"tagline":"You Know, for Search","tagline":"other"})",
        R"({"name":"n","cluster_name":"c","version":{"number":"8.13.4"},"tagline":"You Know, for Search",})",
        R"({"name":"n","cluster_name":"c","version":{"number":"8.13.4"},"tagline":"You Know, for Search"}junk)",
        R"({"name":"n","cluster_name":"c","version":{"number":"8.13.4","distribution":"opensearch"},"tagline":"You Know, for Search"})",
        R"({"name":"n","cluster_name":"c","version":{"number":"2.16.0","distribution":"opensearch"},"tagline":"other"})",
        R"({"name":"n","cluster_name":"c","version":{"number":"8.13.4"},"tagline":"You Know, for Search","bad":"\q"})"}) {
        m = matcher.match(p, http(collision));
        assert(m.service == "http" && m.product.empty() && m.version.empty());
    }
    m = matcher.match(p, http(es, "Content-Encoding: gzip\r\n"));
    assert(m.service == "http" && m.version.empty());
    auto wrong_request = p;
    wrong_request.payload = "GET /_search HTTP/1.1\r\n\r\n";
    assert(matcher.match(wrong_request, http(es)).service == "http");
    m = matcher.match(p, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" +
        std::string{"6b\r\n"} + es + "\r\n0\r\n\r\n");
    // Independently supplied chunk length is checked below with the exact fixture.
    assert(m.service != "elasticsearch");
    const std::string chunk_body = R"({"name":"n","cluster_name":"c","version":{"number":"8.1.0"},"tagline":"You Know, for Search"})";
    assert(chunk_body.size() == 93U);
    m = matcher.match(p, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n5d\r\n" + chunk_body + "\r\n0\r\n\r\n");
    assert(m.service == "elasticsearch" && m.version == "8.1.0");
    // Header-only matching is provisional while content-length/chunks remain incomplete.
    const auto framed = http(es);
    for (std::size_t n = 0U; n < framed.size(); ++n) {
        m = matcher.match(p, std::string_view{framed}.substr(0U, n), false);
        assert(m.service != "elasticsearch");
    }
    const std::string close_delimited = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + es;
    assert(matcher.match(p, close_delimited, false).service == "http");
    assert(matcher.match(p, close_delimited, true).service == "elasticsearch");
    assert(matcher.match(p, http(es, "Content-Type: text/plain\r\n")).service != "elasticsearch");
    // Duplicate keys are compared after escape decoding, at every object depth.
    for (const auto json : {R"({"name":"n","cluster_name":"c","version":{"number":"8.1.0","\u006eumber":"9.0.0"},"tagline":"You Know, for Search"})",
        R"({"name":"n","cluster_name":"c","version":{"number":"8.1.0"},"tagline":"You Know, for Search","x":NaN})",
        R"({"name":"n","cluster_name":"c","version":{"number":"8.1.0"},"tagline":"You Know, for Search","x":01})",
        R"({"name":"n","cluster_name":"c","version":{"number":"8.1.0"},"tagline":"You Know, for Search","x":"\ud800"})"}) {
        assert(!parse_search_identity(json));
    }
    const std::string unicode = R"({"name":"n\u006f\ud83d\ude00","cluster_name":"c","version":{"number":"8.1.0"},"tagline":"You Know, for Search","unused":[true,false,null,-1.2e+3]})";
    assert(parse_search_identity(unicode)->version == "8.1.0");
    for (const auto &suffix : {std::string{R"(\ud83d\ude00)"}, std::string{"\xf0\x9f\x98\x80"}}) {
        auto bounded = es;
        bounded.replace(bounded.find("node"), 4U, std::string(2044U, 'a') + suffix);
        assert(parse_search_identity(bounded));
        bounded = es;
        bounded.replace(bounded.find("node"), 4U, std::string(2047U, 'a') + suffix);
        assert(!parse_search_identity(bounded));
    }
    auto invalid_utf8 = es;
    invalid_utf8.insert(invalid_utf8.find("node"), 1U, static_cast<char>(0xff));
    assert(!parse_search_identity(invalid_utf8));
    const std::string deeply_nested = "{\"x\":" + std::string(18U, '[') + "0" + std::string(18U, ']') + "}";
    assert(!parse_search_identity(deeply_nested));
    assert(!parse_search_identity(R"({"name":"n","cluster_name":"c","version":{"number":"8..x"},"tagline":"You Know, for Search"})"));
    const auto chunked = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n5d;foo=\"bar\"\r\n" + chunk_body + "\r\n0\r\nX-Trace: ok\r\n\r\n";
    assert(matcher.match(p, chunked).service == "elasticsearch");
    for (std::size_t n = 0U; n < chunked.size(); ++n) {
        assert(matcher.match(p, std::string_view{chunked}.substr(0U, n), false).service != "elasticsearch");
    }
    assert(parse_http_response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx!\r\n0\r\n\r\n", true).state == HttpParseState::Malformed);
    assert(parse_http_response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 0\r\n\r\n", true).state == HttpParseState::Malformed);
}

void zookeeper_lines(const ServiceProbeDatabase &db)
{
    const ServiceMatcher matcher(db);
    const auto &p = probe(db, "ZooKeeperServer");
    const std::string good = "Zookeeper version: 3.9.5-build, built on date\nLatency min/avg/max: 0/1/2\nReceived: 10\nSent: 9\nConnections: 1\nOutstanding: 0\nZxid: 0x1\nMode: follower\nNode count: 42\n";
    auto m = matcher.match(p, good);
    assert(m.service == "zookeeper" && m.version == "3.9.5-build" && m.extra == "mode follower");
    for (const auto bad : {"Zookeeper version: 3.9.5\nMode: follower\n",
        "Zookeeper version: 3.9.5\nhtml Mode: follower\nNode count: 1\n",
        "Zookeeper version: 3.9.5\nMode: followerish\nNode count: 1\n"}) {
        assert(!matcher.match(p, bad).matched);
    }
    for (const auto bad_field : {"Zxid: nope\n", "Zxid:0x1\n", "Received:bad\n",
        "Mode:follower\n", "Latency min/avg/max:0/1/2\n"}) {
        assert(!matcher.match(p, good + bad_field).matched);
    }
    auto uncorrelated = p;
    uncorrelated.payload = "ruok\n";
    assert(!matcher.match(uncorrelated, good).matched);
    assert(!matcher.match(p, good.substr(0U, good.size() - 1U)).matched);
    assert(!matcher.match(p, good + "Mode: leader\n").matched);
    assert(!matcher.match(p, good + "Zookeeper version: 9.9.9\n").matched);
    assert(!matcher.match(p, good + "Zookeeper version: 3.9.5-build\n").matched);
    for (std::size_t n = 0U; n <= good.size(); ++n) assert(!matcher.match(p, std::string_view{good}.substr(0U, n), false).matched);
    auto malformed = good;
    malformed.replace(malformed.find("Received: 10"), 12U, "Received: nope");
    assert(!matcher.match(p, malformed).matched);
}
} // namespace

int main(int argc, char **argv)
{
    skan::core::StatusCode status{};
    const auto db = skan::detect::ServiceProbeDatabase::load_file("data/service-probes.db", status);
    assert(status == skan::core::StatusCode::Ok);
    const std::string_view choice = argc > 1 ? argv[1] : "all";
    if (choice == "http" || choice == "all") http_boundaries(db);
    if (choice == "search" || choice == "all") search_structure(db);
    if (choice == "zookeeper" || choice == "all") zookeeper_lines(db);
    std::cout << "service-v3 " << choice << " passed\n";
}
