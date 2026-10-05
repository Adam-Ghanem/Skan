#include <cassert>
#include <string>

#include "detect/service_matcher.hpp"

namespace {

void templated_protocol_regressions()
{
    using namespace skan::detect;
    skan::core::StatusCode status = skan::core::StatusCode::InternalError;
    const auto database = ServiceProbeDatabase::parse(
        "Probe TCP Template rarity=1\n"
        "send \"unrelated\"\n"
        "match type=regex pattern=\"(http|elasticsearch|opensearch|zookeeper)\" service=\"$1\" product=Fake version=9.9.9 confidence=0.99\n",
        status);
    assert(status == skan::core::StatusCode::Ok);
    const ServiceMatcher matcher(database);
    const auto &probe = database.probes().front();
    for (const char *response : {"http", "elasticsearch", "opensearch", "zookeeper"}) {
        assert(!matcher.match(probe, response).matched);
    }
    auto root_probe = probe;
    root_probe.payload = "GET / HTTP/1.1\r\n\r\n";
    const auto body_label = matcher.match(root_probe,
        "HTTP/1.1 200 OK\r\n\r\nhttp Server: nginx/9.9.9\r\n");
    assert(body_label.matched && body_label.service == "http");
    assert(body_label.product.empty() && body_label.version.empty());
    const auto header_label = matcher.match(root_probe,
        "HTTP/1.1 200 OK\r\nX-Service: http\r\nServer: nginx/1.26.2\r\n\r\n");
    assert(header_label.service == "http" && header_label.product == "nginx");
    assert(header_label.version == "1.26.2");
    assert(!matcher.match(root_probe,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        "{\"service\":\"elasticsearch\"}").matched);
    assert(!matcher.match(root_probe,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        "{\"service\":\"opensearch\"}").matched);
}

void mqtt_framing_regressions()
{
    using namespace skan::detect;
    skan::core::StatusCode status = skan::core::StatusCode::InternalError;
    const auto database = ServiceProbeDatabase::load_file("data/service-probes.db", status);
    assert(status == skan::core::StatusCode::Ok);
    const ServiceProbeDefinition *mqtt = nullptr;
    for (const auto &probe : database.probes()) {
        if (probe.name == "MQTTConnect") mqtt = &probe;
    }
    assert(mqtt != nullptr);
    const ServiceMatcher matcher(database);
    const std::string accepted{"\x20\x02\x00\x00", 4U};
    for (std::size_t length = 0U; length < accepted.size(); ++length) {
        assert(!matcher.match(*mqtt, std::string_view{accepted}.substr(0U, length)).matched);
    }
    // Exhaust the two variable bytes: clean-session CONNECT forbids Session
    // Present, all reserved flag bits, and return codes above 5.
    for (unsigned int flags = 0U; flags <= 255U; ++flags) {
        for (unsigned int code = 0U; code <= 255U; ++code) {
            std::string response = accepted;
            response[2] = static_cast<char>(flags);
            response[3] = static_cast<char>(code);
            const auto result = matcher.match(*mqtt, response);
            assert(result.matched == (flags == 0U && code <= 5U));
            if (result.matched) {
                assert(result.service == "mqtt");
                assert(result.product.empty());
                assert(result.version.empty());
                assert(result.mqtt.has_value());
                assert(result.mqtt->return_code == code);
            }
        }
    }
    for (std::size_t index : {0U, 1U}) {
        for (unsigned int byte = 0U; byte <= 255U; ++byte) {
            std::string response = accepted;
            response[index] = static_cast<char>(byte);
            const bool valid = byte == (index == 0U ? 0x20U : 0x02U);
            assert(matcher.match(*mqtt, response).matched == valid);
        }
    }
    auto unrelated = *mqtt;
    unrelated.payload = "GET / HTTP/1.0\r\n\r\n";
    assert(!matcher.match(unrelated, accepted).matched);
    unrelated = *mqtt;
    unrelated.protocol = TransportProtocol::Udp;
    assert(!matcher.match(unrelated, accepted).matched);
    auto renamed = *mqtt;
    renamed.name = "CustomNegotiation";
    renamed.port_hints.clear();
    renamed.rules.resize(1U);
    renamed.rules.front().type = ServiceMatchType::Prefix;
    renamed.rules.front().pattern = " ";
    renamed.rules.front().product = "UnsupportedBroker";
    renamed.rules.front().version = "999";
    const auto custom = matcher.match(renamed, accepted);
    assert(custom.matched && custom.mqtt.has_value());
    assert(custom.product.empty() && custom.version.empty());
    assert(!matcher.match(renamed, std::string_view{accepted}.substr(0U, 2U)).matched);
    // TCP coalescing must not invalidate a complete first CONNACK frame.
    assert(matcher.match(*mqtt, accepted + std::string{"\xd0\x00", 2U}).matched);
    assert(matcher.match(*mqtt, accepted + std::string(8188U, 'x')).matched);
    assert(!matcher.match(*mqtt, accepted + std::string(8192U, 'x')).matched);
}

} // namespace

int main()
{
    templated_protocol_regressions();
    using namespace skan::detect;
    mqtt_framing_regressions();
    const std::string text =
        "Probe TCP Match rarity=1\n"
        "send \"\\r\\n\"\n"
        "match type=prefix pattern=\"SSH-\" service=ssh product=SSH confidence=0.50\n"
        "match type=substring pattern=\"OpenSSH\" service=ssh product=OpenSSH confidence=0.70\n"
        "match type=suffix pattern=\"READY\" service=ready product=Ready confidence=0.80\n"
        "match type=regex pattern=\"^SSH-[0-9.]+-OpenSSH_([0-9.]+)\" service=ssh product=OpenSSH version=\"$1\" confidence=0.90\n"
        "match type=exact pattern=\"TLS-ALERT\" service=tls product=TLS confidence=0.99\n";
    skan::core::StatusCode status = skan::core::StatusCode::InternalError;
    const ServiceProbeDatabase database = ServiceProbeDatabase::parse(text, status);
    assert(status == skan::core::StatusCode::Ok);
    ServiceMatcher matcher(database);
    const ServiceMatchResult match = matcher.match(
        database.probes().front(),
        "SSH-2.0-OpenSSH_9.6\r\n");
    assert(match.matched);
    assert(match.service == "ssh");
    assert(match.product == "OpenSSH");
    assert(match.version == "9.6");
    assert(match.confidence == 0.97);

    const ServiceMatchResult prefix = matcher.match(database.probes().front(), "SSH-legacy\n");
    assert(!prefix.matched);

    const ServiceMatchResult suffix = matcher.match(database.probes().front(), "SERVICE READY");
    assert(suffix.matched);
    assert(suffix.service == "ready");
    assert(suffix.product == "Ready");
    assert(suffix.confidence == 0.80);

    const ServiceMatchResult exact = matcher.match(database.probes().front(), "TLS-ALERT");
    assert(exact.matched);
    assert(exact.service == "tls");
    assert(exact.priority == 4U);

    const std::string anchored_text =
        "Probe TCP Anchored rarity=1\n"
        "send \"x\"\n"
        "match type=regex pattern=\"^\\x20\\x02..\" service=example product=Example version=1 confidence=0.99\n"
        "match type=prefix pattern=\"\\x20\\x02\" service=example product=Example confidence=0.98\n";
    skan::core::StatusCode anchored_status = skan::core::StatusCode::InternalError;
    const ServiceProbeDatabase anchored_database = ServiceProbeDatabase::parse(anchored_text, anchored_status);
    assert(anchored_status == skan::core::StatusCode::Ok);
    const ServiceMatchResult anchored = ServiceMatcher(anchored_database).match(
        anchored_database.probes().front(), std::string{"\x20\x02\x00\x00", 4U});
    assert(anchored.matched);
    assert(anchored.service == "example");
    assert(anchored.version == "1");
    assert(anchored.confidence == 0.99);
    assert(anchored.priority == 4U);

    const std::string soft_text =
        "Probe TCP Soft rarity=1\n"
        "softmatch type=regex pattern=\"^220 ([A-Za-z0-9.-]+)\" service=fixture-smtp product=SMTP hostname=\"$1\" confidence=0.70\n";
    skan::core::StatusCode soft_status = skan::core::StatusCode::InternalError;
    const ServiceProbeDatabase soft_database = ServiceProbeDatabase::parse(soft_text, soft_status);
    assert(soft_status == skan::core::StatusCode::Ok);
    const ServiceMatchResult soft = ServiceMatcher(soft_database).match(
        soft_database.probes().front(), "220 mail.example ESMTP\r\n");
    assert(soft.matched);
    assert(soft.strength == ServiceMatchStrength::Soft);
    assert(soft.hostname == "mail.example");

    const ServiceMatchResult none = matcher.match(
        database.probes().front(),
        "HTTP/1.1 200 OK\r\n");
    assert(!none.matched);
    assert(none.confidence == 0.0);

    ServiceMatchResult incumbent;
    incumbent.matched = true;
    incumbent.strength = ServiceMatchStrength::Soft;
    incumbent.priority = 3U;
    incumbent.confidence = 0.80;
    incumbent.specificity = 5U;
    assert(service_match_is_publishable(incumbent));

    ServiceMatchResult weak = incumbent;
    weak.confidence = 0.45;
    assert(!service_match_is_publishable(weak));

    ServiceMatchResult structurally_weaker = incumbent;
    structurally_weaker.priority = 2U;
    structurally_weaker.confidence = 0.99;
    assert(!service_match_is_better(structurally_weaker, incumbent));

    ServiceMatchResult more_specific = incumbent;
    more_specific.specificity = 6U;
    assert(service_match_is_better(more_specific, incumbent));
    assert(!service_match_is_better(incumbent, incumbent));

    const std::string publishability_text =
        "Probe TCP Publishability rarity=1\n"
        "send \"x\"\n"
        "softmatch type=exact pattern=\"READY\" service=weak product=Exact confidence=0.45\n"
        "softmatch type=prefix pattern=\"REA\" service=strong product=Prefix confidence=0.95\n";
    skan::core::StatusCode publishability_status = skan::core::StatusCode::InternalError;
    const ServiceProbeDatabase publishability_database =
        ServiceProbeDatabase::parse(publishability_text, publishability_status);
    assert(publishability_status == skan::core::StatusCode::Ok);
    const ServiceMatchResult publishable = ServiceMatcher(publishability_database).match(
        publishability_database.probes().front(), "READY");
    assert(publishable.matched);
    assert(publishable.service == "strong");
    assert(publishable.confidence == 0.95);
    return 0;
}
