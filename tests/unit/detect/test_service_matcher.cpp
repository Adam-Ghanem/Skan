#include <cassert>
#include <string>

#include "detect/service_matcher.hpp"

int main()
{
    using namespace skan::detect;
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
    assert(match.confidence == 0.90);

    const ServiceMatchResult prefix = matcher.match(database.probes().front(), "SSH-legacy\n");
    assert(prefix.matched);
    assert(prefix.service == "ssh");
    assert(prefix.product == "SSH");
    assert(prefix.confidence == 0.50);

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
        "match type=regex pattern=\"^\\x20\\x02..\" service=mqtt product=MQTT version=3.1.1 confidence=0.99\n"
        "match type=prefix pattern=\"\\x20\\x02\" service=mqtt product=MQTT confidence=0.98\n";
    skan::core::StatusCode anchored_status = skan::core::StatusCode::InternalError;
    const ServiceProbeDatabase anchored_database = ServiceProbeDatabase::parse(anchored_text, anchored_status);
    assert(anchored_status == skan::core::StatusCode::Ok);
    const ServiceMatchResult anchored = ServiceMatcher(anchored_database).match(
        anchored_database.probes().front(), std::string{"\x20\x02\x00\x00", 4U});
    assert(anchored.matched);
    assert(anchored.service == "mqtt");
    assert(anchored.version == "3.1.1");
    assert(anchored.confidence == 0.99);
    assert(anchored.priority == 4U);

    const std::string soft_text =
        "Probe TCP Soft rarity=1\n"
        "softmatch type=regex pattern=\"^220 ([A-Za-z0-9.-]+)\" service=smtp product=SMTP hostname=\"$1\" confidence=0.70\n";
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
