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
    return 0;
}
