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
        "match type=regex pattern=\"^SSH-[0-9.]+-OpenSSH_([0-9.]+)\" service=ssh product=OpenSSH version=\"$1\" confidence=0.90\n";
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

    const ServiceMatchResult none = matcher.match(database.probes().front(), "HTTP/1.1 200 OK\r\n");
    assert(!none.matched);
    assert(none.confidence == 0.0);
    return 0;
}
