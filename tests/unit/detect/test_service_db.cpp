#include <cassert>
#include <string>

#include "detect/service_db.hpp"

int main()
{
    using namespace skan::detect;
    const std::string text =
        "# comment\n"
        "Probe TCP Demo rarity=2 ports=80,8080\n"
        "send \"GET /\\r\\n\\r\\n\"\n"
        "match type=regex pattern=\"^Demo/([0-9.]+)\" service=demo product=Demo version=\"$1\" confidence=0.75\n"
        "Probe TCP Generic rarity=3\n"
        "send \"\\r\\n\"\n"
        "match type=substring pattern=hello service=text product=Text confidence=0.40\n";
    skan::core::StatusCode status = skan::core::StatusCode::InternalError;
    const ServiceProbeDatabase database = ServiceProbeDatabase::parse(text, status);
    assert(status == skan::core::StatusCode::Ok);
    assert(database.status() == skan::core::StatusCode::Ok);
    assert(database.probes().size() == 2U);
    assert(database.probes()[0].payload == "GET /\r\n\r\n");
    assert(database.probes()[0].port_hints.size() == 2U);
    assert(database.probes()[0].rules[0].compiled_regex.has_value());

    const auto ordered = database.ordered_probe_indices({80U, skan::portscan::Protocol::Tcp}, 2U);
    assert(ordered.size() == 2U);
    assert(database.probes()[ordered[0]].name == "Demo");
    assert(database.probes()[ordered[1]].name == "Generic");

    const ServiceProbeDatabase built_in = ServiceProbeDatabase::built_in();
    assert(built_in.status() == skan::core::StatusCode::Ok);
    assert(built_in.probes().size() >= 5U);
    assert(built_in.ordered_probe_indices({22U, skan::portscan::Protocol::Tcp}, 1U).size() == 1U);
    assert(built_in.probes()[built_in.ordered_probe_indices({22U, skan::portscan::Protocol::Tcp}, 1U)[0]].name ==
           "SSHBanner");

    skan::core::StatusCode bad_status = skan::core::StatusCode::Ok;
    const ServiceProbeDatabase bad = ServiceProbeDatabase::parse(
        "Probe TCP Broken rarity=1\nmatch type=regex pattern=\"[\" service=x confidence=0.5\n",
        bad_status);
    assert(bad_status == skan::core::StatusCode::ParseError);
    assert(bad.status() == skan::core::StatusCode::ParseError);
    assert(bad.probes().empty());
    return 0;
}
