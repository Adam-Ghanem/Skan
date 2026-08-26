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
        "Probe UDP DemoUDP rarity=2 ports=53 protocol=udp\n"
        "send \"\\x12\\x34\"\n"
        "match type=exact pattern=\"\\x12\\x34\" service=dns product=DNS confidence=0.90\n"
        "Probe TCP Generic rarity=3\n"
        "send \"\\r\\n\"\n"
        "match type=substring pattern=hello service=text product=Text confidence=0.40\n";
    skan::core::StatusCode status = skan::core::StatusCode::InternalError;
    const ServiceProbeDatabase database = ServiceProbeDatabase::parse(text, status);
    assert(status == skan::core::StatusCode::Ok);
    assert(database.status() == skan::core::StatusCode::Ok);
    assert(database.probes().size() == 3U);
    assert(database.probes()[0].payload == "GET /\r\n\r\n");
    assert(database.probes()[0].port_hints.size() == 2U);
    assert(database.probes()[0].rules[0].compiled_regex.has_value());
    assert(database.probes()[1].protocol == skan::portscan::Protocol::Udp);
    assert(database.probes()[1].rules[0].type == ServiceMatchType::Exact);

    const auto ordered = database.ordered_probe_indices({80U, skan::portscan::Protocol::Tcp}, 2U);
    assert(ordered.size() == 2U);
    assert(database.probes()[ordered[0]].name == "Demo");
    assert(database.probes()[ordered[1]].name == "Generic");
    assert(database.ordered_probe_indices({53U, skan::portscan::Protocol::Udp}, 1U).size() == 1U);

    const ServiceProbeDatabase built_in = ServiceProbeDatabase::built_in();
    assert(built_in.status() == skan::core::StatusCode::Ok);
    assert(built_in.probes().size() >= 12U);
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

    const std::string oversized_text((1U << 20U) + 1U, '#');
    skan::core::StatusCode oversized_status = skan::core::StatusCode::Ok;
    const ServiceProbeDatabase oversized = ServiceProbeDatabase::parse(oversized_text, oversized_status);
    assert(oversized_status == skan::core::StatusCode::ParseError);
    assert(oversized.status() == skan::core::StatusCode::ParseError);

    const std::string long_pattern(4097U, 'x');
    const std::string long_pattern_text =
        "Probe TCP LongPattern rarity=1\n"
        "send \"x\"\n";
    const std::string long_pattern_database = long_pattern_text +
        "match type=prefix pattern=\"" + long_pattern + "\" service=x confidence=0.5\n";
    skan::core::StatusCode long_pattern_status = skan::core::StatusCode::Ok;
    const ServiceProbeDatabase long_pattern_result =
        ServiceProbeDatabase::parse(long_pattern_database, long_pattern_status);
    assert(long_pattern_status == skan::core::StatusCode::ParseError);
    assert(long_pattern_result.probes().empty());

    std::string too_many_rules = "Probe TCP ManyRules rarity=1\nsend \"x\"\n";
    for (std::size_t index = 0U; index < 257U; ++index) {
        too_many_rules += "match type=prefix pattern=\"x\" service=x confidence=0.5\n";
    }
    skan::core::StatusCode too_many_rules_status = skan::core::StatusCode::Ok;
    const ServiceProbeDatabase too_many_rules_result =
        ServiceProbeDatabase::parse(too_many_rules, too_many_rules_status);
    assert(too_many_rules_status == skan::core::StatusCode::ParseError);
    assert(too_many_rules_result.probes().empty());

    std::string too_many_probes;
    for (std::size_t index = 0U; index < 257U; ++index) {
        too_many_probes += "Probe TCP P" + std::to_string(index) + " rarity=1\n";
    }
    skan::core::StatusCode too_many_probes_status = skan::core::StatusCode::Ok;
    const ServiceProbeDatabase too_many_probes_result =
        ServiceProbeDatabase::parse(too_many_probes, too_many_probes_status);
    assert(too_many_probes_status == skan::core::StatusCode::ParseError);
    assert(too_many_probes_result.probes().empty());

    return 0;
}
