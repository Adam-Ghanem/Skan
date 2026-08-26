#include <cassert>
#include <cstddef>
#include <sstream>
#include <string>

#include "output/output_manager.hpp"
#include "../../unit/output/output_test_fixture.hpp"

int main()
{
    const skan::output::ScanReport report = skan::output::test::make_report();
    std::ostringstream normal;
    std::ostringstream json;
    std::ostringstream xml;
    std::ostringstream grepable;
    assert(skan::output::OutputManager::write(skan::output::OutputFormat::Normal, report, normal) ==
           skan::output::OutputStatus::Ok);
    assert(skan::output::OutputManager::write(skan::output::OutputFormat::Json, report, json) ==
           skan::output::OutputStatus::Ok);
    assert(skan::output::OutputManager::write(skan::output::OutputFormat::Xml, report, xml) ==
           skan::output::OutputStatus::Ok);
    assert(skan::output::OutputManager::write(skan::output::OutputFormat::Grepable, report, grepable) ==
           skan::output::OutputStatus::Ok);
    for (const std::string &output : {normal.str(), json.str(), xml.str(), grepable.str()}) {
        assert(output.find("192.0.2.20") != std::string::npos);
        assert(output.find("SkanLinuxGeneric") != std::string::npos);
        assert(output.find("http") != std::string::npos);
        assert(output.find("Summary") != std::string::npos || output.find("summary") != std::string::npos);
    }
    std::ostringstream repeated;
    assert(skan::output::OutputManager::write(skan::output::OutputFormat::Json, report, repeated) ==
           skan::output::OutputStatus::Ok);
    assert(repeated.str() == json.str());

    skan::output::ScanReport large = report;
    large.hosts.reserve(10000U);
    while (large.hosts.size() < 10000U) {
        const std::size_t index = large.hosts.size();
        skan::output::HostResult host;
        if ((index & 1U) == 0U) {
            host.address = "198.51.100." + std::to_string((index % 254U) + 1U);
            host.family = skan::core::AddressFamily::IPv4;
        } else {
            host.address = "2001:db8::" + std::to_string(index);
            host.family = skan::core::AddressFamily::IPv6;
        }
        host.state = skan::discovery::HostState::Unknown;
        large.hosts.push_back(std::move(host));
    }
    std::ostringstream large_json;
    std::ostringstream large_xml;
    assert(skan::output::OutputManager::write(skan::output::OutputFormat::Json, large, large_json) ==
           skan::output::OutputStatus::Ok);
    assert(skan::output::OutputManager::write(skan::output::OutputFormat::Xml, large, large_xml) ==
           skan::output::OutputStatus::Ok);
    assert(large_json.str().find("\"hosts\"") != std::string::npos);
    assert(large_xml.str().find("<host") != std::string::npos);
    return 0;
}
