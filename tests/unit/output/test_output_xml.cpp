#include <cassert>
#include <sstream>
#include <string>

#include "output/output_xml.hpp"
#include "output_test_fixture.hpp"

int main()
{
    skan::output::XmlOutputWriter writer;
    skan::output::ScanReport report = skan::output::test::make_report();
    skan::portscan::PortResult ambiguous;
    ambiguous.target = report.hosts.front().address;
    ambiguous.port = {53U, skan::portscan::Protocol::Udp};
    ambiguous.probe = skan::portscan::ScanProbeType::Udp;
    ambiguous.state = skan::portscan::PortState::OpenOrFiltered;
    ambiguous.reason = skan::portscan::ScanReason::UdpTimeout;
    report.hosts.front().ports.push_back(std::move(ambiguous));
    report.warnings.push_back(std::string("invalid-utf8") + static_cast<char>(0x9b));
    report.warnings.push_back("xml-forbidden:\xef\xbf\xbe:\xef\xbf\xbf");
    std::ostringstream first;
    std::ostringstream second;
    assert(writer.write(report, first, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(writer.write(report, second, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(first.str() == second.str());
    assert(first.str().find("<?xml version=\"1.0\"") == 0U);
    assert(first.str().find("<skan version=\"0.1.0\">") != std::string::npos);
    assert(first.str().find("&lt;unsafe&gt;") != std::string::npos);
    assert(first.str().find("&amp;") != std::string::npos);
    assert(first.str().find("&quot;") != std::string::npos);
    assert(first.str().find("&apos;") != std::string::npos);
    assert(first.str().find("<host address=\"192.0.2.10\"") <
           first.str().find("<host address=\"192.0.2.20\""));
    assert(first.str().find("<port target=\"192.0.2.20\" number=\"22\"") <
           first.str().find("<port target=\"192.0.2.20\" number=\"80\""));
    assert(first.str().find("<os>") != std::string::npos);
    assert(first.str().find("<os-detection>\n") != std::string::npos);
    assert(first.str().find("<address-family>ipv4</address-family>") != std::string::npos);
    assert(first.str().find("<fingerprint-id>fixture</fingerprint-id>") != std::string::npos);
    assert(first.str().find("<state>complete</state>") != std::string::npos);
    assert(first.str().find("<error>none</error>") != std::string::npos);
    assert(first.str().find("<confidence>0.91</confidence>") != std::string::npos);
    assert(first.str().find("<probes-sent>12</probes-sent>") != std::string::npos);
    assert(first.str().find("<responses-received>7</responses-received>") != std::string::npos);
    assert(first.str().find("<tcp-evidence>0</tcp-evidence>") != std::string::npos);
    assert(first.str().find("<udp-evidence>0</udp-evidence>") != std::string::npos);
    assert(first.str().find("<rtt-ms>4.5</rtt-ms>") != std::string::npos);
    assert(first.str().find("<hostname>www.example.test</hostname>") != std::string::npos);
    assert(first.str().find("<tunnel>tls</tunnel>") != std::string::npos);
    assert(first.str().find("<certificate-subject>CN=www.example.test</certificate-subject>") != std::string::npos);
    assert(first.str().find("<certificate-san>example.test</certificate-san>") != std::string::npos);
    assert(first.str().find("<alpn>h2</alpn>") != std::string::npos);
    assert(first.str().find(static_cast<char>(0x9b)) == std::string::npos);
    assert(first.str().find("invalid-utf8?") != std::string::npos);
    assert(first.str().find("\xef\xbf\xbe") == std::string::npos);
    assert(first.str().find("\xef\xbf\xbf") == std::string::npos);
    assert(first.str().find("xml-forbidden:?:?") != std::string::npos);
    assert(first.str().find("state=\"OPEN_OR_FILTERED\"") != std::string::npos);
    assert(first.str().find("reason=\"UDP_TIMEOUT\"") != std::string::npos);
    assert(first.str().find("<open-or-filtered-ports>1</open-or-filtered-ports>") != std::string::npos);
    return 0;
}
