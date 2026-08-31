#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <utility>

#include "output/output_manager.hpp"
#include "../../unit/output/output_test_fixture.hpp"

namespace {

skan::output::ScanReport make_port_state_report()
{
    skan::output::ScanReport report;
    skan::output::HostResult host;
    host.address = "192.0.2.33";
    host.state = skan::discovery::HostState::Up;

    const auto add_port = [&](std::uint16_t number,
                              skan::portscan::Protocol protocol,
                              skan::portscan::PortState state) {
        host.ports.push_back(skan::portscan::PortResult{
            host.address,
            skan::portscan::Port{number, protocol},
            state,
            protocol == skan::portscan::Protocol::Udp ? skan::portscan::ScanProbeType::Udp
                                                       : skan::portscan::ScanProbeType::TcpConnect,
            skan::portscan::ScanReason::InternalError,
            std::nullopt,
            {},
            0U,
            std::nullopt});
    };

    add_port(10U, skan::portscan::Protocol::Tcp, skan::portscan::PortState::Open);
    add_port(11U, skan::portscan::Protocol::Udp, skan::portscan::PortState::OpenOrFiltered);
    add_port(12U, skan::portscan::Protocol::Tcp, skan::portscan::PortState::Closed);
    add_port(13U, skan::portscan::Protocol::Tcp, skan::portscan::PortState::Filtered);
    add_port(14U, skan::portscan::Protocol::Tcp, skan::portscan::PortState::Unknown);
    add_port(15U, skan::portscan::Protocol::Tcp, skan::portscan::PortState::Unfiltered);
    add_port(16U, skan::portscan::Protocol::Tcp, skan::portscan::PortState::Error);
    add_port(17U, skan::portscan::Protocol::Tcp, skan::portscan::PortState::Unreachable);
    report.hosts.push_back(std::move(host));
    return report;
}

void assert_open_only_writer_parity()
{
    const skan::output::ScanReport report = make_port_state_report();
    skan::output::OutputContext context;
    context.open_only = true;

    struct WriterExpectation final {
        skan::output::OutputFormat format;
        const char *open;
        const char *open_or_filtered;
        const char *excluded_ports[6];
    };
    const WriterExpectation expectations[] = {
        {skan::output::OutputFormat::Normal,
         "10/tcp",
         "11/udp",
         {"12/tcp", "13/tcp", "14/tcp", "15/tcp", "16/tcp", "17/tcp"}},
        {skan::output::OutputFormat::Json,
         "\"port\": 10",
         "\"port\": 11",
         {"\"port\": 12", "\"port\": 13", "\"port\": 14", "\"port\": 15", "\"port\": 16", "\"port\": 17"}},
        {skan::output::OutputFormat::Xml,
         "number=\"10\" protocol=\"tcp\" state=\"OPEN\"",
         "number=\"11\" protocol=\"udp\" state=\"OPEN_OR_FILTERED\"",
         {"number=\"12\"", "number=\"13\"", "number=\"14\"", "number=\"15\"", "number=\"16\"", "number=\"17\""}},
        {skan::output::OutputFormat::Grepable,
         "number=10 protocol=tcp state=OPEN",
         "number=11 protocol=udp state=OPEN_OR_FILTERED",
         {"number=12 ", "number=13 ", "number=14 ", "number=15 ", "number=16 ", "number=17 "}}};

    for (const WriterExpectation &expectation : expectations) {
        std::ostringstream output;
        assert(skan::output::OutputManager::write(expectation.format, report, output, context) ==
               skan::output::OutputStatus::Ok);
        const std::string serialized = output.str();
        assert(serialized.find(expectation.open) != std::string::npos);
        assert(serialized.find(expectation.open_or_filtered) != std::string::npos);
        if (expectation.format == skan::output::OutputFormat::Normal) {
            const std::size_t open_line = serialized.find("10/tcp");
            const std::size_t open_line_end = serialized.find('\n', open_line);
            const std::string open_row = serialized.substr(open_line, open_line_end - open_line);
            assert(open_row.find("OPEN") != std::string::npos);
            assert(open_row.find("OPEN_OR_") == std::string::npos);
            const std::size_t possible_line = serialized.find("11/udp");
            const std::size_t possible_line_end = serialized.find('\n', possible_line);
            const std::string possible_row = serialized.substr(possible_line, possible_line_end - possible_line);
            assert(possible_row.find("OPEN_OR_") != std::string::npos);
        }
        for (const char *excluded : expectation.excluded_ports) {
            assert(serialized.find(excluded) == std::string::npos);
        }
    }
}

} // namespace

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
    assert_open_only_writer_parity();
    return 0;
}
