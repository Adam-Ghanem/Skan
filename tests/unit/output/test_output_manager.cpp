#include <cassert>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

#include "output/output_manager.hpp"
#include "output_test_fixture.hpp"

int main()
{
    const skan::output::ScanReport report = skan::output::test::make_report();
    const skan::output::OutputFormat formats[] = {
        skan::output::OutputFormat::Normal,
        skan::output::OutputFormat::Json,
        skan::output::OutputFormat::Xml,
        skan::output::OutputFormat::Grepable};
    for (const skan::output::OutputFormat format : formats) {
        assert(skan::output::OutputManager::create(format) != nullptr);
        std::ostringstream output;
        assert(skan::output::OutputManager::write(format, report, output) == skan::output::OutputStatus::Ok);
        assert(!output.str().empty());
    }
    skan::output::ScanReport ack_report;
    skan::output::HostResult ack_host;
    ack_host.address = "192.0.2.1";
    skan::portscan::PortResult ack_port;
    ack_port.target = ack_host.address;
    ack_port.port = {443U, skan::portscan::Protocol::Tcp};
    ack_port.probe = skan::portscan::ScanProbeType::TcpAck;
    ack_port.state = skan::portscan::PortState::Unfiltered;
    ack_port.reason = skan::portscan::ScanReason::AckRst;
    ack_host.ports.push_back(ack_port);
    ack_report.hosts.push_back(ack_host);
    for (const skan::output::OutputFormat format : formats) {
        skan::output::OutputContext context;
        context.include_reasons = true;
        std::ostringstream full;
        assert(skan::output::OutputManager::write(format, ack_report, full, context) == skan::output::OutputStatus::Ok);
        assert(full.str().find("UNFILTERED") != std::string::npos);
        assert(full.str().find("ACK_RST") != std::string::npos);
        context.open_only = true;
        std::ostringstream filtered;
        assert(skan::output::OutputManager::write(format, ack_report, filtered, context) == skan::output::OutputStatus::Ok);
        assert(filtered.str().find("UNFILTERED") == std::string::npos);
        assert(filtered.str().find("ACK_RST") == std::string::npos);
    }
    assert(skan::output::OutputManager::create(static_cast<skan::output::OutputFormat>(255U)) == nullptr);
    skan::output::OutputFormat parsed = skan::output::OutputFormat::Normal;
    assert(skan::output::parse_output_format("json", parsed) == skan::output::OutputStatus::Ok);
    assert(parsed == skan::output::OutputFormat::Json);
    assert(skan::output::parse_output_format("invalid", parsed) == skan::output::OutputStatus::InvalidFormat);

    const std::string path = "/tmp/skan-phase8-output.xml";
    {
        std::ofstream file(path, std::ios::out | std::ios::trunc);
        assert(file.is_open());
        assert(skan::output::OutputManager::write(
                   skan::output::OutputFormat::Xml, report, file) == skan::output::OutputStatus::Ok);
    }
    std::ifstream file(path);
    assert(file.is_open());
    const std::string serialized((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    assert(serialized.find("<skan") != std::string::npos);
    std::remove(path.c_str());

    std::ofstream unwritable("/proc/skan-phase8-output.json", std::ios::out | std::ios::trunc);
    assert(!unwritable.is_open());
    return 0;
}
