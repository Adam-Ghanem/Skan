#include <algorithm>
#include <cassert>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "output/terminal/report_renderer.hpp"
#include "output/terminal_text.hpp"

namespace {

skan::detect::ServiceResult service(
    std::string name,
    std::string product,
    std::string version,
    std::string probe)
{
    skan::detect::ServiceResult result;
    result.target = "2001:db8::10";
    result.port = {443U, skan::portscan::Protocol::Tcp};
    result.protocol = skan::portscan::Protocol::Tcp;
    result.port_state = skan::portscan::PortState::Open;
    result.state = skan::detect::DetectionState::Detected;
    result.service = std::move(name);
    result.product = std::move(product);
    result.version = std::move(version);
    result.probe_name = std::move(probe);
    result.confidence = 0.95;
    return result;
}

skan::output::ScanReport report_fixture()
{
    skan::output::ScanReport report;
    report.scanner_name = "Skan";
    report.scanner_version = "0.1.0";
    report.started_at = "2026-09-01T12:00:00Z";
    report.duration_ms = 42.5;
    report.target_spec = "2001:db8::10";
    report.timing_profile = skan::scanengine::TimingProfileId::T3;

    skan::output::HostResult host;
    host.address = "2001:db8::10";
    host.family = skan::core::AddressFamily::IPv6;
    host.hostname = std::string("edge") + '\x1b' + "[31m\nhost";
    host.state = skan::discovery::HostState::Up;
    host.rtt_ms = 4.2;
    host.ports.push_back({
        host.address,
        {443U, skan::portscan::Protocol::Tcp},
        skan::portscan::PortState::Open,
        skan::portscan::ScanProbeType::TcpConnect,
        skan::portscan::ScanReason::ImmediateSuccess,
        4.2,
        {},
        0U,
        std::nullopt});
    host.ports.push_back({
        host.address,
        {22U, skan::portscan::Protocol::Tcp},
        skan::portscan::PortState::Closed,
        skan::portscan::ScanProbeType::TcpConnect,
        skan::portscan::ScanReason::ConnectionRefused,
        3.1,
        {},
        0U,
        std::nullopt});
    host.services.push_back(service("ssl/http", "OpenSSL", "3.0", "TLS"));
    host.services.push_back(service("https", "nginx", "1.25-very-long-version", "GetRequest"));
    host.warnings.push_back(std::string("banner") + static_cast<char>(0x9b) + "unsafe");
    report.hosts.push_back(std::move(host));
    return report;
}

std::string fixture(std::string_view name)
{
    std::ifstream input(std::string("tests/data/output/") + std::string(name), std::ios::binary);
    if (!input.is_open()) {
        return {};
    }
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void assert_fixture(std::string_view name, const std::string &actual)
{
    const std::string expected = fixture(name);
    if (actual != expected) {
        std::cerr << "--- " << name << " ---\n" << actual << "--- end " << name << " ---\n";
    }
    assert(actual == expected);
}

std::string render(skan::output::TerminalCapabilities capabilities, skan::output::ScanReport report)
{
    skan::output::OutputContext context;
    context.include_reasons = true;
    context.terminal = capabilities;
    std::ostringstream output;
    const skan::output::TerminalReportRenderer renderer;
    assert(renderer.render(report, output, context) == skan::output::OutputStatus::Ok);
    return output.str();
}

void assert_width(std::string_view rendered, std::size_t columns)
{
    std::istringstream lines{std::string(rendered)};
    std::string line;
    while (std::getline(lines, line)) {
        assert(skan::output::display_width(line) <= columns);
    }
}

} // namespace

int main()
{
    const skan::output::TerminalCapabilities wide{true, 120U, false, true};
    const skan::output::TerminalCapabilities medium{true, 100U, false, true};
    const skan::output::TerminalCapabilities narrow{true, 72U, false, true};
    const skan::output::TerminalCapabilities plain{false, 200U, false, false};

    const std::string wide_output = render(wide, report_fixture());
    const std::string medium_output = render(medium, report_fixture());
    const std::string narrow_output = render(narrow, report_fixture());
    const std::string plain_output = render(plain, report_fixture());

    assert_fixture("wide.golden", wide_output);
    assert_fixture("medium.golden", medium_output);
    assert_fixture("narrow.golden", narrow_output);
    assert_fixture("plain.golden", plain_output);
    assert_width(wide_output, wide.columns);
    assert_width(medium_output, medium.columns);
    assert_width(narrow_output, narrow.columns);
    assert(plain_output.find('\x1b') == std::string::npos);
    assert(plain_output.find("\xe2\x94") == std::string::npos);
    assert(wide_output.find("https") != std::string::npos);
    assert(wide_output.find("ssl/http") != std::string::npos);
    assert(wide_output.find(static_cast<char>(0x9b)) == std::string::npos);

    auto reordered = report_fixture();
    std::reverse(reordered.hosts.front().services.begin(), reordered.hosts.front().services.end());
    assert(render(wide, std::move(reordered)) == wide_output);

    return 0;
}
