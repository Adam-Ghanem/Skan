#include <cassert>
#include <cstdlib>
#include <sstream>
#include <string>

#include "output/output_normal.hpp"
#include "output_test_fixture.hpp"

namespace {

std::string line_containing(const std::string &text, const std::string &needle)
{
    const std::size_t position = text.find(needle);
    assert(position != std::string::npos);
    const std::size_t begin = text.rfind('\n', position);
    const std::size_t end = text.find('\n', position);
    const std::size_t start = begin == std::string::npos ? 0U : begin + 1U;
    return text.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

} // namespace

int main()
{
    skan::output::NormalOutputWriter writer;
    skan::output::OutputContext interactive;
    interactive.interactive_terminal = true;

    std::ostringstream empty_output;
    assert(writer.write(skan::output::ScanReport{}, empty_output, interactive) ==
           skan::output::OutputStatus::Ok);
    assert(empty_output.str().find("◈ SKAN") != std::string::npos);
    assert(empty_output.str().find("Modern Network Scanner") != std::string::npos);
    assert(empty_output.str().find("Summary: hosts=") == std::string::npos);
    assert(empty_output.str().find("Scan complete") != std::string::npos);
    assert(empty_output.str().find("\x1b[") == std::string::npos);

    skan::output::ScanReport branded_report;
    branded_report.scanner_name = "Skan";
    branded_report.scanner_version = "Skan 0.1.0";
    std::ostringstream branded_output;
    assert(writer.write(branded_report, branded_output, interactive) ==
           skan::output::OutputStatus::Ok);
    assert(branded_output.str().find("v0.1.0") != std::string::npos);
    assert(branded_output.str().find("Skan Skan") == std::string::npos);
    assert(branded_output.str().find("vSkan") == std::string::npos);

    const skan::output::ScanReport report = skan::output::test::make_report();
    std::ostringstream first;
    std::ostringstream second;
    assert(writer.write(report, first, interactive) == skan::output::OutputStatus::Ok);
    assert(writer.write(report, second, interactive) == skan::output::OutputStatus::Ok);
    assert(first.str() == second.str());
    assert(first.str().find("192.0.2.10") < first.str().find("192.0.2.20"));
    assert(first.str().find("PORT") != std::string::npos);
    assert(first.str().find("STATE") != std::string::npos);
    assert(first.str().find("SERVICE") != std::string::npos);
    assert(first.str().find("VERSION") != std::string::npos);
    assert(first.str().find("22/tcp") < first.str().find("80/tcp"));
    assert(first.str().find("confidence=") == std::string::npos);
    assert(first.str().find("probe=") == std::string::npos);
    assert(first.str().find("Metrics:") == std::string::npos);
    assert(first.str().find("Summary: hosts=") == std::string::npos);
    assert(first.str().find("SkanLinuxGeneric") != std::string::npos);

    std::ostringstream plain_output;
    assert(writer.write(report, plain_output, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(plain_output.str().rfind("SKAN v0.1.0\n", 0U) == 0U);
    assert(plain_output.str().find("◈") == std::string::npos);
    assert(plain_output.str().find("╭") == std::string::npos);
    assert(plain_output.str().find("●") == std::string::npos);
    assert(plain_output.str().find("Skan —") == std::string::npos);

    const std::string open_line = line_containing(first.str(), "80/tcp");
    assert(open_line.find("80/tcp") == 2U);
    assert(open_line.find("OPEN") == 14U);
    assert(open_line.find("http") == 27U);
    assert(open_line.find("nginx") == 41U);

    skan::output::ScanReport reachable_report = report;
    reachable_report.hosts.front().state = skan::discovery::HostState::Unknown;
    std::ostringstream reachable_output;
    assert(writer.write(reachable_report, reachable_output, interactive) ==
           skan::output::OutputStatus::Ok);
    const std::string reachable_host_line = line_containing(reachable_output.str(), "192.0.2.20");
    assert(reachable_host_line.find("reachable") != std::string::npos);
    assert(reachable_host_line.find("UNKNOWN") == std::string::npos);

    skan::output::OutputContext colored;
    colored.interactive_terminal = true;
    colored.color_enabled = true;
    std::ostringstream colored_output;
    assert(writer.write(report, colored_output, colored) == skan::output::OutputStatus::Ok);
    assert(colored_output.str().find("\x1b[36m") != std::string::npos);
    assert(colored_output.str().find("\x1b[32mOPEN") != std::string::npos);
    assert(colored_output.str().find("\x1b[33mFILTERED") != std::string::npos);

    skan::output::OutputContext filtered = interactive;
    filtered.include_closed_ports = false;
    filtered.include_filtered_ports = false;
    std::ostringstream filtered_output;
    assert(writer.write(report, filtered_output, filtered) == skan::output::OutputStatus::Ok);
    assert(filtered_output.str().find("22/tcp") == std::string::npos);
    assert(filtered_output.str().find("\n  443/tcp") == std::string::npos);


    (void)::setenv("COLUMNS", "60", 1);
    std::ostringstream narrow_output;
    assert(writer.write(report, narrow_output, interactive) == skan::output::OutputStatus::Ok);
    std::istringstream narrow_lines(narrow_output.str());
    std::string narrow_line;
    while (std::getline(narrow_lines, narrow_line)) {
        assert(narrow_line.size() <= 60U);
    }
    assert(narrow_output.str().find("VERSION") == std::string::npos);
    (void)::unsetenv("COLUMNS");

    skan::output::OutputContext reasons = interactive;
    reasons.include_reasons = true;
    std::ostringstream reason_output;
    assert(writer.write(report, reason_output, reasons) == skan::output::OutputStatus::Ok);
    assert(reason_output.str().find("REASON") != std::string::npos);
    assert(line_containing(reason_output.str(), "22/tcp").find("CONNECTION_REFUSED") != std::string::npos);
    assert(line_containing(reason_output.str(), "80/tcp").find("IMMEDIATE_SUCCESS") != std::string::npos);

    skan::output::OutputContext open_only = interactive;
    open_only.open_only = true;
    std::ostringstream open_output;
    assert(writer.write(report, open_output, open_only) == skan::output::OutputStatus::Ok);
    assert(open_output.str().find("80/tcp") != std::string::npos);
    assert(open_output.str().find("22/tcp") == std::string::npos);
    assert(open_output.str().find("443/tcp") == std::string::npos);
    assert(open_output.str().find("8443/tcp") == std::string::npos);
    assert(open_output.str().find("1 open") != std::string::npos);
    assert(open_output.str().find("1 filtered") != std::string::npos);

    return 0;
}
