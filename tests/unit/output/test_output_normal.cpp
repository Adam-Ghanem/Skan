#include <cassert>
#include <sstream>
#include <string>

#include "output/output_normal.hpp"
#include "output_test_fixture.hpp"

int main()
{
    skan::output::NormalOutputWriter writer;
    std::ostringstream empty_output;
    assert(writer.write(skan::output::ScanReport{}, empty_output, skan::output::OutputContext{}) ==
           skan::output::OutputStatus::Ok);
    assert(empty_output.str().find("◈ Skan") != std::string::npos);
    assert(empty_output.str().find("Modern network reconnaissance engine") != std::string::npos);
    assert(empty_output.str().find("Summary: hosts=0") != std::string::npos);
    assert(empty_output.str().find("✓ Scan complete") != std::string::npos);
    assert(empty_output.str().find("\x1b[") == std::string::npos);

    skan::output::ScanReport branded_report;
    branded_report.scanner_name = "Skan";
    branded_report.scanner_version = "Skan 0.1.0";
    std::ostringstream branded_output;
    assert(writer.write(branded_report, branded_output, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(branded_output.str().find("vSkan 0.1.0") == std::string::npos);
    assert(branded_output.str().find("Skan 0.1.0") != std::string::npos);

    const skan::output::ScanReport report = skan::output::test::make_report();
    std::ostringstream first;
    std::ostringstream second;
    assert(writer.write(report, first, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(writer.write(report, second, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(first.str() == second.str());
    assert(first.str().find("Host 192.0.2.10") < first.str().find("Host 192.0.2.20"));
    assert(first.str().find("PORT") != std::string::npos);
    assert(first.str().find("STATE") != std::string::npos);
    assert(first.str().find("SERVICE") != std::string::npos);
    assert(first.str().find("VERSION") != std::string::npos);
    assert(first.str().find("22/tcp") < first.str().find("80/tcp"));
    assert(first.str().find("http") != std::string::npos);
    assert(first.str().find("hostname=www.example.test tunnel=tls tls=yes tls_version=TLS 1.3") != std::string::npos);
    assert(first.str().find("SkanLinuxGeneric") < first.str().find("SkanWindowsGeneric"));
    assert(first.str().find("OS family=ipv4 status=complete error=none") != std::string::npos);
    assert(first.str().find("OS family=ipv4 status=complete error=none confidence=0.91") != std::string::npos);
    assert(first.str().find("probes=12 responses=7 timeouts=5 tcp_evidence=0") != std::string::npos);
    assert(first.str().find("Warning:") != std::string::npos);
    assert(first.str().find("Error:") != std::string::npos);

    skan::output::OutputContext colored;
    colored.color_enabled = true;
    std::ostringstream colored_output;
    assert(writer.write(report, colored_output, colored) == skan::output::OutputStatus::Ok);
    assert(colored_output.str().find("\x1b[36m") != std::string::npos);
    assert(colored_output.str().find("\x1b[32mOPEN") != std::string::npos);
    assert(colored_output.str().find("\x1b[33mFILTERED") != std::string::npos);

    skan::output::OutputContext filtered;
    filtered.include_closed_ports = false;
    filtered.include_filtered_ports = false;
    std::ostringstream filtered_output;
    assert(writer.write(report, filtered_output, filtered) == skan::output::OutputStatus::Ok);
    assert(filtered_output.str().find("22/tcp") == std::string::npos);
    assert(filtered_output.str().find("\n  443/tcp") == std::string::npos);

    return 0;
}
