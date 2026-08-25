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
    assert(empty_output.str().find("Skan 0.1.0") != std::string::npos);
    assert(empty_output.str().find("Summary: hosts=0") != std::string::npos);

    const skan::output::ScanReport report = skan::output::test::make_report();
    std::ostringstream first;
    std::ostringstream second;
    assert(writer.write(report, first, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(writer.write(report, second, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(first.str() == second.str());
    assert(first.str().find("Host 192.0.2.10") < first.str().find("Host 192.0.2.20"));
    assert(first.str().find("Port 22/tcp CLOSED") < first.str().find("Port 80/tcp OPEN"));
    assert(first.str().find("service=http") != std::string::npos);
    assert(first.str().find("SkanLinuxGeneric") < first.str().find("SkanWindowsGeneric"));
    assert(first.str().find("OS status=complete error=none") != std::string::npos);
    assert(first.str().find("OS status=complete error=none confidence=0.91") != std::string::npos);
    assert(first.str().find("probes=12 responses=7 timeouts=5 tcp_evidence=0") != std::string::npos);
    assert(first.str().find("Warning:") != std::string::npos);
    assert(first.str().find("Error:") != std::string::npos);

    skan::output::OutputContext filtered;
    filtered.include_closed_ports = false;
    filtered.include_filtered_ports = false;
    std::ostringstream filtered_output;
    assert(writer.write(report, filtered_output, filtered) == skan::output::OutputStatus::Ok);
    assert(filtered_output.str().find("Port 22/tcp CLOSED") == std::string::npos);
    assert(filtered_output.str().find("Port 443/tcp FILTERED") == std::string::npos);

    return 0;
}
