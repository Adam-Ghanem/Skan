#include <cassert>
#include <sstream>
#include <string>

#include "output/output_grepable.hpp"
#include "output_test_fixture.hpp"

int main()
{
    skan::output::GrepableOutputWriter writer;
    const skan::output::ScanReport report = skan::output::test::make_report();
    std::ostringstream first;
    std::ostringstream second;
    assert(writer.write(report, first, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(writer.write(report, second, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(first.str() == second.str());
    assert(first.str().find("Host: address=\"192.0.2.10\"") <
           first.str().find("Host: address=\"192.0.2.20\""));
    assert(first.str().find("Port: target=\"192.0.2.20\" number=22") <
           first.str().find("Port: target=\"192.0.2.20\" number=80"));
    assert(first.str().find("Service:") != std::string::npos);
    assert(first.str().find("OS: address=\"192.0.2.20\"") != std::string::npos);
    assert(first.str().find("OSStatus: address=\"192.0.2.20\" state=complete error=none confidence=0.91 probes=12 responses=7 timeouts=5 tcp_evidence=0") !=
           std::string::npos);
    assert(first.str().find("\\n") != std::string::npos);
    assert(first.str().find("\\\"") != std::string::npos);
    assert(first.str().find('\x1b') == std::string::npos);
    for (std::size_t start = 0U; start < first.str().size();) {
        const std::size_t end = first.str().find('\n', start);
        const std::size_t length = end == std::string::npos ? first.str().size() - start : end - start;
        assert(first.str().substr(start, length).find('\r') == std::string::npos);
        if (end == std::string::npos) {
            break;
        }
        start = end + 1U;
    }
    return 0;
}
