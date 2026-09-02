#include <cassert>
#include <sstream>
#include <string>

#include "output/output_json.hpp"
#include "output_test_fixture.hpp"

int main()
{
    skan::output::JsonOutputWriter writer;
    skan::output::ScanReport report = skan::output::test::make_report();
    report.warnings.push_back(std::string("invalid-utf8") + static_cast<char>(0x9b));
    std::ostringstream first;
    std::ostringstream second;
    assert(writer.write(report, first, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(writer.write(report, second, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(first.str() == second.str());
    assert(first.str().front() == '{');
    assert(first.str().back() == '\n');
    assert(first.str().find("\"scanner\"") != std::string::npos);
    assert(first.str().find("\"hosts\"") != std::string::npos);
    assert(first.str().find("\\\"") != std::string::npos);
    assert(first.str().find("\\\\") != std::string::npos);
    assert(first.str().find("\\n") != std::string::npos);
    assert(first.str().find("\\t") != std::string::npos);
    assert(first.str().find("1.2✓") != std::string::npos);
    assert(first.str().find(",]") == std::string::npos);
    assert(first.str().find(",}") == std::string::npos);
    assert(first.str().find("\"os\": [\n") != std::string::npos);
    assert(first.str().find("\"os_detection\": {") != std::string::npos);
    assert(first.str().find("\"address_family\": \"ipv4\"") != std::string::npos);
    assert(first.str().find("\"fingerprint_id\": \"fixture\"") != std::string::npos);
    assert(first.str().find("\"state\": \"complete\"") != std::string::npos);
    assert(first.str().find("\"family\": \"Linux\"") != std::string::npos);
    assert(first.str().find("\"confidence\": 0.91") != std::string::npos);
    assert(first.str().find("\"probes_generated\": 12") != std::string::npos);
    assert(first.str().find("\"responses_received\": 7") != std::string::npos);
    assert(first.str().find("\"rtt_ms\": 4.5") != std::string::npos);
    assert(first.str().find("\"tcp_observations\": 0") != std::string::npos);
    assert(first.str().find("\"icmp_observations\": 0") != std::string::npos);
    assert(first.str().find("\"udp_observations\": 0") != std::string::npos);
    assert(first.str().find("\"hostname\": \"www.example.test\"") != std::string::npos);
    assert(first.str().find("\"tunnel\": \"tls\"") != std::string::npos);
    assert(first.str().find("\"certificate_subject\": \"CN=www.example.test\"") != std::string::npos);
    assert(first.str().find("\"certificate_san_names\": [") != std::string::npos);
    assert(first.str().find("\"alpn\": [") != std::string::npos);
    assert(first.str().find(static_cast<char>(0x9b)) == std::string::npos);
    assert(first.str().find("invalid-utf8?") != std::string::npos);

    skan::output::OutputContext compact;
    compact.pretty_json = false;
    std::ostringstream compact_output;
    assert(writer.write(report, compact_output, compact) == skan::output::OutputStatus::Ok);
    assert(compact_output.str().find('\n') == compact_output.str().size() - 1U);
    assert(compact_output.str().find(",]") == std::string::npos);
    return 0;
}
