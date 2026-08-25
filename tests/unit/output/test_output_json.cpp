#include <cassert>
#include <sstream>
#include <string>

#include "output/output_json.hpp"
#include "output_test_fixture.hpp"

int main()
{
    skan::output::JsonOutputWriter writer;
    const skan::output::ScanReport report = skan::output::test::make_report();
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

    skan::output::OutputContext compact;
    compact.pretty_json = false;
    std::ostringstream compact_output;
    assert(writer.write(report, compact_output, compact) == skan::output::OutputStatus::Ok);
    assert(compact_output.str().find('\n') == compact_output.str().size() - 1U);
    assert(compact_output.str().find(",]") == std::string::npos);
    return 0;
}
