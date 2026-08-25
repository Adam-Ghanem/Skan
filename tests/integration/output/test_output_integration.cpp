#include <cassert>
#include <sstream>
#include <string>

#include "output/output_manager.hpp"
#include "../../unit/output/output_test_fixture.hpp"

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
    return 0;
}
