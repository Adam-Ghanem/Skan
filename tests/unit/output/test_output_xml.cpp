#include <cassert>
#include <sstream>
#include <string>

#include "output/output_xml.hpp"
#include "output_test_fixture.hpp"

int main()
{
    skan::output::XmlOutputWriter writer;
    const skan::output::ScanReport report = skan::output::test::make_report();
    std::ostringstream first;
    std::ostringstream second;
    assert(writer.write(report, first, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(writer.write(report, second, skan::output::OutputContext{}) == skan::output::OutputStatus::Ok);
    assert(first.str() == second.str());
    assert(first.str().find("<?xml version=\"1.0\"") == 0U);
    assert(first.str().find("<skan version=\"0.1.0\">") != std::string::npos);
    assert(first.str().find("&lt;unsafe&gt;") != std::string::npos);
    assert(first.str().find("&amp;") != std::string::npos);
    assert(first.str().find("&quot;") != std::string::npos);
    assert(first.str().find("&apos;") != std::string::npos);
    assert(first.str().find("<host address=\"192.0.2.10\"") <
           first.str().find("<host address=\"192.0.2.20\""));
    assert(first.str().find("<port target=\"192.0.2.20\" number=\"22\"") <
           first.str().find("<port target=\"192.0.2.20\" number=\"80\""));
    assert(first.str().find("<os>") != std::string::npos);
    return 0;
}
