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
