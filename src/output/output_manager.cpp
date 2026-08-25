#include "output/output_manager.hpp"

#include "output/output_grepable.hpp"
#include "output/output_json.hpp"
#include "output/output_normal.hpp"
#include "output/output_xml.hpp"

namespace skan::output {

std::unique_ptr<OutputWriter> OutputManager::create(OutputFormat format)
{
    switch (format) {
    case OutputFormat::Normal:
        return std::make_unique<NormalOutputWriter>();
    case OutputFormat::Json:
        return std::make_unique<JsonOutputWriter>();
    case OutputFormat::Xml:
        return std::make_unique<XmlOutputWriter>();
    case OutputFormat::Grepable:
        return std::make_unique<GrepableOutputWriter>();
    }
    return nullptr;
}

OutputStatus OutputManager::write(
    OutputFormat format,
    const ScanReport &report,
    std::ostream &output,
    const OutputContext &context)
{
    const std::unique_ptr<OutputWriter> writer = create(format);
    if (writer == nullptr) {
        return OutputStatus::InvalidFormat;
    }
    return writer->write(report, output, context);
}

} // namespace skan::output
