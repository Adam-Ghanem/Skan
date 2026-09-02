#include "output/output_normal.hpp"

#include "output/terminal/report_renderer.hpp"

namespace skan::output {

OutputFormat NormalOutputWriter::format() const noexcept
{
    return OutputFormat::Normal;
}

OutputStatus NormalOutputWriter::write(
    const ScanReport &report,
    std::ostream &output,
    const OutputContext &context) const
{
    return TerminalReportRenderer{}.render(report, output, context);
}

} // namespace skan::output
