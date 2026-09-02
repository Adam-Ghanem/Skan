#ifndef SKAN_OUTPUT_TERMINAL_REPORT_RENDERER_HPP
#define SKAN_OUTPUT_TERMINAL_REPORT_RENDERER_HPP

#include <iosfwd>

#include "output/output_context.hpp"
#include "output/result_model.hpp"

namespace skan::output {

class TerminalReportRenderer final {
public:
    OutputStatus render(
        const ScanReport &report,
        std::ostream &output,
        const OutputContext &context) const;
};

} // namespace skan::output

#endif // SKAN_OUTPUT_TERMINAL_REPORT_RENDERER_HPP
