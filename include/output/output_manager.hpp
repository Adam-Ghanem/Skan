#ifndef SKAN_OUTPUT_OUTPUT_MANAGER_HPP
#define SKAN_OUTPUT_OUTPUT_MANAGER_HPP

#include <memory>

#include "output/output_writer.hpp"

namespace skan::output {

class OutputManager final {
public:
    static std::unique_ptr<OutputWriter> create(OutputFormat format);
    static OutputStatus write(
        OutputFormat format,
        const ScanReport &report,
        std::ostream &output,
        const OutputContext &context = OutputContext{});
};

} // namespace skan::output

#endif // SKAN_OUTPUT_OUTPUT_MANAGER_HPP
