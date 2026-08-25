#ifndef SKAN_OUTPUT_OUTPUT_GREPPABLE_HPP
#define SKAN_OUTPUT_OUTPUT_GREPPABLE_HPP

#include "output/output_writer.hpp"

namespace skan::output {

class GrepableOutputWriter final : public OutputWriter {
public:
    OutputFormat format() const noexcept override;
    OutputStatus write(const ScanReport &report, std::ostream &output, const OutputContext &context) const override;
};

} // namespace skan::output

#endif // SKAN_OUTPUT_OUTPUT_GREPPABLE_HPP
