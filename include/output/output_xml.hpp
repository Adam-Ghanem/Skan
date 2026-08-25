#ifndef SKAN_OUTPUT_OUTPUT_XML_HPP
#define SKAN_OUTPUT_OUTPUT_XML_HPP

#include "output/output_writer.hpp"

namespace skan::output {

class XmlOutputWriter final : public OutputWriter {
public:
    OutputFormat format() const noexcept override;
    OutputStatus write(const ScanReport &report, std::ostream &output, const OutputContext &context) const override;
};

} // namespace skan::output

#endif // SKAN_OUTPUT_OUTPUT_XML_HPP
