#ifndef SKAN_OUTPUT_OUTPUT_WRITER_HPP
#define SKAN_OUTPUT_OUTPUT_WRITER_HPP

#include <iosfwd>
#include <string>
#include <vector>

#include "output/output_context.hpp"
#include "output/result_model.hpp"

namespace skan::output {

class OutputWriter {
public:
    virtual ~OutputWriter() = default;

    virtual OutputFormat format() const noexcept = 0;
    virtual OutputStatus write(
        const ScanReport &report,
        std::ostream &output,
        const OutputContext &context) const = 0;
};

namespace detail {
std::vector<const HostResult *> ordered_hosts(const ScanReport &report);
std::vector<const portscan::PortResult *> ordered_ports(const HostResult &host, const OutputContext &context);
std::vector<const detect::ServiceResult *> ordered_services(const HostResult &host);
std::vector<const osdetect::OSMatchResult *> ordered_os_matches(const HostResult &host);
std::string json_escape(std::string_view value);
std::string xml_escape(std::string_view value);
std::string grep_escape(std::string_view value);
std::string number(double value);
OutputStatus check_stream(std::ostream &output) noexcept;
} // namespace detail

} // namespace skan::output

#endif // SKAN_OUTPUT_OUTPUT_WRITER_HPP
