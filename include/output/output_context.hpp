#ifndef SKAN_OUTPUT_OUTPUT_CONTEXT_HPP
#define SKAN_OUTPUT_OUTPUT_CONTEXT_HPP

namespace skan::output {

struct OutputContext final {
    bool include_hostnames{true};
    bool include_closed_ports{true};
    bool include_filtered_ports{true};
    bool include_unknown{true};
    bool pretty_json{true};
    bool pretty_xml{true};
    bool color_enabled{false};
};

} // namespace skan::output

#endif // SKAN_OUTPUT_OUTPUT_CONTEXT_HPP
