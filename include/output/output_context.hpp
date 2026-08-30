#ifndef SKAN_OUTPUT_OUTPUT_CONTEXT_HPP
#define SKAN_OUTPUT_OUTPUT_CONTEXT_HPP

namespace skan::output {

struct OutputContext final {
    bool include_hostnames{true};
    bool include_closed_ports{true};
    bool include_filtered_ports{true};
    bool include_unknown{true};
    bool open_only{false};
    bool include_reasons{false};
    bool pretty_json{true};
    bool pretty_xml{true};
    bool color_enabled{false};
    bool interactive_terminal{false};
};

} // namespace skan::output

#endif // SKAN_OUTPUT_OUTPUT_CONTEXT_HPP
