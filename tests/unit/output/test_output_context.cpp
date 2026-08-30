#include <cassert>

#include "output/output_context.hpp"

int main()
{
    const skan::output::OutputContext context;
    assert(context.include_hostnames);
    assert(context.include_closed_ports);
    assert(context.include_filtered_ports);
    assert(context.include_unknown);
    assert(!context.open_only);
    assert(!context.include_reasons);
    assert(context.pretty_json);
    assert(context.pretty_xml);
    assert(!context.color_enabled);

    skan::output::OutputContext machine;
    machine.open_only = true;
    machine.include_reasons = true;
    machine.pretty_json = false;
    machine.pretty_xml = false;
    machine.color_enabled = true;
    assert(machine.open_only);
    assert(machine.include_reasons);
    assert(!machine.pretty_json);
    assert(!machine.pretty_xml);
    assert(machine.color_enabled);
    return 0;
}
