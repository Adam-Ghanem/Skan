#include "portscan/port_result.hpp"

namespace skan::portscan {

const char *port_result_state_name(PortState state) noexcept
{
    return port_state_name(state);
}

} // namespace skan::portscan
