#include "output/output_context.hpp"

namespace skan::output {

static_assert(OutputContext{}.color_enabled == false);
static_assert(OutputContext{}.interactive_terminal == false);

} // namespace skan::output
