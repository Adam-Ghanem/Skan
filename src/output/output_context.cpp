#include "output/output_context.hpp"

namespace skan::output {

static_assert(OutputContext{}.terminal.interactive == false);
static_assert(OutputContext{}.terminal.color == false);

} // namespace skan::output
