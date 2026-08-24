#include "core/types.hpp"

#include <limits>


static_assert(std::numeric_limits<std::uint16_t>::max() >= 65535U,
              "port numbers must support the full 16-bit range");
