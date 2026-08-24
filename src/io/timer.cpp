#include "io/timer.hpp"

#include <chrono>
#include <cstdint>

static_assert(std::chrono::steady_clock::is_steady,
              "Skan timers require a monotonic steady clock");
static_assert(sizeof(skan::io::TimerId) >= sizeof(std::uint32_t),
              "timer identifiers must support a useful Phase 1 range");
