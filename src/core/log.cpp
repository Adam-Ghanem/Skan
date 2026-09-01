#include "core/log.hpp"

#include <atomic>
#include <chrono>
#include <ctime>
#include <string_view>
#include <iomanip>
#include <iostream>
#include <mutex>

namespace skan::log {
namespace {

std::atomic<Level> configured_minimum_level{Level::Info};

const char *level_name(Level level) noexcept
{
    switch (level) {
    case Level::Debug:
        return "DEBUG";
    case Level::Info:
        return "INFO";
    case Level::Warn:
        return "WARN";
    case Level::Error:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

bool enabled(Level level) noexcept
{
    return static_cast<unsigned int>(level) >=
           static_cast<unsigned int>(configured_minimum_level.load(std::memory_order_relaxed));
}

std::string timestamp()
{
    const std::time_t now = std::time(nullptr);
    std::tm local_time{};
    if (localtime_r(&now, &local_time) == nullptr) {
        return "0000-00-00 00:00:00";
    }

    std::ostringstream stream;
    stream << std::put_time(&local_time, "%Y-%m-%d %H:%M:%S");
    return stream.str();
}

} // namespace

void set_minimum_level(Level level) noexcept
{
    configured_minimum_level.store(level, std::memory_order_relaxed);
}

Level minimum_level() noexcept
{
    return configured_minimum_level.load(std::memory_order_relaxed);
}

void write(Level level, std::string_view message)
{
    if (!enabled(level)) {
        return;
    }
    static std::mutex log_mutex;
    const std::lock_guard<std::mutex> lock(log_mutex);
    std::ostream &stream = std::cerr;

    stream << '[' << timestamp() << "] [" << level_name(level) << "] " << message << '\n';
}

} // namespace skan::log
