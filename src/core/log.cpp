#include "core/log.hpp"

#include <chrono>
#include <ctime>
#include <cstdlib>
#include <string_view>
#include <iomanip>
#include <iostream>
#include <mutex>

namespace skan::log {
namespace {

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
    if (level != Level::Debug) {
        return true;
    }
    const char *configured = std::getenv("SKAN_LOG");
    return configured != nullptr && std::string_view(configured) == "debug";
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
