#include "core/log.hpp"

#include <chrono>
#include <ctime>
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
    static std::mutex log_mutex;
    const std::lock_guard<std::mutex> lock(log_mutex);
    std::ostream &stream = (level == Level::Warn || level == Level::Error) ? std::cerr : std::cout;

    stream << '[' << timestamp() << "] [" << level_name(level) << "] " << message << '\n';
}

} // namespace skan::log
