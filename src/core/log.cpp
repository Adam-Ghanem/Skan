#include "core/log.hpp"

#include <atomic>
#include <chrono>
#include <ctime>
#include <string_view>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <unistd.h>

#include "core/text_safety.hpp"

namespace skan::log {
namespace {

std::atomic<Level> configured_minimum_level{Level::Info};
std::atomic<bool> terminal_progress_active{false};

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

void set_terminal_progress_active(bool active) noexcept
{
    terminal_progress_active.store(active, std::memory_order_release);
}

void write(Level level, std::string_view message)
{
    if (!enabled(level)) {
        return;
    }
    static std::mutex log_mutex;
    const std::lock_guard<std::mutex> lock(log_mutex);
    const bool clear_active_terminal_line =
        terminal_progress_active.exchange(false, std::memory_order_acq_rel) &&
        ::isatty(STDERR_FILENO) == 1;
    write_to(std::cerr, clear_active_terminal_line, level, message);
}

void write_to(std::ostream &stream, bool clear_active_terminal_line, Level level, std::string_view message)
{
    if (clear_active_terminal_line) {
        stream << "\r\x1b[2K";
    }
    stream << '[' << timestamp() << "] [" << level_name(level) << "] "
           << core::text::sanitize_terminal(message) << '\n';
}

} // namespace skan::log
