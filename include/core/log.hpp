#ifndef SKAN_CORE_LOG_HPP
#define SKAN_CORE_LOG_HPP

#include <sstream>
#include <iosfwd>
#include <string>
#include <string_view>

namespace skan::log {

enum class Level {
    Debug,
    Info,
    Warn,
    Error
};

void set_minimum_level(Level level) noexcept;
Level minimum_level() noexcept;
void set_terminal_progress_active(bool active) noexcept;
void write_to(std::ostream &stream, bool clear_active_terminal_line, Level level, std::string_view message);
void write(Level level, std::string_view message);

namespace detail {

template <typename Value>
std::string render_argument(const Value &value)
{
    std::ostringstream stream;
    stream << value;
    return stream.str();
}

inline std::string format_message(std::string_view format)
{
    return std::string(format);
}

template <typename... Arguments>
std::string format_message(std::string_view format, const Arguments &...arguments)
{
    const std::string rendered[] = {render_argument(arguments)...};
    std::string result;
    std::size_t argument_index = 0U;
    std::size_t cursor = 0U;

    while (cursor < format.size()) {
        const std::size_t placeholder = format.find("{}", cursor);
        if (placeholder == std::string_view::npos) {
            result.append(format.substr(cursor));
            break;
        }

        result.append(format.substr(cursor, placeholder - cursor));
        if (argument_index < sizeof...(Arguments)) {
            result.append(rendered[argument_index]);
            ++argument_index;
        } else {
            result.append("{}");
        }
        cursor = placeholder + 2U;
    }

    return result;
}

} // namespace detail

template <typename... Arguments>
void debug(std::string_view format, const Arguments &...arguments)
{
    write(Level::Debug, detail::format_message(format, arguments...));
}

template <typename... Arguments>
void info(std::string_view format, const Arguments &...arguments)
{
    write(Level::Info, detail::format_message(format, arguments...));
}

template <typename... Arguments>
void warn(std::string_view format, const Arguments &...arguments)
{
    write(Level::Warn, detail::format_message(format, arguments...));
}

template <typename... Arguments>
void error(std::string_view format, const Arguments &...arguments)
{
    write(Level::Error, detail::format_message(format, arguments...));
}

} // namespace skan::log

#endif // SKAN_CORE_LOG_HPP
