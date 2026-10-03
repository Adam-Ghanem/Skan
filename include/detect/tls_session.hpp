#ifndef SKAN_DETECT_TLS_SESSION_HPP
#define SKAN_DETECT_TLS_SESSION_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

#include "detect/tls_metadata.hpp"

namespace skan::detect {

bool valid_tls_server_name(std::string_view name) noexcept;

enum class TlsIoState { Ready, WantRead, WantWrite, Closed, Error };

struct TlsIoResult final {
    TlsIoState state{TlsIoState::Error};
    std::size_t bytes{0U};
    int system_error{0};
};

/** Nonblocking TLS over a borrowed socket; never owns/closes the descriptor. */
class TlsSession final {
public:
    explicit TlsSession(int descriptor, std::string_view server_name = {});
    ~TlsSession();
    TlsSession(const TlsSession &) = delete;
    TlsSession &operator=(const TlsSession &) = delete;

    bool valid() const noexcept;
    TlsIoResult handshake() noexcept;
    TlsIoResult write(std::span<const std::uint8_t> data) noexcept;
    TlsIoResult read(std::span<std::uint8_t> data) noexcept;
    TlsMetadata metadata() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace skan::detect
#endif
