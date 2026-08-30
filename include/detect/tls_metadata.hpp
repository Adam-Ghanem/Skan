#ifndef SKAN_DETECT_TLS_METADATA_HPP
#define SKAN_DETECT_TLS_METADATA_HPP

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace skan::detect {

struct TlsMetadata final {
    bool detected{false};
    std::string protocol_version;
    std::string certificate_subject;
    std::string certificate_issuer;
    std::vector<std::string> certificate_san_names;
    std::string certificate_not_before;
    std::string certificate_not_after;
    std::vector<std::string> alpn;
};

/** Parse bounded, unauthenticated metadata from complete TLS records already received. */
TlsMetadata parse_tls_metadata(std::span<const std::uint8_t> response);

} // namespace skan::detect

#endif // SKAN_DETECT_TLS_METADATA_HPP
