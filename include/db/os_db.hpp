#ifndef SKAN_DB_OS_DB_HPP
#define SKAN_DB_OS_DB_HPP

#include <string>
#include <vector>

#include "core/status.hpp"
#include "db/db_types.hpp"

namespace skan::db {

class OSFingerprintDatabase final {
public:
    OSFingerprintDatabase() = default;

    static OSFingerprintDatabase parse(
        const std::string &text,
        core::StatusCode &status,
        core::AddressFamily expected_family = core::AddressFamily::Unknown);
    static OSFingerprintDatabase load_file(
        const std::string &path,
        core::StatusCode &status,
        core::AddressFamily expected_family = core::AddressFamily::Unknown);
    static OSFingerprintDatabase built_in();

    core::StatusCode status() const noexcept;
    const std::vector<OSFingerprint> &fingerprints() const noexcept;

private:
    core::StatusCode status_{core::StatusCode::Ok};
    std::vector<OSFingerprint> fingerprints_;
};

} // namespace skan::db

#endif // SKAN_DB_OS_DB_HPP
