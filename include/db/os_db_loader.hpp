#ifndef SKAN_DB_OS_DB_LOADER_HPP
#define SKAN_DB_OS_DB_LOADER_HPP

#include <string>

#include "db/os_db.hpp"

namespace skan::db {

OSFingerprintDatabase load_os_database(const std::string &path, core::StatusCode &status);

} // namespace skan::db

#endif // SKAN_DB_OS_DB_LOADER_HPP
