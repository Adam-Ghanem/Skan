#include "db/os_db_loader.hpp"

namespace skan::db {

OSFingerprintDatabase load_os_database(const std::string &path, core::StatusCode &status)
{
    return OSFingerprintDatabase::load_file(path, status);
}

} // namespace skan::db
