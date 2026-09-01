#include "core/runtime_paths.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <string_view>
#include <system_error>
#include <utility>

#ifndef SKAN_DATA_DIR
#error "SKAN_DATA_DIR must be supplied by the build system"
#endif

namespace skan::core {
namespace {

namespace fs = std::filesystem;

fs::path normalized_path(fs::path path)
{
    if (path.is_absolute()) {
        std::error_code error;
        const fs::path canonical = fs::weakly_canonical(path, error);
        if (!error) {
            return canonical.lexically_normal();
        }
    }
    return path.lexically_normal();
}

bool readable_regular_file(const fs::path &path)
{
    std::error_code error;
    if (!fs::is_regular_file(path, error) || error) {
        return false;
    }
    std::ifstream input(path);
    return input.good();
}

fs::path first_resource(
    const std::vector<fs::path> &data_directories,
    std::string_view filename)
{
    for (const fs::path &directory : data_directories) {
        const fs::path candidate = directory / filename;
        if (readable_regular_file(candidate)) {
            return candidate;
        }
    }
    return data_directories.front() / filename;
}

} // namespace

RuntimePaths RuntimePaths::for_process()
{
    std::error_code error;
    fs::path executable = fs::read_symlink("/proc/self/exe", error);
    if (error) {
        executable = "/proc/self/exe";
    }
    return from_executable(std::move(executable), SKAN_DATA_DIR);
}

RuntimePaths RuntimePaths::from_executable(
    fs::path executable,
    fs::path compiled_data_directory)
{
    RuntimePaths paths;
    const fs::path executable_directory = normalized_path(std::move(executable)).parent_path();
    const std::array<fs::path, 3U> candidates{
        normalized_path(executable_directory / ".." / "share" / "skan"),
        normalized_path(executable_directory / ".." / "data"),
        normalized_path(std::move(compiled_data_directory))};
    for (const fs::path &candidate : candidates) {
        if (std::find(paths.data_directories_.begin(), paths.data_directories_.end(), candidate) ==
            paths.data_directories_.end()) {
            paths.data_directories_.push_back(candidate);
        }
    }
    return paths;
}

fs::path RuntimePaths::service_probe_db() const
{
    return first_resource(data_directories_, "service-probes.db");
}

fs::path RuntimePaths::udp_probe_db() const
{
    return first_resource(data_directories_, "udp-probes.db");
}

OSFingerprintPaths RuntimePaths::os_fingerprint_dbs() const
{
    for (const fs::path &directory : data_directories_) {
        const fs::path ipv4 = directory / "os-fingerprints.db";
        const fs::path ipv6 = directory / "os-fingerprints-v6.db";
        if (readable_regular_file(ipv4) && readable_regular_file(ipv6)) {
            return OSFingerprintPaths{ipv4, ipv6};
        }
    }
    return OSFingerprintPaths{
        data_directories_.front() / "os-fingerprints.db",
        data_directories_.front() / "os-fingerprints-v6.db"};
}

} // namespace skan::core
