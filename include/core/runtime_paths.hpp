#ifndef SKAN_CORE_RUNTIME_PATHS_HPP
#define SKAN_CORE_RUNTIME_PATHS_HPP

#include <filesystem>
#include <vector>

namespace skan::core {

struct OSFingerprintPaths final {
    std::filesystem::path ipv4;
    std::filesystem::path ipv6;
};

class RuntimePaths final {
public:
    static RuntimePaths for_process();
    static RuntimePaths from_executable(
        std::filesystem::path executable,
        std::filesystem::path compiled_data_directory);

    std::filesystem::path service_probe_db() const;
    std::filesystem::path udp_probe_db() const;
    OSFingerprintPaths os_fingerprint_dbs() const;

private:
    RuntimePaths() = default;

    std::vector<std::filesystem::path> data_directories_;
};

} // namespace skan::core

#endif // SKAN_CORE_RUNTIME_PATHS_HPP
