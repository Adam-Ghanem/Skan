#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string_view>

#include "core/runtime_paths.hpp"

namespace {

namespace fs = std::filesystem;

class TemporaryTree final {
public:
    TemporaryTree()
        : path_(fs::temp_directory_path() /
                ("skan-runtime-paths-" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())))
    {
        fs::create_directories(path_);
    }

    ~TemporaryTree()
    {
        std::error_code error;
        fs::remove_all(path_, error);
    }

    TemporaryTree(const TemporaryTree &) = delete;
    TemporaryTree &operator=(const TemporaryTree &) = delete;

    const fs::path &path() const noexcept { return path_; }

private:
    fs::path path_;
};

class CurrentPathGuard final {
public:
    CurrentPathGuard() : original_(fs::current_path()) {}
    ~CurrentPathGuard()
    {
        std::error_code error;
        fs::current_path(original_, error);
    }

    CurrentPathGuard(const CurrentPathGuard &) = delete;
    CurrentPathGuard &operator=(const CurrentPathGuard &) = delete;

private:
    fs::path original_;
};

void write_file(const fs::path &path, std::string_view contents)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path);
    assert(output);
    output << contents;
    assert(output.good());
}

} // namespace

int main()
{
    TemporaryTree temporary;
    const fs::path fake_root = temporary.path() / "portable";
    const fs::path fake_system_root = temporary.path() / "system-share";
    const fs::path unrelated_cwd = temporary.path() / "empty-cwd";

    write_file(fake_root / "bin/skan", "executable");
    write_file(fake_root / "share/skan/service-probes.db", "installed");
    write_file(fake_root / "data/udp-probes.db", "source");

    // Split higher-priority files must not be combined into a false OS pair.
    write_file(fake_root / "share/skan/os-fingerprints.db", "ipv4-only");
    write_file(fake_root / "data/os-fingerprints-v6.db", "ipv6-only");
    write_file(fake_system_root / "os-fingerprints.db", "system-ipv4");
    write_file(fake_system_root / "os-fingerprints-v6.db", "system-ipv6");
    fs::create_directories(unrelated_cwd);

    const skan::core::RuntimePaths paths = skan::core::RuntimePaths::from_executable(
        fake_root / "bin/skan", fake_system_root);

    CurrentPathGuard cwd_guard;
    fs::current_path(unrelated_cwd);

    assert(paths.service_probe_db() == fake_root / "share/skan/service-probes.db");
    assert(paths.udp_probe_db() == fake_root / "data/udp-probes.db");

    const skan::core::OSFingerprintPaths os_paths = paths.os_fingerprint_dbs();
    assert(os_paths.ipv4 == fake_system_root / "os-fingerprints.db");
    assert(os_paths.ipv6 == fake_system_root / "os-fingerprints-v6.db");
    assert(os_paths.ipv4.parent_path() == os_paths.ipv6.parent_path());

    return 0;
}
