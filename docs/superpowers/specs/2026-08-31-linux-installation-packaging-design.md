# Skan Linux Installation and Debian Packaging Design

## Status and scope

This design turns Skan 0.1.0 into an installable Linux command while preserving the first-party C++20 scanner, its existing terminal UI, and every supported scan/output option. It covers deterministic runtime-resource discovery, staged installation, Debian packaging, isolated package acceptance, release artifacts, documentation, and CI. It does not add scanner features, publish an APT repository, grant capabilities, install setuid bits, or claim Debian/Ubuntu archive availability.

The implementation starts from `origin/main` at `28972151ae77f4ccb21bf22e740164d630fb788e`, where Phase 33 and the terminal dashboard are already present. The work lives on `codex/linux-packaging` in an isolated worktree.

## User-visible contract

The Debian package installs:

```text
/usr/bin/skan
/usr/share/skan/service-probes.db
/usr/share/skan/udp-probes.db
/usr/share/skan/os-fingerprints.db
/usr/share/skan/os-fingerprints-v6.db
/usr/share/doc/skan/
```

After `sudo apt install ./skan_0.1.0-1_amd64.deb`, `skan --version`, `skan --help`, unprivileged TCP Connect scans, and resource-backed scans work from any directory. The package does not set setuid or file capabilities. Raw SYN, UDP, discovery, and OS-probe modes retain their existing explicit privilege errors and documentation instructs operators to use `sudo` only for those modes.

The immediate supported APT experience is installation of a downloaded local `.deb`. Plain `sudo apt install skan` remains unavailable until Debian/Ubuntu accepts the package or a separately governed signed repository exists.

## Runtime resource architecture

All implicit database lookup moves behind `skan::core::RuntimePaths`. Database parsers remain responsible for parsing; the locator owns path policy.

```cpp
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
    std::vector<std::filesystem::path> data_directories_;
};

}
```

`for_process()` resolves `/proc/self/exe` on Linux and delegates to the pure, injectable constructor. It never uses `current_path()` or a developer path. Candidate roots are bounded and deterministic:

1. `<canonical-executable>/../share/skan`, which yields `/usr/share/skan` for `/usr/bin/skan` and supports portable `bin/` + `share/` layouts.
2. `<canonical-executable>/../data`, which preserves source-tree execution from `bin/skan` without depending on the caller's working directory.
3. The compile-time `SKAN_DATA_DIR`, set by Make from `DATADIR` and set to `/usr/share/skan` for Debian builds.

Duplicate normalized roots are removed. A resource getter returns the first regular readable file. The IPv4 and IPv6 OS databases must come from the same root. If no candidate contains the requested resource, the getter returns the highest-priority canonical path and the existing loader produces its typed `NotFound` status; lookup does not download data or silently switch after a malformed explicit file.

Existing CLI override semantics remain authoritative:

- `--service-db <path>` bypasses automatic service-database selection.
- `--os-db <path>` bypasses the default OS pair in the dedicated `os-detect` flow and is also accepted by the scan flow already advertising it.
- UDP automatic lookup uses the packaged `udp-probes.db`; no new public option is required for this packaging phase.

`ScanConfig` uses empty strings to mean automatic selection for compatibility with its current public shape. The existing relative default for `udp_probe_db_path` is removed. Stage construction resolves automatic paths once, before loading, so asynchronous work never loses resource context.

## Version authority

The repository-root `VERSION` file contains the sole upstream version string, `0.1.0`. Make validates the `MAJOR.MINOR.PATCH` shape and passes its components and bare string as compile definitions. C++ constants expose separate product and version values:

```cpp
SKAN_PRODUCT_NAME       // "Skan"
SKAN_VERSION_STRING     // "0.1.0"
SKAN_DISPLAY_VERSION    // "Skan 0.1.0"
```

CLI `--version` prints the display value once. Structured output stores the bare version so normal output can compose product and version without `Skan Skan 0.1.0`. Debian `0.1.0-1` adds only the Debian revision; `make check-version` verifies the changelog upstream component matches `VERSION`. A `v0.1.0` release workflow verifies the tag against the same file.

## Build and install targets

GNU Make gains conventional variables with safe defaults:

```make
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share/skan
DOCDIR ?= $(PREFIX)/share/doc/skan
DESTDIR ?=
```

`make install DESTDIR=<staging>` installs only the executable, four runtime databases, README, LICENSE, and focused operator documentation beneath the staging root. `DESTDIR` never enters compile definitions. Debian invokes `make install DESTDIR=debian/skan PREFIX=/usr`, producing `/usr/bin/skan` and `/usr/share/skan`.

No Make `uninstall` target is added. System package removal is owned by `dpkg`, while a source-install uninstall target could delete administrator-managed files at configurable prefixes. Package acceptance proves deterministic `dpkg --remove` and `dpkg --purge` cleanup instead.

## Debian package

The package uses debhelper compatibility level 13 and `3.0 (quilt)` source format. `debian/control` declares only factual build dependencies (`debhelper-compat (= 13)`, `g++ (>= 10)`, and `make`) and delegates runtime shared-library dependencies to `${shlibs:Depends}` and `${misc:Depends}`. `Architecture: any` reflects portable source; the validated release artifact is amd64.

`debian/rules` enables all Debian hardening flags, delegates to `dh`, runs the full registered test suite through `dh_auto_test`, and stages through the upstream install target. DEP-5 copyright metadata records the repository's MIT license and project-owned data. The package has no maintainer scripts, conffiles, services, daemons, setuid files, or capabilities.

`make package-deb` uses `scripts/build_deb.sh` to create an isolated source copy under `build/package/source`, runs `dpkg-buildpackage -us -uc -b`, and copies the single resulting `.deb` into `dist/`. All temporary build state stays inside the repository. Generated `build/`, `dist/`, Debian helper state, and package artifacts remain ignored.

## Package acceptance

`tests/packaging/deb_acceptance.sh` runs as root only inside a container with networking disabled and raw/network-admin capabilities dropped. It receives one `.deb`, installs it with `apt-get install -y ./package.deb`, changes to `/tmp/skan-package-acceptance`, and verifies:

- package metadata names `skan` and the expected version/architecture;
- `/usr/bin/skan` is globally discoverable, root-owned, and mode 0755;
- all four `/usr/share/skan` files are non-empty, root-owned, mode 0644, and owned by the package;
- `skan --version` prints exactly `Skan 0.1.0` and `skan --help` succeeds;
- an offline UDP scan loads the installed UDP corpus from outside the source tree;
- an offline OS-detection flow loads the installed IPv4/IPv6 corpus;
- a loopback-only banner fixture proves the full installed service corpus is used;
- an explicit service database fixture overrides the installed default;
- package contents contain no setuid/setgid file, Linux file capability, systemd unit, or maintainer network script;
- `dpkg --remove` removes the executable and runtime data, and `dpkg --purge` removes package registration.

The acceptance image contains only its harness and synthetic fixtures; it never copies repository `data/`. It uses Debian 12 and Ubuntu 24.04 images. `--network none` makes unintended external scans impossible while leaving loopback available. The existing privileged namespace job remains separate and continues to cover raw IPv4/IPv6 behavior using documentation ranges.

## CI and releases

The existing scanner CI jobs remain intact. A new `package-deb-acceptance` job runs after the normal build/test audit, builds the Debian package, runs `dpkg-deb` metadata inspection and `lintian`, then executes the acceptance harness in Debian 12 and Ubuntu 24.04 containers.

`.github/workflows/release.yml` triggers only on `v*` tags. It verifies tag/version/changelog agreement, runs the existing build/test/CLI gates, builds and accepts the package, uploads the `.deb` as an Actions artifact, and creates a GitHub Release through the preinstalled `gh` CLI. Global permissions remain read-only; only the final release job receives `contents: write`. Release jobs use no signing secrets and do not publish an APT repository.

## APT repository readiness

The project follows the official Debian/Ubuntu submission-readiness path. In-repository readiness consists of policy-compliant metadata, source format, copyright, tests, `lintian`, reproducible build inputs, and documented sponsorship/submission steps. External acceptance remains blocked on maintainer/sponsor review and distribution archive processes.

A project-owned APT repository is not fabricated. If chosen later, it requires an owned HTTPS host, a dedicated archive signing key and published fingerprint, signed `InRelease` metadata, a `signed-by=` client keyring, protected publishing credentials, supported-suite policy, rotation/revocation procedures, and retained metadata. `apt-key` and curl-pipe-shell patterns are prohibited.

## Security and failure behavior

- The package never grants privilege; raw modes continue to fail explicitly without required OS capabilities.
- Resource lookup is read-only, bounded, and based on the canonical executable path plus a compile-time FHS directory.
- Explicit database paths never fall through to defaults after failure.
- No post-install network activity, downloads, shell execution from Skan, or writes to `/etc` are introduced.
- Package tests use offline transports, container loopback, or the existing isolated namespace only.
- Missing or malformed resources surface existing typed status failures rather than being guessed or downloaded.

## Verification gates

Completion requires fresh evidence for production build, all registered tests, CLI regression, debug and release builds, ASan/LSan, UBSan, coverage, benchmark, fuzz build/fallback, static/security audit, staged Make install, Debian build, `lintian`, Debian 12 install acceptance, Ubuntu 24.04 install acceptance, clean diff, independent code review, pushed PR CI, and verified post-merge `main` CI. Any unavailable check is reported factually and prevents an unsupported compatibility claim.
