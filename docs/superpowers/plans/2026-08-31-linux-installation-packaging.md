# Skan Linux Installation and Debian Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce and validate a Debian package that installs Skan globally with all runtime databases and works from an unrelated directory without source-tree knowledge.

**Architecture:** A C++20 `RuntimePaths` boundary resolves packaged or executable-relative resources without consulting the current directory. GNU Make owns the authoritative version/build/install contract; debhelper stages that contract into a policy-compliant package, and container acceptance tests exercise the installed artifact rather than the source tree.

**Tech Stack:** C++20, GNU Make, Bash, Debian debhelper 13/dpkg/lintian, Docker, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-31-linux-installation-packaging-design.md`

## Global Constraints

- Preserve the first-party C++ scanner; never execute or delegate scanning to Nmap.
- Runtime data install under `/usr/share/skan`; the Debian executable installs as `/usr/bin/skan`.
- Explicit `--service-db` and `--os-db` paths override defaults and fail visibly when invalid.
- Runtime lookup never depends on cwd, a developer home path, `/mnt/c`, or the Git worktree layout.
- Default packaging installs no SUID bit, Linux file capability, maintainer network script, daemon, or systemd unit.
- Package acceptance uses offline transports, container loopback, documentation addresses, or the existing namespace lab only.
- `VERSION` is the single upstream version authority; the initial upstream version is exactly `0.1.0`.
- Debian package version is exactly `0.1.0-1`; the validated amd64 artifact is `skan_0.1.0-1_amd64.deb`.
- Existing terminal UI and all Phase 33 CLI/output behavior remain covered by the full suite and CLI regression.
- No claim that plain repository-level `sudo apt install skan` works until external archive acceptance or a signed hosted repository exists.

---

### Task 1: Authoritative version and deterministic runtime resources

**Files:**
- Create: `VERSION`
- Create: `include/core/runtime_paths.hpp`
- Create: `src/core/runtime_paths.cpp`
- Create: `tests/unit/core/test_runtime_paths.cpp`
- Modify: `include/core/constants.hpp`
- Modify: `include/output/result_model.hpp`
- Modify: `src/main.cpp`
- Modify: `include/orchestrator/scan_config.hpp`
- Modify: `src/orchestrator/scan_stage.cpp`
- Modify: `src/detect/service_db.cpp`
- Modify: `src/db/os_db.cpp`
- Modify: `Makefile`
- Modify: `tests/unit/core/test_constants.cpp`
- Modify: `tests/unit/output/test_output_normal.cpp`
- Modify: `tests/integration/cli/test_nmap_compat.sh`

**Interfaces:**
- Produces: `RuntimePaths::for_process()`, `RuntimePaths::from_executable(path, path)`, `service_probe_db()`, `udp_probe_db()`, and `os_fingerprint_dbs()`.
- Produces: `SKAN_PRODUCT_NAME == "Skan"`, bare `SKAN_VERSION_STRING == "0.1.0"`, and display `SKAN_DISPLAY_VERSION == "Skan 0.1.0"`.
- Consumes: existing database `load_file` functions and typed `core::StatusCode` failures.

- [ ] **Step 1: Add failing resource-location unit tests**

  Create temporary fake roots beneath the test process temporary directory. Construct `RuntimePaths::from_executable(fake_root / "bin/skan", fake_system_root)` and assert literal expected paths for service, UDP, and an atomic IPv4/IPv6 OS pair. Change cwd to a second empty directory before assertions. Include these cases:

  ```cpp
  // installed/portable root wins
  write_file(fake_root / "share/skan/service-probes.db", "installed");
  assert(paths.service_probe_db() == fake_root / "share/skan/service-probes.db");

  // source fallback is executable-relative, not cwd-relative
  write_file(fake_root / "data/udp-probes.db", "source");
  assert(paths.udp_probe_db() == fake_root / "data/udp-probes.db");

  // both OS files must come from one root
  assert(paths.os_fingerprint_dbs().ipv4.parent_path() ==
         paths.os_fingerprint_dbs().ipv6.parent_path());
  ```

  Before writing the test body, name the mutation: replacing executable-relative roots with `current_path()/data` must fail this test.

- [ ] **Step 2: Run the focused test and record RED**

  Run:

  ```bash
  make build/test_runtime_paths
  ```

  Expected RED: compilation fails because `core/runtime_paths.hpp` and `RuntimePaths` do not exist.

- [ ] **Step 3: Implement minimal `RuntimePaths`**

  Use `std::filesystem` with `std::error_code`. Resolve `/proc/self/exe` in `for_process()`. Build and de-duplicate the exact candidate roots from the spec. Never call `current_path()`. Return the first regular file for single resources, require both OS files under the same root, and otherwise return the top canonical candidate so the existing loader reports `NotFound`.

- [ ] **Step 4: Wire automatic stage/database defaults**

  Add `src/core/runtime_paths.cpp` to `CPP_SOURCES` and its object to every relevant test link group. Make `ScanConfig::udp_probe_db_path` empty by default. In UDP/service/OS stages, use the locator only when the explicit config path is empty. Update `ServiceProbeDatabase::built_in()` and `OSFingerprintDatabase::built_in()` to delegate path policy to the locator while preserving service's compact embedded recovery only when all automatic service paths are absent.

- [ ] **Step 5: Verify resource tests GREEN and run affected suites**

  Run:

  ```bash
  make build/test_runtime_paths build/test_service_db build/test_os_db build/test_scan_stage
  ./build/test_runtime_paths
  ./build/test_service_db
  ./build/test_os_db
  ./build/test_scan_stage
  ```

  Expected: all exit 0, and the resource test still passes after changing cwd.

- [ ] **Step 6: Add failing version/output/CLI tests**

  Update constants and output tests to require bare and display forms. Add CLI assertions:

  ```bash
  test "$(./bin/skan --version)" = "Skan 0.1.0"
  ! ./bin/skan --version | grep -F "Skan Skan"
  ```

  Add a scan-parser regression proving `scan ... --os-detect --os-db <fixture>` is accepted. Name the mutations: a hardcoded second version or a missing scan-mode `--os-db` branch must fail.

- [ ] **Step 7: Run version/CLI tests and record RED**

  Run:

  ```bash
  make build/test_constants build/test_output_normal
  ./build/test_constants
  ./build/test_output_normal
  bash tests/integration/cli/test_nmap_compat.sh
  ```

  Expected RED: constants/output expect the new split version contract and scan-mode `--os-db` is rejected.

- [ ] **Step 8: Implement the single version source and scan override**

  Add `VERSION` containing only `0.1.0`. Make reads and validates it, supplies `SKAN_VERSION_VALUE`, `SKAN_VERSION_MAJOR_VALUE`, `SKAN_VERSION_MINOR_VALUE`, and `SKAN_VERSION_PATCH_VALUE`, and defines `SKAN_DATA_DIR` from `DATADIR` without `DESTDIR`. Update C++ constants/output/CLI and the scan parser. Do not copy `0.1.0` into another production source file.

- [ ] **Step 9: Verify GREEN and commit Task 1**

  Run affected tests plus the full CLI regression. On a Windows CRLF checkout, run the unchanged script through `bash <(sed 's/\r$//' ...)` and record that environmental adaptation. Then commit:

  ```bash
  git add VERSION include/core/runtime_paths.hpp src/core/runtime_paths.cpp include/core/constants.hpp include/output/result_model.hpp include/orchestrator/scan_config.hpp src/main.cpp src/orchestrator/scan_stage.cpp src/detect/service_db.cpp src/db/os_db.cpp Makefile tests/unit/core/test_runtime_paths.cpp tests/unit/core/test_constants.cpp tests/unit/output/test_output_normal.cpp tests/integration/cli/test_nmap_compat.sh
  git commit -m "feat(runtime): locate installed resources deterministically"
  ```

### Task 2: Staged system installation contract

**Files:**
- Create: `tests/packaging/test_make_install.sh`
- Modify: `Makefile`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `VERSION`, `bin/skan`, and the four files under `data/`.
- Produces: `make install DESTDIR=<root> PREFIX=/usr` with exact FHS paths and modes.
- Produces: `make check-version` for package/tag consumers.

- [ ] **Step 1: Write a failing staged-install behavior test**

  The script creates a temporary staging directory, runs `make install DESTDIR="$stage" PREFIX=/usr`, and asserts exact files and modes:

  ```bash
  test -x "$stage/usr/bin/skan"
  test "$(stat -c %a "$stage/usr/bin/skan")" = 755
  for db in service-probes.db udp-probes.db os-fingerprints.db os-fingerprints-v6.db; do
    test -s "$stage/usr/share/skan/$db"
    test "$(stat -c %a "$stage/usr/share/skan/$db")" = 644
  done
  test ! -e "$stage/usr/local"
  (cd /tmp && "$stage/usr/bin/skan" --version)
  ```

  Name the mutation: omitting any data file or compiling `DESTDIR` into the binary must fail.

- [ ] **Step 2: Run and record RED**

  Run `bash tests/packaging/test_make_install.sh`.
  Expected RED: `make: *** No rule to make target 'install'`.

- [ ] **Step 3: Implement Make install/check-version targets**

  Add `PREFIX`, `BINDIR`, `DATADIR`, `DOCDIR`, `DESTDIR`, and `INSTALL`. Install the binary as 0755 and data/docs as 0644. Add `check-version` that extracts the upstream part of `debian/changelog` when present and compares it with `VERSION`. Do not add an uninstall target.

- [ ] **Step 4: Verify GREEN and commit Task 2**

  Run the staged install test twice with different temporary directories to prove staging independence, then:

  ```bash
  git add Makefile .gitignore tests/packaging/test_make_install.sh
  git commit -m "build: add staged Linux installation"
  ```

### Task 3: Debian metadata, package build, and installed-artifact acceptance

**Files:**
- Create: `debian/changelog`
- Create: `debian/control`
- Create: `debian/copyright`
- Create: `debian/rules`
- Create: `debian/source/format`
- Create: `debian/skan.docs`
- Create: `debian/tests/control`
- Create: `debian/tests/smoke`
- Create: `scripts/build_deb.sh`
- Create: `scripts/test_deb_package.sh`
- Create: `tests/packaging/deb_acceptance.sh`
- Create: `tests/packaging/fixtures/banner_server.py`
- Create: `tests/packaging/fixtures/service-override.db`
- Create: `tests/packaging/fixtures/os-override.db`
- Create: `tests/packaging/fixtures/invalid.db`
- Modify: `Makefile`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `make install`, `VERSION`, Docker, debhelper 13, dpkg, lintian.
- Produces: exactly one `dist/skan_0.1.0-1_amd64.deb` on amd64.
- Produces: `scripts/test_deb_package.sh <deb> debian:12` and `... ubuntu:24.04` acceptance entry points.

- [ ] **Step 1: Write the package acceptance harness before packaging**

  Implement assertions from the spec against an input `.deb`. Use `apt-get install -y "$deb"` inside the container, change to an empty `/tmp/skan-package-acceptance`, and test exact version/help output, global command lookup, dpkg ownership, file modes, no setuid/setgid/capabilities/systemd/maintainer scripts, offline OS/UDP lookup, loopback-only service detection, explicit service and OS overrides, and invalid override failures. Use traps to terminate only fixture PIDs created by the script.

- [ ] **Step 2: Run the harness with no package and record RED**

  Run:

  ```bash
  tests/packaging/deb_acceptance.sh dist/skan_0.1.0-1_amd64.deb
  ```

  Expected RED: the input package does not exist.

- [ ] **Step 3: Add policy-compliant Debian metadata**

  Use source format `3.0 (quilt)`, debhelper compat 13, MIT DEP-5 copyright, `Architecture: any`, and only `${shlibs:Depends}, ${misc:Depends}` runtime dependency substitution. `debian/rules` exports `DEB_BUILD_MAINT_OPTIONS = hardening=+all`, delegates to `dh`, and stages with `$(MAKE) install DESTDIR=$(CURDIR)/debian/skan PREFIX=/usr`.

- [ ] **Step 4: Implement repository-local package build**

  `scripts/build_deb.sh` checks required commands, clears only resolved `build/package` and `dist` directories inside the repository, copies the source tree while excluding `.git`, `.worktrees`, `build`, `bin`, and `dist`, runs `dpkg-buildpackage -us -uc -b`, verifies exactly one `.deb`, and copies it to `dist/`. Add `make package-deb` as a wrapper.

- [ ] **Step 5: Build the package and fix metadata failures systematically**

  In a Debian 12 builder container install only `build-essential`, `debhelper`, `devscripts`, `dpkg-dev`, and `lintian`, mount the repository, and run `make package-deb`. Inspect `dpkg-deb --info`, `dpkg-deb --contents`, and `lintian --display-info --fail-on error`. Expected artifact: `dist/skan_0.1.0-1_amd64.deb`.

- [ ] **Step 6: Run Debian 12 acceptance and record GREEN**

  Run the container through `scripts/test_deb_package.sh dist/skan_0.1.0-1_amd64.deb debian:12`. It must use `--network none --cap-drop=NET_RAW --cap-drop=NET_ADMIN` for the acceptance container and exit 0 after uninstall/purge checks.

- [ ] **Step 7: Run Ubuntu 24.04 acceptance and record GREEN**

  Run `scripts/test_deb_package.sh dist/skan_0.1.0-1_amd64.deb ubuntu:24.04`. Require the same assertions and exit 0; do not extrapolate to any untested distro.

- [ ] **Step 8: Commit Task 3**

  ```bash
  git add debian scripts/build_deb.sh scripts/test_deb_package.sh tests/packaging Makefile .gitignore
  git commit -m "feat(packaging): build and validate Debian package"
  ```

### Task 4: CI, release automation, and end-user documentation

**Files:**
- Create: `.github/workflows/release.yml`
- Create: `docs/INSTALLATION.md`
- Create: `docs/DEBIAN_PACKAGING.md`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`
- Modify: `docs/SERVICE_FINGERPRINTS.md`
- Modify: `SECURITY.md`

**Interfaces:**
- Consumes: `make package-deb` and `scripts/test_deb_package.sh`.
- Produces: PR/push package validation and tag-only GitHub release publication.
- Produces: accurate end-user install and privilege documentation.

- [ ] **Step 1: Add CI workflow syntax/contract tests**

  Extend the static audit to parse both workflows with a YAML parser available in CI or Ruby's standard YAML parser. Add shell syntax checks for every new script. Validate that the release workflow has global `contents: read`, grants `contents: write` only to its publish job, triggers only on `v*`, and invokes both distro acceptance commands.

- [ ] **Step 2: Add the package CI job**

  Preserve the existing scanner jobs unchanged. Add `package-deb-acceptance` with `needs: build-test-audit`, Ubuntu 24.04, minimal packaging dependencies, package build, metadata/lintian checks, and Debian 12 plus Ubuntu 24.04 acceptance. Upload the `.deb` with a bounded retention period.

- [ ] **Step 3: Add tag release automation**

  Verify `GITHUB_REF_NAME` equals `v$(cat VERSION)`, run production/full/CLI/package gates, upload the accepted `.deb`, and publish it with `gh release create` or `gh release upload --clobber` only in the scoped write-permission job. Never embed tokens, keys, or a fabricated APT URL.

- [ ] **Step 4: Rewrite installation documentation**

  Put end-user Debian installation first:

  ```bash
  sudo apt install ./skan_0.1.0-1_amd64.deb
  skan --version
  ```

  Move compiler/Make instructions under “Building from source.” Use only `192.0.2.10`, localhost, or other documentation/private examples. Document unprivileged `-sT`, root-required raw modes, no automatic capabilities, package resource layout, explicit DB overrides, supported tested distros, and the external archive blocker for plain `apt install skan`.

- [ ] **Step 5: Verify docs/workflows and commit Task 4**

  Run shell syntax, YAML parse, `git diff --check`, README command smoke tests, and `make check-version`, then:

  ```bash
  git add .github/workflows/ci.yml .github/workflows/release.yml README.md ARCHITECTURE.md SECURITY.md docs/INSTALLATION.md docs/DEBIAN_PACKAGING.md docs/SERVICE_FINGERPRINTS.md
  git commit -m "ci(release): validate and publish Linux packages"
  ```

### Task 5: Full verification, review, delivery, and main validation

**Files:**
- Modify only files required by verified failures or review findings.

**Interfaces:**
- Consumes: all prior task deliverables.
- Produces: reviewed branch, pushed PR, green CI, merge when appropriate, and verified `main`.

- [ ] **Step 1: Run the full local Linux quality matrix**

  Run, in order, from the isolated worktree:

  ```bash
  make clean
  make -j2
  make test
  bash tests/integration/cli/test_nmap_compat.sh
  make debug
  make release
  make asan
  make ubsan
  make coverage
  make benchmark
  ./build/benchmark_offline >/tmp/skan-packaging-benchmark.csv
  test -s /tmp/skan-packaging-benchmark.csv
  make fuzz
  make package-deb
  scripts/test_deb_package.sh dist/skan_0.1.0-1_amd64.deb debian:12
  scripts/test_deb_package.sh dist/skan_0.1.0-1_amd64.deb ubuntu:24.04
  git diff --check
  git status --short
  ```

  Apply systematic debugging to every failure and add a failing regression test before any behavioral fix.

- [ ] **Step 2: Perform security/package audit**

  Verify package contents and control metadata, no setuid/setgid/capabilities, no maintainer scripts, no source/worktree paths in the ELF or package, no `system`/`popen`, no external scan target in tests, exact dpkg ownership/cleanup, and no secret-like material. Record exact commands and outputs.

- [ ] **Step 3: Request independent whole-branch code review**

  Compare `git merge-base origin/main HEAD` to `HEAD`. Give the reviewer the spec, plan, full diff package, verification evidence, and deferred rulings. Fix every Critical/Important finding through a reviewed TDD fix wave, then rerun affected and full gates.

- [ ] **Step 4: Commit any verified review fixes and push**

  Review full `git status`, `git diff`, staged diff, secret scan, and package exclusions. Create only conventional commits, then:

  ```bash
  git push -u origin codex/linux-packaging
  gh pr create --base main --head codex/linux-packaging \
    --title "Package Skan as a system Linux command" \
    --body "Builds and validates the Skan 0.1.0 Debian package, deterministic installed-resource lookup, staged installation, release automation, and end-user installation documentation."
  ```

- [ ] **Step 5: Monitor and repair CI**

  Wait for every PR check to reach a terminal state. For failures, inspect the exact failing step/log, reproduce safely, use systematic debugging and TDD, commit, push, and wait for the replacement SHA's complete matrix.

- [ ] **Step 6: Finish the branch and verify main**

  Use `superpowers:finishing-a-development-branch`. Because the user has pre-authorized merge when verified and appropriate, merge only after independent review and all required checks succeed, without force-push or history rewriting. Pull/fetch the resulting `main`, verify its SHA, wait for the main push workflow, and rerun the installed package smoke check against the merged source.

- [ ] **Step 7: Report factual evidence only**

  Report branch, commit SHA, PR URL, merge status, resulting main SHA, exact package filename, tested distro/container versions, exact install command, exact `skan --version` output, package acceptance result, CI URL/result, and the external Debian/Ubuntu archive acceptance blocker for plain `sudo apt install skan`.
