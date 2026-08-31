# Debian packaging

Skan's Debian package installs the first-party C++ scanner, four project-owned runtime databases, documentation, the MIT license, and a manual page. It adds no service, maintainer script, setuid bit, or file capability.

## Authoritative version

`VERSION` is the upstream version source used by the C++ binary and Makefile. `debian/changelog` carries the required Debian revision. `make check-version` fails if their upstream components differ. A release tag must be exactly `v` followed by the value in `VERSION`.

## Local package build

On Debian or Ubuntu with packaging tools installed:

```bash
sudo apt-get install build-essential debhelper dpkg-dev lintian
make package-deb
```

The build copies a clean source snapshot into a temporary Linux directory, applies Debian hardening flags, runs the registered test suite, and writes only the main binary package to `dist/`:

```text
dist/skan_0.1.0-1_amd64.deb
```

For an environment matching CI, use the pinned Debian 12 builder:

```bash
docker build --tag skan-debian12-builder --file tests/packaging/Dockerfile.builder .
docker run --rm --volume "$PWD:/work" --workdir /work \
  skan-debian12-builder bash scripts/build_deb.sh
```

## Policy and installed-package checks

```bash
docker run --rm --volume "$PWD/dist:/dist:ro" \
  skan-debian12-builder \
  lintian --fail-on error /dist/skan_0.1.0-1_amd64.deb

bash scripts/test_deb_package.sh \
  dist/skan_0.1.0-1_amd64.deb debian:12
bash scripts/test_deb_package.sh \
  dist/skan_0.1.0-1_amd64.deb ubuntu:24.04
```

The acceptance harness installs the package into a fresh image, then runs offline with raw-network capabilities dropped and the container network disabled. It verifies:

- global command discovery from an unrelated temporary directory;
- version and help output;
- package ownership, modes, and absence of setuid bits or file capabilities;
- automatic discovery of all installed databases;
- explicit service and OS database overrides and visible invalid-file failures;
- safe offline scans against documentation addresses;
- TCP connect service detection against a loopback-only fixture;
- purge and package-owned path cleanup.

The image build needs distribution package mirrors to install the `.deb` and acceptance tools. The actual scan and removal test runs with `--network none`.

## GitHub release

A tag matching `v*.*.*` starts `.github/workflows/release.yml`. The workflow rejects a tag that differs from `VERSION` or is not reachable from `main`, rebuilds and retests the package, runs both installed-package acceptance environments, and produces the validated `.deb` plus `SHA256SUMS`. A separate publication job downloads those assets and attaches them to the corresponding GitHub Release. Only that publication job receives `contents: write`; it does not check out or execute repository code, and normal CI remains read-only.

The release asset supports the immediately available flow:

```bash
sudo apt install ./skan_0.1.0-1_amd64.deb
```

Official Debian/Ubuntu archive availability is separate and must not be claimed before external acceptance. The current automation builds a binary package; an archive submission still needs a policy-complete signed source package, sponsor review, and acceptance.
