# Installing Skan

## End-user installation on Ubuntu or Debian

Download the `amd64` `.deb` attached to a Skan GitHub Release. For version 0.1.0, install it from the directory containing the download:

```bash
sudo apt install ./skan_0.1.0-1_amd64.deb
```

APT resolves the package's factual C++ runtime dependencies from the configured distribution repositories. The Skan package itself runs no maintainer scripts and performs no network activity during installation.

Verify the global command from an unrelated directory:

```bash
cd /tmp
skan --version
skan --help
skan -sT -p 22,80,443 192.0.2.10
```

The package owns these runtime paths:

- `/usr/bin/skan`
- `/usr/share/skan/service-probes.db`
- `/usr/share/skan/udp-probes.db`
- `/usr/share/skan/os-fingerprints.db`
- `/usr/share/skan/os-fingerprints-v6.db`
- `/usr/share/man/man1/skan.1.gz`

Remove the package through APT:

```bash
sudo apt remove skan
```

Skan intentionally has no `make uninstall` target. Package-manager ownership is the deterministic and auditable removal path for end users.

## Privileges

The executable is installed as a normal `0755` file. It is not setuid, receives no file capabilities, and has no post-install action that changes privileges.

TCP connect scans normally work without root:

```bash
skan -sT -p 80,443 192.0.2.10
```

Live SYN, UDP, discovery, and other raw-packet operations can require root:

```bash
sudo skan -sS --top-ports 100 192.0.2.10
sudo skan -sU -p 53 192.0.2.10
```

Skan reports missing privileges explicitly. Assigning `CAP_NET_RAW` or other capabilities is an administrator security decision and is not performed by the package.

## Runtime database selection

Installed builds find project-owned defaults under `/usr/share/skan` without consulting the current working directory. A development binary can use resources beside its own source-tree layout. Explicit options always take precedence:

```bash
skan -sT -sV --service-db /approved/path/service-probes.db -p 443 192.0.2.10
skan scan --transport offline --os-detect --os-db /approved/path/os.db -p 80 192.0.2.10
```

Missing or invalid explicit databases fail visibly; Skan does not silently download or replace them.

## Building and installing from source

This workflow is for developers and distribution packagers:

```bash
sudo apt-get install build-essential
make -j2
make test
sudo make install PREFIX=/usr
```

To inspect the install layout without modifying the host:

```bash
stage=$(mktemp -d)
make install DESTDIR="$stage" PREFIX=/usr
find "$stage" -type f -print
```

## Plain `apt install skan` status

The package metadata, license declarations, tests, reproducible staging interface, and Debian source layout form a foundation for an eventual official Debian/Ubuntu submission. The current automation produces a binary package; a policy-complete signed source upload and sponsor review remain external work. Skan has not been accepted into those archives, and the project does not currently publish a signed APT repository. Therefore this command is not yet claimed to work:

```bash
sudo apt install skan
```

Official archive submission requires external sponsorship, review, and acceptance. A future project-owned repository would additionally require durable hosting and protected offline GPG signing keys; it must use a dedicated keyring and `signed-by=` rather than `apt-key` or a curl-to-shell installer.
