#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
stage=$(mktemp -d)
outside=$(mktemp -d)
trap 'rm -rf "$stage" "$outside"' EXIT

make -C "$repo_root" install DESTDIR="$stage" PREFIX=/usr

test -x "$stage/usr/bin/skan"
test "$(stat -c %a "$stage/usr/bin/skan")" = 755

runtime_dir="$repo_root/build/corpus-runtime"
for database in service-probes.db udp-probes.db os-fingerprints.db os-fingerprints-v6.db; do
    test -s "$runtime_dir/$database"
    test -s "$stage/usr/share/skan/$database"
    test "$(stat -c %a "$stage/usr/share/skan/$database")" = 644
    cmp -s "$runtime_dir/$database" "$stage/usr/share/skan/$database"
done

test -s "$runtime_dir/manifest.json"
test -s "$stage/usr/share/skan/manifest.json"
test "$(stat -c %a "$stage/usr/share/skan/manifest.json")" = 644
cmp -s "$runtime_dir/manifest.json" "$stage/usr/share/skan/manifest.json"

test -s "$stage/usr/share/doc/skan/README.md"
test -s "$stage/usr/share/doc/skan/LICENSE"
test -s "$stage/usr/share/doc/skan/ARCHITECTURE.md"
test -s "$stage/usr/share/doc/skan/SECURITY.md"
test -s "$stage/usr/share/man/man1/skan.1"
test "$(stat -c %a "$stage/usr/share/man/man1/skan.1")" = 644
test ! -e "$stage/usr/local"

version=$(<"$repo_root/VERSION")
test "$(cd "$outside" && "$stage/usr/bin/skan" --version)" = "Skan $version"
(cd "$outside" && "$stage/usr/bin/skan" scan 192.0.2.10 --transport offline \
    -p 80 --os-detect --output json >/dev/null)

if strings "$stage/usr/bin/skan" | grep -F "$stage" >/dev/null; then
    echo "DESTDIR leaked into the installed binary" >&2
    exit 1
fi
