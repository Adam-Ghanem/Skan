#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
package_root=$(mktemp -d "${TMPDIR:-/tmp}/skan-package.XXXXXX")
source_root="$package_root/source"
dist_root="$repo_root/dist"
cleanup() { rm -rf -- "$package_root"; }
trap cleanup EXIT

for command in dpkg-buildpackage dpkg-deb make tar; do
    command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done

case "$package_root" in "${TMPDIR:-/tmp}"/skan-package.*) ;; *) exit 1 ;; esac
case "$dist_root" in "$repo_root"/*) ;; *) exit 1 ;; esac
rm -rf -- "$dist_root"
mkdir -p "$source_root" "$dist_root"

tar -C "$repo_root" --exclude=.git --exclude=.worktrees --exclude=.superpowers \
    --exclude=build --exclude=bin --exclude=dist -cf - . | tar -C "$source_root" -xf -
find "$source_root" -type f -exec chmod 0644 {} +
chmod 0755 "$source_root/debian/rules" "$source_root/debian/tests/smoke" \
    "$source_root/scripts/build_deb.sh" "$source_root/scripts/test_deb_package.sh" \
    "$source_root/tests/packaging/deb_acceptance.sh" \
    "$source_root/tests/packaging/test_make_install.sh" \
    "$source_root/tests/packaging/fixtures/banner_server.py"

(
    cd "$source_root"
    make check-version
    bash tests/packaging/test_make_install.sh
    dpkg-buildpackage -us -uc -b
)

mapfile -t packages < <(find "$package_root" -maxdepth 1 -type f -name 'skan_*_*.deb' -print)
test "${#packages[@]}" -eq 1 || { echo "expected exactly one binary package" >&2; exit 1; }
cp "${packages[0]}" "$dist_root/"
dpkg-deb --info "$dist_root/$(basename "${packages[0]}")" >/dev/null
printf '%s\n' "$dist_root/$(basename "${packages[0]}")"
