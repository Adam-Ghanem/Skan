#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
package=${1:?usage: test_deb_package.sh PACKAGE [IMAGE]}
image=${2:-debian:12}
package=$(realpath "$package")
test -f "$package" || { echo "package not found: $package" >&2; exit 1; }
command -v docker >/dev/null || { echo "missing required command: docker" >&2; exit 1; }

context="$repo_root/build/package-acceptance"
case "$context" in "$repo_root"/*) ;; *) exit 1 ;; esac
rm -rf -- "$context"
mkdir -p "$context/fixtures"
cp "$package" "$context/skan.deb"
cp "$repo_root/tests/packaging/Dockerfile.acceptance" "$context/Dockerfile"
cp "$repo_root/tests/packaging/deb_acceptance.sh" "$context/deb_acceptance.sh"
cp "$repo_root/tests/packaging/fixtures/"* "$context/fixtures/"

tag="skan-package-acceptance-$((RANDOM + RANDOM))"
cleanup() { docker image rm -f "$tag" >/dev/null 2>&1 || true; rm -rf -- "$context"; }
trap cleanup EXIT
docker build --build-arg "BASE_IMAGE=$image" --tag "$tag" "$context"
docker run --rm --network none --cap-drop NET_RAW --cap-drop NET_ADMIN "$tag" /tmp/skan.deb
