#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: prepare_release_assets.sh PACKAGE NEW_ASSET_DIRECTORY" >&2
    exit 2
fi
package=$1
assets=$2
name=$(basename -- "$package")
if [[ ! -f "$package" || -L "$package" ||
      ! "$name" =~ ^skan_[0-9][0-9A-Za-z.+:~_-]*_amd64\.deb$ ]]; then
    echo "expected a regular amd64 Skan Debian package" >&2
    exit 1
fi

# The Docker builder owns dist/. Stage into a new runner-owned directory
# rather than writing there or broadening permissions on container output.
# Refuse an existing directory so reruns cannot overwrite release assets.
mkdir -m 0755 -- "$assets"
install -m 0644 -- "$package" "$assets/$name"
(cd -- "$assets" && sha256sum -- "$name" >SHA256SUMS)
