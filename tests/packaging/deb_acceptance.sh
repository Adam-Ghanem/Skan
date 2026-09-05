#!/usr/bin/env bash
set -euo pipefail

package=${1:-/tmp/skan.deb}
test -f "$package" || { echo "package not found: $package" >&2; exit 1; }

work=$(mktemp -d /tmp/skan-package-acceptance.XXXXXX)
server_pid=
cleanup() {
    if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; fi
    rm -rf "$work"
}
trap cleanup EXIT

cd "$work"
test "$(command -v skan)" = /usr/bin/skan
package_version=$(dpkg-query -W -f='${Version}' skan)
upstream_version=${package_version%%-*}
test "$(skan --version)" = "Skan $upstream_version"
skan --help | grep -F "Usage:" >/dev/null

for path in /usr/bin/skan /usr/share/skan/service-probes.db \
    /usr/share/skan/udp-probes.db /usr/share/skan/os-fingerprints.db \
    /usr/share/skan/os-fingerprints-v6.db; do
    dpkg-query -S "$path" | grep -F "skan:" >/dev/null
done
test "$(stat -c %a /usr/bin/skan)" = 755
find /usr/bin/skan /usr/share/skan -perm /6000 -print -quit | grep -q . && exit 1
test -z "$(getcap /usr/bin/skan)"
if dpkg-query -L skan | grep -Eq '/(systemd|init\.d)/'; then
    echo "package unexpectedly installs a system service" >&2
    exit 1
fi
for script in preinst postinst prerm postrm; do
    test ! -e "/var/lib/dpkg/info/skan.$script"
done

skan scan 192.0.2.10 --transport offline -p 80 --os-detect --output json >os.json
python3 -m json.tool os.json >/dev/null
skan -sU --transport offline -p 53 --output json 192.0.2.10 >udp.json
python3 -m json.tool udp.json >/dev/null

python3 /opt/skan-tests/banner_server.py 8080 &
server_pid=$!
for _ in {1..50}; do
    python3 - <<'PY' >/dev/null 2>&1 && break || true
import socket
with socket.create_connection(("127.0.0.1", 8080), timeout=0.1):
    pass
PY
    sleep 0.05
done
skan -sT -sV -p 8080 --timeout-ms 1000 --output json 127.0.0.1 >service.json
python3 -m json.tool service.json >/dev/null
grep -F 'http' service.json >/dev/null

skan scan 192.0.2.10 --transport offline -p 80 --os-detect \
    --os-db /opt/skan-tests/os-override.db --output json >os-override.json
python3 -m json.tool os-override.json >/dev/null
skan -sT -sV -p 8080 --timeout-ms 1000 --service-db \
    /opt/skan-tests/service-override.db --output json 127.0.0.1 >service-override.json
python3 -m json.tool service-override.json >/dev/null

if skan scan 192.0.2.10 --transport offline -p 80 --os-detect \
    --os-db /opt/skan-tests/invalid.db --output json >/dev/null 2>&1; then
    echo "invalid OS database unexpectedly accepted" >&2
    exit 1
fi
if skan -sT -sV -p 8080 --service-db /opt/skan-tests/invalid.db \
    --output json 127.0.0.1 >/dev/null 2>&1; then
    echo "invalid service database unexpectedly accepted" >&2
    exit 1
fi

apt-get purge -y skan >/dev/null
if command -v skan >/dev/null; then
    echo "skan remains on PATH after purge" >&2
    exit 1
fi
if dpkg-query -W skan >/dev/null 2>&1; then
    echo "skan remains registered after purge" >&2
    exit 1
fi
test ! -e /usr/bin/skan
test ! -e /usr/share/skan
