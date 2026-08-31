#!/usr/bin/env bash
set -euo pipefail

skan_bin=${SKAN_BIN:-./bin/skan}
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

test "$("$skan_bin" --version)" = "Skan 0.1.0"
! "$skan_bin" --version | grep -F "Skan Skan"

"$skan_bin" -sT -p 1 --timeout-ms 50 --output json 127.0.0.1 >"$tmp_dir/connect.json"
python3 -m json.tool "$tmp_dir/connect.json" >/dev/null

"$skan_bin" -sS --transport offline -p 80 --output json 192.0.2.1 >"$tmp_dir/syn.json"
python3 -m json.tool "$tmp_dir/syn.json" >/dev/null

"$skan_bin" -sU --transport offline --udp-ports 53 --output json 192.0.2.1 >"$tmp_dir/udp.json"
python3 -m json.tool "$tmp_dir/udp.json" >/dev/null

"$skan_bin" -sn --transport offline --output json 192.0.2.1 >"$tmp_dir/discovery.json"
python3 -m json.tool "$tmp_dir/discovery.json" >/dev/null

"$skan_bin" scan 192.0.2.1 --transport offline -p 80 --os-detect \
  --os-db data/os-fingerprints.db --output json >"$tmp_dir/scan-os-db.json"
python3 -m json.tool "$tmp_dir/scan-os-db.json" >/dev/null

"$skan_bin" -sS --transport offline --top-ports 10 -T4 -oA "$tmp_dir/aggregate" 192.0.2.1
test -s "$tmp_dir/aggregate.nmap"
test -s "$tmp_dir/aggregate.xml"
test -s "$tmp_dir/aggregate.gnmap"

"$skan_bin" -sT -p 1 -oX "$tmp_dir/connect.xml" 127.0.0.1
test -s "$tmp_dir/connect.xml"

if "$skan_bin" -sU --transport offline --top-ports 10 192.0.2.1 >/dev/null 2>&1; then
  echo "TCP-only --top-ports unexpectedly accepted for UDP" >&2
  exit 1
fi

"$skan_bin" -sS --transport offline -p 80 --output json \
  192.0.2.1 192.0.2.2 >"$tmp_dir/multiple-targets.json"
python3 - "$tmp_dir/multiple-targets.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
addresses = [host["address"] for host in report["hosts"]]
assert addresses == ["192.0.2.1", "192.0.2.2"], addresses
PY

"$skan_bin" -sS --transport offline -6 -p 80 --output json \
  192.0.2.1 ::1 ::2 --exclude ::2 >"$tmp_dir/ipv6-filter.json"
python3 - "$tmp_dir/ipv6-filter.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
hosts = report["hosts"]
assert [(host["address"], host["family"]) for host in hosts] == [("::1", "ipv6")], hosts
PY

"$skan_bin" -sU --transport offline -p 53,123 --exclude-ports 123 \
  --output json 192.0.2.1 >"$tmp_dir/udp-port-selection.json"
python3 - "$tmp_dir/udp-port-selection.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
ports = [(port["port"], port["protocol"]) for host in report["hosts"] for port in host["ports"]]
assert ports == [(53, "udp")], ports
PY

"$skan_bin" -sS --transport offline --exclude-ports 80 \
  --output json 192.0.2.1 >"$tmp_dir/default-excluded-port.json"
python3 - "$tmp_dir/default-excluded-port.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
ports = [port["port"] for host in report["hosts"] for port in host["ports"]]
assert ports == [22, 443], ports
PY

if "$skan_bin" -sS --transport offline -4 -6 -p 80 192.0.2.1 >/dev/null 2>&1; then
  echo "-4 and -6 unexpectedly accepted together" >&2
  exit 1
fi

if "$skan_bin" -sS --transport offline -p 80 --exclude 192.0.2.1 192.0.2.1 >/dev/null 2>&1; then
  echo "scan unexpectedly accepted after every target was excluded" >&2
  exit 1
fi

if "$skan_bin" -sU --transport offline -p 53 --udp-ports 53 192.0.2.1 >/dev/null 2>&1; then
  echo "ambiguous UDP port selection unexpectedly accepted" >&2
  exit 1
fi

"$skan_bin" -sS --transport offline -p 80 --reason --output normal \
  192.0.2.1 >"$tmp_dir/reason.nmap"
grep -Eq "^[[:space:]]*80/tcp[[:space:]]+FILTERED[[:space:]]+.*TIMEOUT$" "$tmp_dir/reason.nmap"

"$skan_bin" -sS --transport offline -p 80 --open --output normal \
  192.0.2.1 >"$tmp_dir/open-only.nmap"
if grep -Eq "^[[:space:]]*80/tcp[[:space:]]" "$tmp_dir/open-only.nmap"; then
  echo "--open unexpectedly emitted a filtered port" >&2
  exit 1
fi
grep -q "1 filtered" "$tmp_dir/open-only.nmap"

"$skan_bin" -sS --transport offline -p 80 --output normal \
  192.0.2.1 >"$tmp_dir/redirected-normal.nmap"
if grep -Eq '╭|╰|◈|●|○|\x1b' "$tmp_dir/redirected-normal.nmap"; then
  echo "redirected normal output unexpectedly contains terminal decoration" >&2
  exit 1
fi
grep -q '^SKAN v' "$tmp_dir/redirected-normal.nmap"
grep -Eq '^[[:space:]]*80/tcp[[:space:]]+FILTERED' "$tmp_dir/redirected-normal.nmap"
