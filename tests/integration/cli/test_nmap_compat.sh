#!/usr/bin/env bash
set -euo pipefail

skan_bin=${SKAN_BIN:-./bin/skan}
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

"$skan_bin" -sT -p 1 --timeout-ms 50 --output json 127.0.0.1 >"$tmp_dir/connect.json"
python3 -m json.tool "$tmp_dir/connect.json" >/dev/null

"$skan_bin" -sS --transport offline -p 80 --output json 192.0.2.1 >"$tmp_dir/syn.json"
python3 -m json.tool "$tmp_dir/syn.json" >/dev/null

"$skan_bin" -sU --transport offline --udp-ports 53 --output json 192.0.2.1 >"$tmp_dir/udp.json"
python3 -m json.tool "$tmp_dir/udp.json" >/dev/null

"$skan_bin" -sn --transport offline --output json 192.0.2.1 >"$tmp_dir/discovery.json"
python3 -m json.tool "$tmp_dir/discovery.json" >/dev/null

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
