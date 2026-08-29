#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: SKAN_AUTHORIZED_LAB=1 $0 <target> [tcp-ports] [interface]" >&2
  echo "Example: SKAN_AUTHORIZED_LAB=1 $0 192.0.2.2 22,80 eth0" >&2
}

if [[ $# -lt 1 || $# -gt 3 ]]; then
  usage
  exit 64
fi
if [[ "${SKAN_AUTHORIZED_LAB:-}" != "1" ]]; then
  echo "Refusing to scan: set SKAN_AUTHORIZED_LAB=1 only for an explicitly authorized private lab." >&2
  exit 77
fi

target=$1
port_range=${2:-22,80,443}
interface_name=${3:-}
skan_bin=${SKAN_BIN:-./bin/skan}
validation_dir=${VALIDATION_DIR:-validation_runs}

command -v nmap >/dev/null 2>&1 || {
  echo "nmap is required for ground-truth comparison" >&2
  exit 69
}
if [[ ! -x "$skan_bin" ]]; then
  echo "Skan binary not found or not executable: $skan_bin" >&2
  exit 69
fi

if [[ "$(id -u)" -ne 0 ]]; then
  command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required for capability validation" >&2
    exit 69
  }
  cap_eff=$(awk '$1 == "CapEff:" {print $2}' /proc/self/status 2>/dev/null || true)
  if [[ -z "$cap_eff" ]]; then
    echo "CAP_NET_RAW required: cannot read /proc/self/status CapEff" >&2
    exit 77
  fi
  if ! CAP_EFF="$cap_eff" python3 -c 'import os, sys; cap=int(os.environ["CAP_EFF"], 16); sys.exit(0 if cap & (1 << 13) else 1)'; then
    echo "CAP_NET_RAW required: effective CAP_NET_RAW is not present" >&2
    exit 77
  fi
fi

mkdir -p "$validation_dir"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
safe_target=$(printf '%s' "$target" | tr -c 'A-Za-z0-9._-' '_')
base="$validation_dir/${stamp}_${safe_target}"
skan_out="${base}_skan.txt"
nmap_out="${base}_nmap.txt"
meta_out="${base}_meta.txt"

skan_cmd=("$skan_bin" scan "$target" --tcp-ports "$port_range" --method syn --transport linux --service-detect)
nmap_cmd=(nmap -Pn -sS -sV -p "$port_range")
if [[ "$target" == *:* ]]; then
  nmap_cmd+=(-6)
fi
if [[ -n "$interface_name" ]]; then
  skan_cmd+=(--interface "$interface_name")
  nmap_cmd+=(-e "$interface_name")
fi
nmap_cmd+=("$target")

set +e
"${skan_cmd[@]}" >"$skan_out" 2>&1
skan_status=$?
"${nmap_cmd[@]}" >"$nmap_out" 2>&1
nmap_status=$?
set -e

{
  printf 'timestamp_utc=%s\n' "$stamp"
  printf 'target=%s\n' "$target"
  printf 'tcp_port_range=%s\n' "$port_range"
  printf 'interface=%s\n' "${interface_name:-auto}"
  printf 'uid=%s\n' "$(id -u)"
  printf 'effective_capabilities=%s\n' "$(awk '$1 == "CapEff:" {print $2}' /proc/self/status 2>/dev/null || echo unavailable)"
  printf 'skan_binary=%s\n' "$skan_bin"
  printf 'skan_exit=%s\n' "$skan_status"
  printf 'nmap=%s\n' "$(command -v nmap)"
  printf 'nmap_exit=%s\n' "$nmap_status"
} >"$meta_out"

echo "Skan output: $skan_out"
echo "nmap output: $nmap_out"
echo "Metadata: $meta_out"

if [[ "$skan_status" -ne 0 || "$nmap_status" -ne 0 ]]; then
  echo "Privileged validation failed; inspect the captured outputs." >&2
  exit 1
fi
