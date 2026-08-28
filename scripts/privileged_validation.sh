#!/usr/bin/env bash
set -euo pipefail

# Capability-gated raw validation harness. This script deliberately refuses to
# run raw validation when the current process lacks CAP_NET_RAW or root.

usage() {
  echo "Usage: $0 <target> [tcp-port-range]" >&2
  echo "Example: $0 127.0.0.1 22,80,443" >&2
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 64
fi

target=$1
port_range=${2:-1-1024}

if [[ "$(id -u)" -ne 0 ]]; then
  cap_eff=$(awk '$1 == "CapEff:" {print $2}' /proc/self/status 2>/dev/null || true)
  if [[ -z "$cap_eff" ]]; then
    echo "CAP_NET_RAW required: cannot read /proc/self/status CapEff" >&2
    exit 77
  fi
  # Linux capability number 13 is CAP_NET_RAW. Test its bit without requiring
  # capsh/libcap to be installed: (CapEff & (1 << 13)) != 0.
  if ! CAP_EFF="$cap_eff" python3 -c 'import os, sys; cap=int(os.environ["CAP_EFF"], 16); sys.exit(0 if cap & (1 << 13) else 1)'; then
    echo "CAP_NET_RAW required: effective CAP_NET_RAW is not present" >&2
    exit 77
  fi
fi

command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required for capability validation" >&2
  exit 69
}
command -v sudo >/dev/null 2>&1 || {
  echo "sudo is required to run the nmap ground-truth command" >&2
  exit 69
}
command -v nmap >/dev/null 2>&1 || {
  echo "nmap is required for ground-truth comparison" >&2
  exit 69
}

SKAN_BIN=${SKAN_BIN:-./bin/skan}
if [[ ! -x "$SKAN_BIN" ]]; then
  echo "Skan binary not found or not executable: $SKAN_BIN" >&2
  exit 69
fi

mkdir -p validation_runs
stamp=$(date -u +%Y%m%dT%H%M%SZ)
base="validation_runs/${stamp}_$(printf '%s' "$target" | tr -c 'A-Za-z0-9._-' '_')"
skan_out="${base}_skan.txt"
nmap_out="${base}_nmap.txt"
meta_out="${base}_meta.txt"

{
  printf 'timestamp_utc=%s\n' "$stamp"
  printf 'target=%s\n' "$target"
  printf 'tcp_port_range=%s\n' "$port_range"
  printf 'uid=%s\n' "$(id -u)"
  printf 'effective_capabilities=%s\n' "$(awk '$1 == "CapEff:" {print $2}' /proc/self/status 2>/dev/null || echo unavailable)"
  printf 'skan_binary=%s\n' "$SKAN_BIN"
  printf 'nmap=%s\n' "$(command -v nmap)"
} >"$meta_out"

echo "Running Skan raw SYN/service detection: $target ports $port_range"
"$SKAN_BIN" scan "$target" --tcp-ports "$port_range" --method syn --service-detect >"$skan_out" 2>&1

echo "Running nmap ground truth: $target ports $port_range"
sudo nmap -sS -sV -p "$port_range" "$target" >"$nmap_out" 2>&1

echo "Skan output: $skan_out"
echo "nmap output: $nmap_out"
echo "Metadata: $meta_out"
