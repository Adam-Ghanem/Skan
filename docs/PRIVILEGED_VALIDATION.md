# Privileged Private-Lab Validation

Skan's raw Linux path is validated only inside an explicitly authorized and isolated network namespace. The automated lab creates a temporary veth pair with documentation-only IPv4 and IPv6 addresses, starts local HTTP fixtures, and compares Skan's SYN/service results with Nmap ground truth.

## Automated acceptance

The `privileged-private-lab` CI job proves:

- AF_PACKET capture and injection on a dedicated veth interface;
- ARP-backed IPv4 SYN correlation for one open and one closed TCP port;
- NDP-backed IPv6 SYN correlation for one open and one closed TCP port;
- service detection on controlled local HTTP listeners;
- agreement with Nmap for the tested port states;
- retained output and metadata artifacts for audit.

No public route or public target is used.

## Manual reproduction

Build Skan and create an equivalent private lab, then run:

```bash
SKAN_AUTHORIZED_LAB=1 \
  ./scripts/privileged_validation.sh <private-target> <ports> <interface>
```

The guard variable is mandatory. The operator remains responsible for ensuring that the target and interface belong to an authorized lab.

## Capability boundary

A successful isolated test validates the exercised interface, address families, probes, and observations. It does not imply permission to scan another network, Internet-wide correctness, or parity with Nmap's full fingerprint and scripting databases.
