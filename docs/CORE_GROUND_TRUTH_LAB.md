# Core V3 Ground-Truth Lab

This lab is the CORE-01 correctness foundation for Skan. It is intentionally isolated, authorization-gated, dual-stack, and independent from Skan's own classifications.

## Safety boundary

Live mutation requires:

```bash
SKAN_AUTHORIZED_LAB=1
```

and root/CAP_NET_ADMIN. The controller only creates a local Linux network namespace and veth pair using documentation address space:

- scanner IPv4: `192.0.2.5/30`
- target IPv4: `192.0.2.6/30`
- scanner IPv6: `2001:db8:42::1/64`
- target IPv6: `2001:db8:42::2/64`

The lab never selects or contacts a public target.

The IPv4 subnet is intentionally distinct from the repository's older privileged CI namespace (`192.0.2.0/30`) so both labs can coexist in the same job without route ambiguity.

Raw AF_PACKET SYN/ACK paths consume the kernel's direct-link ARP/NDP neighbor state. The lab therefore establishes IPv4 and IPv6 adjacency against its own known-open endpoints before raw smoke validation and verifies a usable `ip neigh` entry. This is a topology precondition only; neighbor priming is not a truth source and does not change any canonical scanner state.

## Independent truth

`truth_manifest.json` defines configured truth from lab configuration, not from Skan or Nmap output.

Truth is verified from independent operating-system evidence:

- bound TCP/UDP listeners via `ss`
- IPv4 firewall rules via `iptables-save`
- IPv6 firewall rules via `ip6tables-save`
- traffic-control state via `tc -j qdisc`
- scanner-side ARP/NDP adjacency via `ip neigh`
- packet evidence via `tcpdump` during live smoke validation

A scanner disagreement must therefore be investigated against configured socket/firewall/packet truth. Nmap may be used later as a differential peer, never as the oracle.

## Baseline truth cases

The lab currently provisions:

- IPv4 TCP OPEN
- IPv6 TCP OPEN
- dual-stack TCP CLOSED
- dual-stack TCP DROP
- dual-stack administrative REJECT
- dual-stack rate-limited TCP RST behavior
- dual-stack rate-limited administrative ICMP behavior
- IPv4 UDP OPEN
- IPv6 UDP OPEN
- dual-stack UDP CLOSED

The first CI smoke slice validates current SYN and ACK semantics. UDP, discovery, rate-limit and high-loss classifications are intentionally consumed by later Core V3 phases instead of being guessed in CORE-01.

## Network profiles

The manifest defines reusable profiles for:

- clean network
- 1%, 5%, 10%, and 20% packet loss
- 1, 20, 100, 300, and 800 ms approximate RTT
- jitter
- duplication
- reordering
- burst loss
- 10 Mbit/s bandwidth limiting

Stochastic profiles require seeded `tc netem` support. The controller fails explicitly instead of silently falling back to an unseeded random profile.

The controller applies impairment to both veth directions so later fault-injection phases can measure scanner behavior without changing target truth.

## Commands

Offline contract validation:

```bash
make test-core-lab-contract
```

Create the authorized private lab:

```bash
sudo env SKAN_AUTHORIZED_LAB=1 \
  python3 tests/integration/core_lab/core_lab.py setup
```

Apply a profile:

```bash
sudo env SKAN_AUTHORIZED_LAB=1 \
  python3 tests/integration/core_lab/core_lab.py profile loss-5
```

Capture an independent truth snapshot:

```bash
sudo env SKAN_AUTHORIZED_LAB=1 \
  python3 tests/integration/core_lab/core_lab.py snapshot \
  --profile loss-5 \
  --output validation_runs/core-ground-truth/truth.json
```

Run the clean-network smoke validation:

```bash
sudo env SKAN_AUTHORIZED_LAB=1 \
  python3 tests/integration/core_lab/core_lab.py smoke \
  --skan ./bin/skan \
  --evidence-dir validation_runs/core-ground-truth
```

Cleanup:

```bash
sudo env SKAN_AUTHORIZED_LAB=1 \
  python3 tests/integration/core_lab/core_lab.py cleanup
```

## Evidence artifacts

A live smoke run records:

- `truth-before.json`
- `truth-after.json`
- IPv4 SYN output
- IPv6 SYN output
- IPv4 ACK output
- packet capture

The truth snapshots contain the manifest plus observed listener/firewall/qdisc state and do not derive truth from scanner output.

## CORE-01 acceptance boundary

CORE-01 establishes the reusable lab and its independent truth source. It does not claim the later loss-resilience, timing, correlation, UDP-rate-limit, stress, differential, or long-run reliability acceptance gates.

Those gates consume this lab in CORE-03 through CORE-20.

A future change must not weaken:

- the explicit authorization gate
- documentation-only addressing
- independent truth evidence
- deterministic profile definitions
- explicit failure when deterministic impairment cannot be configured
- cleanup of namespace processes, qdisc state and veth resources
