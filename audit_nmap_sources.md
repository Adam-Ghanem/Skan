# Nmap comparison sources

## Official Nmap Reference Guide
Source: https://nmap.org/book/man.html

The current Nmap reference describes host discovery, port scanning, service/version detection, OS detection, NSE, timing/performance, evasion/spoofing, and output as separate capabilities. It states that Nmap reports open, filtered, closed, unfiltered, open|filtered, and closed|filtered states, and can provide reverse DNS names, OS guesses, device types, and MAC addresses.

## Host discovery
Source: https://nmap.org/book/man-host-discovery.html

Nmap supports list scan and no-ping modes, combinations of ICMP, TCP SYN/ACK, UDP, SCTP INIT, and IP protocol probes, plus ARP/IPv6 Neighbor Discovery on local Ethernet. The default discovery set includes ICMP echo, TCP SYN, TCP ACK, and ICMP timestamp (with IPv6 differences). It also documents UDP payload use and multiple response classifications.

## Port scanning techniques
Source: https://nmap.org/book/man-port-scanning-techniques.html

Nmap documents TCP Connect, SYN, UDP, SCTP INIT/COOKIE ECHO, NULL, FIN, Xmas, ACK, Window, Maimon, custom TCP flags, idle, IP protocol, and FTP bounce scan types. It states that raw-packet techniques generally require privileges on Unix. SYN and UDP scans can be combined, and UDP uses protocol-specific payloads for common ports.

## OS detection
Source: https://nmap.org/book/man-os-detection.html

Nmap OS detection sends TCP and UDP probes and compares many response properties against an `nmap-os-db` database described there as containing more than 2,600 known fingerprints. The page describes OS/device classification, CPEs, OS-scan limits, fuzzy guesses, and configurable OS retry counts.

These sources are used only for a factual capability comparison; no Nmap code or database data is copied.

## Timing and performance
Source: https://nmap.org/book/man-performance.html

Nmap documents adaptive parallelism, min/max parallelism, dynamic RTT timeouts, retransmission limits, host timeouts, scan delays/rates, and six timing templates T0–T5. It uses host groups and bounded outstanding probes and adapts to packet loss and latency.

## Output
Source: https://nmap.org/book/man-output.html

Nmap documents interactive/normal, XML, grepable, and script-kiddie output, named-file output, append/clobber behavior, and resume support. XML is emphasized as the machine-readable extensible format; grepable output is deprecated but still available.

## Service and version detection
Source: https://nmap.org/book/man-version-detection.html

Nmap uses service and version databases with probe definitions and match expressions. The reference describes intensity levels 0–9, probe rarity, service/version/product/version/OS/device/CPE extraction, and additional RPC/SSL behavior.

## Nmap Scripting Engine
Source: https://nmap.org/book/nse.html

NSE is an embedded Lua-based scripting engine supporting discovery, advanced version detection, vulnerability and backdoor detection, and extensible scripts. Scripts run in parallel and integrate with normal and XML output. Skan intentionally does not implement an NSE-equivalent scripting subsystem in this audit.
