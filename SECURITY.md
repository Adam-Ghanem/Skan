# Security Policy

## Authorized use

Skan is a network reconnaissance tool. Use it only on systems and networks you own or are explicitly authorized to assess. The automated privileged validation job is restricted to a temporary isolated network namespace and documentation-only addresses.

## Reporting a vulnerability

Do not publish exploitable details in a public issue. Contact the repository owner through the private security-reporting channel available on the GitHub repository. Include the affected commit, reproduction conditions, impact, and the smallest safe proof of concept.

## Supported version

Security fixes currently target the latest commit on `main`. Tagged release support will be documented when the first release is published.

## Scope boundary

Unsupported raw capability is reported explicitly. A capability failure must never be converted into fabricated scan evidence or a silent fallback.

## Linux package security

The Debian package installs a normal `0755` executable. It does not use setuid, assign file capabilities, install a service, execute maintainer scripts, or perform post-install network activity. Raw-packet privileges remain an explicit operator decision. Runtime databases are package-owned read-only data under `/usr/share/skan`, and explicit database paths are validated rather than downloaded or silently substituted.

Release validation runs with read-only repository permissions. The separate publication job receives the minimum `contents: write` permission only after validated artifacts are produced, and it does not check out or execute repository code. Privileged network-namespace CI is disabled for untrusted fork pull requests.
