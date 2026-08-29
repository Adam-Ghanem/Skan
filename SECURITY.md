# Security Policy

## Authorized use

Skan is a network reconnaissance tool. Use it only on systems and networks you own or are explicitly authorized to assess. The automated privileged validation job is restricted to a temporary isolated network namespace and documentation-only addresses.

## Reporting a vulnerability

Do not publish exploitable details in a public issue. Contact the repository owner through the private security-reporting channel available on the GitHub repository. Include the affected commit, reproduction conditions, impact, and the smallest safe proof of concept.

## Supported version

Security fixes currently target the latest commit on `main`. Tagged release support will be documented when the first release is published.

## Scope boundary

Unsupported raw capability is reported explicitly. A capability failure must never be converted into fabricated scan evidence or a silent fallback.
