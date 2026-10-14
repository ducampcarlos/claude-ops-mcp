# Security policy

See [docs/security.md](docs/security.md) for the threat model and the defences in place.

## Reporting a vulnerability

Please report vulnerabilities through a **private GitHub security advisory** on this repository (Security tab → Report a vulnerability) rather than a public issue. Include the version, a description and, if possible, a minimal reproduction. You can expect an acknowledgement within a few days.

Particularly interesting: any way to make the server connect to a private, loopback or link-local address with default settings, to read a response body or cookie value, or to exceed the configured limits through tool arguments.
