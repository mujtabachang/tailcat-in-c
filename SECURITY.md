# Security

## Reporting a vulnerability

Security issues in this C++ rewrite should be reported to this repository rather than assumed to be vulnerabilities in Tailscale's upstream Go implementation. Prefer GitHub's private vulnerability reporting / Security Advisory flow for this repository when available; otherwise open the minimum public issue needed to request a private contact path and do not publish exploit details.

If a report applies to the upstream `tailscale/tailcat` project or Tailscale infrastructure itself, follow upstream's security reporting instructions instead.

## Native implementation boundary

This repository is an independent C++ implementation of the Tailcat protocol. It does **not** use Tailscale's Go `magicsock`, gVisor netstack, or the upstream Go WireGuard engine.

Important native components include:

- libsodium for Curve25519/NaCl primitives
- a C WireGuard implementation derived from wireguard-lwip
- lwIP for the userspace TCP/IP stack
- libcurl/TLS for DERP HTTPS transport
- nlohmann/json for DERP-map and persisted-key parsing

Protocol compatibility with upstream does not imply identical implementation security properties. Bugs in the C++ port can exist independently of upstream Tailcat.

## Tailcat addresses are credentials

A Tailcat `tc...` address contains connection metadata and can contain a WireGuard preshared key. Treat addresses as secrets unless you deliberately created a configuration without a PSK and understand the consequences.

Do not publish sensitive addresses in logs, screenshots, issue reports, DNS records, shell history, or public chat. A persistent address should be protected like a long-lived credential and rotated if exposed.

## SSH

The current `tailcat ssh` client validates the Tailcat address before constructing an OpenSSH `ProxyCommand`. The ProxyCommand arguments are quoted for the platform and the stream is binary-safe.

The current `tailcat serve ssh` implementation forwards the encrypted Tailcat connection to a local SSH daemon rather than embedding an SSH server. Normal SSH authentication and authorization are therefore still enforced by that daemon. Keep the local daemon configured securely even if it is reachable only through loopback and Tailcat.

Host-key checking is intentionally disabled for the synthetic OpenSSH destination used by the Tailcat ProxyCommand, matching the transport model where the Tailcat address selects the encrypted peer. The Tailcat address itself therefore needs to remain trusted.

## Network exposure

The C++ data path is userspace-only and does not install kernel routes or a TUN interface. Current peer traffic is relayed through DERP while remaining end-to-end WireGuard encrypted.

Serving arbitrary ports, SSH, future file shares, SOCKS proxies, or exit-node functionality can expose powerful local resources to anyone who possesses sufficient Tailcat connection credentials. Apply least privilege to every service behind Tailcat.

## Untrusted input

Treat all of the following as attacker-controlled input:

- Tailcat addresses received from another party
- DERP frames and rendezvous packets
- decrypted IP/TCP/UDP traffic from an authenticated peer
- DERP-map JSON and future DNS TXT aliases
- SSH/scp paths and arguments
- persisted key/configuration files that can be modified by another user

Parsing and bounds checks are security boundaries. New protocol features should include malformed-input tests and cross-platform CI coverage before being called complete.

## Dependency and release policy

Native dependencies are pinned in CMake. Dependency updates should be reviewed as security-sensitive changes and run through the complete Linux/macOS/Windows test matrix.

Until full upstream parity and broader interoperability testing are complete, publish development versions as prereleases. A green build is necessary but is not by itself a security audit.

## Upstream security lessons

Upstream Tailcat has previously fixed issues involving unsafe SSH/scp argument handling, DNS leakage of mistyped addresses, unauthenticated malformed rendezvous packets, disco-key privacy, and write-only file-share semantics. Equivalent features in this rewrite must preserve those lessons rather than merely reproduce the happy path.
