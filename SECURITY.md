# Security

## Reporting a vulnerability

Please report security issues privately to the repository maintainer rather than publishing exploit details in a public issue. Include the affected version/commit, platform, reproduction steps, and expected impact when possible.

## C++ rewrite security model

`tailcat-in-c` is an independent C++20 rewrite. It does **not** embed upstream Tailcat's Go WireGuard, magicsock, or gVisor netstack implementation.

The current transport connects to a DERP relay over TLS. Peer application packets are additionally encrypted end-to-end with XChaCha20-Poly1305 using a session key derived from X25519 and the pre-shared key carried in the `tc...` address. Treat a complete Tailcat address as a secret capability because possession of it includes the pre-shared key needed to authenticate to that server session.

The DERP relay can observe peer public keys, packet sizes, and timing, but should not be able to read application plaintext. The implementation has not received an independent cryptographic or security audit and should not be assumed to have the same security properties or maturity as upstream Tailcat/Tailscale.

The `serve exit-node` mode can connect to arbitrary TCP destinations reachable by the server. Only expose an exit-node address to peers you intend to grant that network access. `serve all` similarly permits all localhost TCP ports. Prefer an explicit port list when possible.

## Upstream history

This repository originated as a fork of `tailscale/tailcat`. Historical Tailcat security reports and acknowledgements remain available in the upstream repository and changelog, but fixes to the old Go implementation should not be assumed to apply automatically to this C++ rewrite.
