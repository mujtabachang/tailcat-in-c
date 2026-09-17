# Security

## Reporting a vulnerability

Security issues in this C++ rewrite should be reported to this repository rather than assumed to affect Tailscale's upstream Go implementation. Prefer GitHub private vulnerability reporting / Security Advisories when available. Do not publish exploit details merely to obtain contact.

If an issue applies to upstream `tailscale/tailcat` or Tailscale infrastructure, use upstream's security reporting process.

## Native implementation boundary

This is an independent C++ implementation of the Tailcat protocol. It does **not** ship Tailscale's Go magicsock, gVisor netstack, Go WireGuard engine, or a Go helper process.

Security-relevant native dependencies include:

- libsodium for Curve25519/NaCl primitives
- a C WireGuard implementation derived from wireguard-lwip
- lwIP for userspace IP/TCP/UDP
- libcurl/TLS for DERP HTTPS
- libssh for the embedded SSH server
- Mbed TLS for libssh crypto on Windows
- nlohmann/json for DERP-map and persisted configuration parsing

Wire compatibility with upstream does not imply identical security properties.

## Tailcat addresses are credentials

A `tc...` address contains peer metadata and may contain a WireGuard preshared key. Treat secret-bearing addresses as credentials.

Do not publish such addresses in logs, screenshots, issues, public DNS, shell history, or chat unless you intentionally chose a configuration suitable for disclosure. Rotate persistent credentials after exposure.

## SSH

The SSH client validates direct Tailcat addresses before constructing its OpenSSH `ProxyCommand`. Proxy arguments are platform-quoted and the byte stream is binary-safe.

The server terminates SSH **inside the Tailcat process** with a persistent Ed25519 host key:

- `serve ssh` requires `--ssh-authorized-keys` and performs SSH public-key authentication.
- `serve no-auth-ssh` deliberately skips that extra SSH key check; anyone able to establish the Tailcat session can receive a shell. Keep its address secret and use `--allow` to restrict Tailcat node keys when practical.

Authorized-key sources are loaded and validated at startup. Options on authorized_keys lines that the implementation does not enforce are rejected rather than silently ignored.

The OpenSSH client disables normal host-key persistence for the synthetic Tailcat destination. Authentication of the transport therefore depends on possession/validation of the Tailcat connection material; do not substitute an untrusted `tc...` address.

SFTP and the upstream rooted file-service policy are not yet implemented and must not be treated as available security boundaries.

## DNS names

Native `tailcat=` TXT resolution rejects a Tailcat address hidden inside a DNS label to avoid leaking a mistyped secret address into DNS. The upstream SSH public-name stranger-probe behavior is not yet complete, so SSH DNS aliases are not claimed as full parity.

## Network exposure

The C++ data path is userspace-only and does not install kernel routes or a TUN interface. Current peer traffic remains DERP-relayed while being end-to-end WireGuard encrypted.

Serving TCP ports, SSH, SOCKS, future file shares, or future exit-node functionality can expose powerful local resources. Apply least privilege and use `--allow` where appropriate.

## Untrusted input

Treat these as attacker-controlled:

- Tailcat addresses and DNS TXT records
- DERP frames and rendezvous packets
- decrypted IP/TCP/UDP packets
- DERP-map JSON
- SSH client requests and public keys
- SOCKS requests
- persisted key/configuration files writable by another user

Parsing, length checks, authentication state, and path confinement are security boundaries. New features should include malformed-input/failure-path tests before being called complete.

## Interoperability and release policy

The repository runs separate-runner C++↔C++ tests and pinned upstream Go↔C++ tests in both directions. Embedded SSH has a separate two-runner gate.

Native dependencies are pinned. Releases build and test Linux, macOS, and Windows and publish checksums. Until direct-path, SFTP/file services, exit-node behavior, and the remaining parity work are complete, releases remain prereleases.

A green build and interoperability test are quality gates, not a security audit.
