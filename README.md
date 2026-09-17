<p align="center">
  <img src="tailcat.png" alt="Tailcat" width="149" height="176">
</p>

# Tailcat in C++

This repository is a native C++20 rewrite of [tailscale/tailcat](https://github.com/tailscale/tailcat). It speaks Tailcat's `tc...` address format and implements the encrypted data path without a Go runtime, Go source tree, Go shared library, or Go helper process.

The compatibility target is upstream Tailcat, currently tracked against `tailscale/tailcat` main. Features are only called complete here when the native implementation has matching behavior and tests; a command name existing in `--help` is not considered parity.

## Current feature status

| Area | Status | Notes |
| --- | --- | --- |
| `tc...` addresses | ✅ | CBOR/base64url parse and encode, including embedded DERP regions |
| Node/disco keys + PSK | ✅ | Native X25519/libsodium primitives; persistent key-file format is implemented |
| DERP v2 | ✅ | HTTPS/TLS connection, authenticated framing, MEOW/MEOWED rendezvous |
| WireGuard transport | ✅ | Native C WireGuard engine with optional preshared key |
| Userspace TCP | ✅ | lwIP IPv6/TCP, no kernel TUN or routing-table changes |
| Pipe/listen/connect | ✅ | Binary-safe stdin/stdout transport |
| `serve` TCP ports | ✅ | Selected ports forwarded to host services |
| `forward` TCP | ✅ | Local TCP forwarding, including OS-assigned local port `0` |
| `browse` | ✅ | Opens an HTTP service through an ephemeral local forward |
| `ping`, `parse`, `resolve` | ✅ | Native implementations |
| `ssh` client | ✅ | System OpenSSH through Tailcat `ProxyCommand` |
| `cp` client | ✅ | System `scp` through the same Tailcat transport |
| Persistent server identity | 🟡 | Key serialization/loading is native; full upstream `genkey` CLI parity is still being completed |
| Embedded SSH/SFTP server | 🟡 | `serve ssh` currently bridges to a local `sshd`; upstream's embedded server is not yet ported |
| DNS TXT Tailcat names | ❌ | DNS lookup and public-name SSH safety probe remain to be ported |
| `files`, `recv`, `ls` | ❌ | Embedded SFTP/file-service semantics remain to be ported |
| SOCKS5 | ❌ | TCP and UDP proxy support remain to be ported |
| Exit-node forwarding | ❌ | Arbitrary destination TCP/UDP remains to be ported |
| Application UDP | ❌ | lwIP/data-plane UDP plumbing remains to be ported |
| Direct NAT traversal | ❌ | Current connections stay DERP-relayed; STUN/disco/direct-path upgrade remains to be ported |

`✅` means the native path exists and is covered by the repository's CTest suite. `🟡` means useful functionality exists but does not yet match all upstream behavior. `❌` means it is deliberately not presented as implemented.

## SSH

SSH is the primary supported application workflow in the current rewrite.

### Server

`serve ssh` exposes a local SSH daemon through Tailcat. The daemon does not need to listen on a public interface; Tailcat transports the SSH byte stream through the encrypted WireGuard session.

```sh
tailcat serve ssh
# 🐈 Server listening with new address: tc...
```

The current implementation checks the local SSH service before advertising the Tailcat address. This is intentionally different from upstream Tailcat's embedded SSH server and is listed as partial parity above.

### Client

```sh
tailcat ssh tc...
tailcat ssh user@tc...
tailcat ssh tc... uname -a
```

Tailcat starts the system `ssh` client with Tailcat itself as `ProxyCommand`. OpenSSH therefore continues to handle keys, `ssh-agent`, PTYs, interactive shells, remote commands, and the user's SSH configuration. The proxy stream is unbuffered and binary-safe, including binary stdin/stdout mode on Windows.

File copying uses the same transport:

```sh
tailcat cp ./report.pdf tc...:/tmp/report.pdf
tailcat cp -r ./directory user@tc...:/tmp/
```

## Basic transport examples

Start the default pipe server:

```sh
tailcat
# 🐈 Server listening with new address: tc...
```

Send bytes from a client:

```sh
echo hello | tailcat tc...
```

Expose host TCP services:

```sh
tailcat serve 8080 8443
```

Connect directly or create a local forward:

```sh
tailcat tc... 8080
tailcat forward tc... 18080:8080
tailcat forward tc... 0:8080
```

Open a remote HTTP service in the default browser:

```sh
tailcat browse tc...
```

## Build

Requirements:

- CMake 3.24+
- Ninja
- a C++20 compiler
- network access during configure so pinned native dependencies can be fetched

Linux:

```sh
cmake --preset linux
cmake --build --preset linux
ctest --preset linux
```

macOS:

```sh
cmake --preset macos
cmake --build --preset macos
ctest --preset macos
```

Windows:

```powershell
cmake --preset windows
cmake --build --preset windows
ctest --preset windows
```

See [INSTALL.md](INSTALL.md) for installation and runtime requirements.

## Native dependencies

The shipped implementation is C/C++ only. CMake pins native dependencies used by the data path:

- libsodium for Curve25519/NaCl primitives
- wireguard-lwip's C WireGuard implementation
- lwIP for the userspace TCP/IP stack
- libcurl for verified HTTPS/TLS transport
- nlohmann/json for DERP maps and persisted configuration

There is no Go dependency in the shipped implementation.

## Network model

Today the initial rendezvous and all encrypted data packets use DERP. WireGuard still provides end-to-end encryption; the DERP relay carries ciphertext. Upstream Tailcat can upgrade suitable peers to a direct UDP path after NAT discovery. That direct-path upgrade is one of the major remaining parity items and is not silently emulated by an unrelated transport.

## CI and releases

Every pull request and every push to `main` builds and runs CTest on Ubuntu, macOS, and Windows. Releases are produced only from `main` by the manual release workflow described in [RELEASING.md](RELEASING.md).

Until the parity table is complete and upstream interoperability coverage is comprehensive, releases should be treated as development/prerelease builds rather than a claim of full Tailcat replacement.

## Security

A Tailcat address can contain secret connection material, including a WireGuard preshared key. Treat it as a credential. See [SECURITY.md](SECURITY.md) for the rewrite-specific threat model.

## License

BSD-3-Clause, matching upstream. See [LICENSE](LICENSE).

## Upstream

Original project: https://github.com/tailscale/tailcat
