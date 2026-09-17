<p align="center">
  <img src="tailcat.png" alt="Tailcat" width="149" height="176">
</p>

# Tailcat in C++

This repository is a native C++20 rewrite of [tailscale/tailcat](https://github.com/tailscale/tailcat). The shipped implementation contains no Go runtime, Go helper process, or Go source dependency.

The compatibility target is upstream Tailcat's `tc...` protocol. Compatibility is verified in GitHub Actions with separate runners: C++↔C++ is tested first, followed by upstream Go→C++ and C++→upstream Go data-plane connections.

## Current status

| Area | Status | Notes |
| --- | --- | --- |
| `tc...` addresses | ✅ | CBOR/base64url encoding and decoding, including embedded DERP region data |
| Node/disco keys, PSK, saved identities | ✅ | Native key generation, named/default client and server identities, `genkey`, `printpub`, list/delete |
| DERP v2 + rendezvous | ✅ | HTTPS/TLS, authenticated DERP framing, MEOW/MEOWED |
| WireGuard data plane | ✅ | Native C WireGuard engine with optional preshared key |
| Userspace IPv6/TCP | ✅ | lwIP TCP over WireGuard, without TUN devices or host routes |
| C++↔C++ transport | ✅ | Live two-runner GitHub Actions interoperability test |
| Upstream Go interoperability | ✅ | Live Go client→C++ server and C++ client→Go server tests against a pinned upstream revision |
| Pipe/listen/connect | ✅ | Binary-safe stdin/stdout transport |
| TCP `serve`, `forward`, `browse` | ✅ | Host service exposure and local TCP forwarding |
| `ping`, `parse`, `resolve` | ✅ | Native implementations |
| DNS `tailcat=` TXT names | 🟡 | Native TXT resolution and anti-leak address classification; upstream SSH public-name safety probing is still incomplete |
| Userspace UDP | 🟡 | lwIP UDP sockets and packet tests exist; full application UDP forwarding is not complete |
| SOCKS5 | 🟡 | TCP CONNECT through a fixed Tailcat peer works; UDP ASSOCIATE and full upstream destination behavior remain |
| SSH client | ✅ | System OpenSSH using Tailcat as `ProxyCommand` |
| Embedded SSH server | 🟡 | In-process libssh server, persistent Ed25519 host key, public-key auth, `no-auth-ssh`, shell/exec, Unix PTY/window resize; Windows ConPTY and SFTP remain |
| `cp` | 🟡 | System `scp` client is wired through Tailcat; full compatibility depends on the still-pending SFTP subsystem |
| `files`, `recv`, `ls` | ❌ | Rooted SFTP and file-service policy parity are not implemented yet |
| Exit-node forwarding | ❌ | Arbitrary destination TCP/UDP forwarding is not implemented yet |
| Direct NAT traversal | ❌ | Encrypted traffic currently stays DERP-relayed; STUN/disco/direct UDP path upgrade remains |

`✅` means the native path exists and has automated coverage. `🟡` means useful functionality exists but upstream parity is incomplete. `❌` is intentionally not presented as implemented.

## SSH

SSH is terminated inside Tailcat; a host `sshd` is not required.

### Public-key-authenticated server

Current upstream semantics require authorized keys for the `ssh` service:

```sh
tailcat serve --ssh-authorized-keys="$HOME/.ssh/authorized_keys" ssh
# 🐈 Server listening with address: tc...
```

`--ssh-authorized-keys` accepts an authorized_keys file, a literal OpenSSH public-key line, or a GitHub key source such as `alice@github`.

You can additionally restrict which authenticated Tailcat node keys may reach the server:

```sh
tailcat serve --allow=nodekey:... \
  --ssh-authorized-keys="$HOME/.ssh/authorized_keys" ssh
```

### Address-auth-only SSH

```sh
tailcat serve no-auth-ssh
```

This deliberately skips a second SSH public-key check. Anyone who can establish the Tailcat session can receive a shell, so keep the address secret and preferably combine it with `--allow`.

### Client

```sh
tailcat ssh tc...
tailcat ssh user@tc...
tailcat ssh tc... uname -a
```

Tailcat launches the system OpenSSH client with Tailcat as its `ProxyCommand`. The proxy stream is unbuffered and binary-safe.

File-copy client plumbing uses the same transport:

```sh
tailcat cp ./report.pdf tc...:/tmp/report.pdf
```

The embedded SFTP server is still pending, so `cp` is not yet considered full upstream parity.

## Basic transport examples

Start the default pipe server:

```sh
tailcat
# 🐈 Server listening with address: tc...
```

Send bytes from another Tailcat:

```sh
echo hello | tailcat tc...
```

Expose host TCP services:

```sh
tailcat serve 8080 8443
```

Connect or forward locally:

```sh
tailcat tc... 8080
tailcat forward tc... 18080:8080
tailcat forward tc... 0:8080
```

Open a remote HTTP service:

```sh
tailcat browse tc...
```

## Build

Requirements:

- CMake 3.24+
- Ninja
- a C++20 compiler
- network access during configure for pinned native dependencies
- system OpenSSH `ssh` for `tailcat ssh`
- system `scp` for `tailcat cp`

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

See [INSTALL.md](INSTALL.md) for installation details.

## Native dependencies

The shipped program is C/C++. CMake pins the native dependencies used by the implementation:

- libsodium for Curve25519/NaCl primitives
- wireguard-lwip's C WireGuard engine
- lwIP for the userspace IP/TCP/UDP stack
- libcurl for verified DERP HTTPS/TLS transport
- libssh for the embedded SSH server
- Mbed TLS as libssh's Windows crypto backend
- nlohmann/json for DERP maps and persisted configuration

## Network and interoperability model

DERP currently carries rendezvous and encrypted peer packets. WireGuard provides end-to-end encryption; DERP sees ciphertext. Direct STUN/disco/NAT traversal is the major remaining transport-parity item.

The `.github/workflows/interop.yml` gate builds a pinned upstream Go Tailcat reference and verifies both cross-language directions on separate GitHub runners. `.github/workflows/ssh-interop.yml` separately exercises the embedded C++ SSH server, including remote exec, SSH public-key authentication, and a Unix PTY session.

## Releases

The repository version is stored in [VERSION](VERSION). A version change on `main` runs the release workflow, which builds, tests, installs, and version-checks Linux x86_64, macOS arm64, and Windows x86_64 artifacts before publishing a GitHub Release and `SHA256SUMS`.

See [RELEASING.md](RELEASING.md) for the release policy.

Until the remaining parity rows are complete, releases are prereleases and are not a claim of full upstream Tailcat replacement.

## Security

A `tc...` address can contain secret connection material, including a WireGuard preshared key. Treat secret-bearing addresses like credentials. See [SECURITY.md](SECURITY.md).

## License

BSD-3-Clause, matching upstream. See [LICENSE](LICENSE).

## Upstream

Original project: https://github.com/tailscale/tailcat
